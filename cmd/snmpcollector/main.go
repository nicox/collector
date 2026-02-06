package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"snmp-collector/internal/config"
    "snmp-collector/internal/collectors/cisco"
    "snmp-collector/internal/devicetypes"
	snmpclient "snmp-collector/internal/snmpclient"
	nbclient "snmp-collector/internal/netbox"
)

func main() {
    configPath := flag.String("config", "config/snmp-collector.yaml", "Path to YAML config file")
    flag.Parse()

    cfg, err := config.Load(*configPath)
    if err != nil {
        log.Fatalf("failed to load config: %v", err)
    }

    log.Printf("Loaded config with %d devices\n", len(cfg.Devices))

    // Initialize NetBox client if not dry-run
    var nb *nbclient.NetBoxClient
    if !cfg.NetBox.DryRun && cfg.NetBox.URL != "" && cfg.NetBox.Token != "" {
        nb, err = nbclient.New(cfg.NetBox.URL, cfg.NetBox.Token, cfg.NetBox.Insecure)
        if err != nil {
            log.Fatalf("failed to create NetBox client: %v", err)
        }
        
        // Ensure custom fields exist
        fmt.Println("\n→ Ensuring Sophos custom fields exist in NetBox...")
        if err := nb.EnsureSophosCustomFields(); err != nil {
            log.Printf("⚠ Warning: Failed to ensure custom fields: %v\n", err)
        }
    }
    
    // Scan each device
    for _, device := range cfg.Devices {
        log.Printf("\n=== Scanning %s (%s:%d) ===\n", device.Name, device.Target, device.Port)

        snmpCfg := snmpclient.Config{
            Target:       device.Target,
            Port:         uint16(device.Port),
            User:         device.User,
            AuthProtocol: cfg.SNMP.AuthProto,
            AuthPassword: cfg.SNMP.AuthPass,
            PrivProtocol: cfg.SNMP.PrivProto,
            PrivPassword: cfg.SNMP.PrivPass,
            Timeout:      time.Duration(cfg.SNMP.Timeout) * time.Second,
            Retries:      cfg.SNMP.Retries,
        }

        client, err := snmpclient.New(snmpCfg)
        if err != nil {
            log.Printf("❌ SNMP connection failed: %v\n", err)
            continue
        }
        defer client.Close()

        // Get device info
        deviceInfo, err := client.GetDeviceInfo()
        if err != nil {
            log.Printf("❌ Failed to get device info: %v\n", err)
            continue
        }

        fmt.Printf("✓ Device: %s\n", deviceInfo.SysName)
        fmt.Printf("  Model: %s\n", deviceInfo.SysObjectID)
        fmt.Printf("  Contact: %s\n", deviceInfo.SysContact)

        // Check if this is a Sophos device and get extended info
        var sophosInfo *snmpclient.SophosFirewallInfo
        if client.IsSophosDevice() {
            fmt.Println("\n→ Detected Sophos firewall, collecting extended information...")
            sophosInfo, err = client.GetSophosFirewallInfo()
            if err != nil {
                log.Printf("⚠ Warning: Failed to get Sophos info: %v\n", err)
            } else {
                fmt.Printf("✓ Sophos Information:\n")
                fmt.Printf("  Model: %s\n", sophosInfo.Model)
                fmt.Printf("  Serial: %s\n", sophosInfo.SerialNumber)
                fmt.Printf("  Firmware: %s\n", sophosInfo.FirmwareVersion)
                fmt.Printf("  CPU Usage: %s%%\n", sophosInfo.CPUUsage)
                fmt.Printf("  Memory Usage: %.1f%%\n", sophosInfo.MemoryUsagePercent)
                fmt.Printf("  Active Connections: %s\n", sophosInfo.ActiveConnections)
                if sophosInfo.HAEnabled {
                    fmt.Printf("  HA: Enabled (%s)\n", sophosInfo.HAMode)
                }
                if sophosInfo.LicenseStatus != "" {
                    fmt.Printf("  License: %s (expires: %s)\n", sophosInfo.LicenseStatus, sophosInfo.LicenseExpiry)
                }
            }
        }
		if client.IsSophosDevice() {
    		fmt.Println("\n→ Detected Sophos firewall, collecting extended information...")
    
    	// Debug: Walk the OID tree to see what's available
    	if err := client.DebugWalkSophosOIDs(); err != nil {
        	log.Printf("⚠ Debug walk failed: %v\n", err)
    	}
    
    	sophosInfo, err = client.GetSophosFirewallInfo()
    	// ... rest of code
		}

        // Get interfaces
        ifaces, err := client.WalkInterfaces()
        if err != nil {
            log.Printf("⚠ Failed to walk interfaces: %v\n", err)
        } else {
            fmt.Printf("✓ Interfaces: %d\n", len(ifaces))
            for _, iface := range ifaces {
                if iface.Name != "" {
                    fmt.Printf("  - %s (speed=%s, type=%s)\n", iface.Name, iface.Speed, iface.Type)
                }
            }
        }

        // Get ARP
        arp, err := client.WalkARP()
        if err != nil {
            log.Printf("⚠ Failed to walk ARP: %v\n", err)
        } else {
            fmt.Printf("✓ ARP entries: %d\n", len(arp))
            for i, entry := range arp {
                if i < 3 {
                    fmt.Printf("  - %s (%s) → %s\n", entry.IPAddr, entry.Hostname, entry.MACAddr)
                }
            }
            if len(arp) > 3 {
                fmt.Printf("  ... and %d more\n", len(arp)-3)
            }
        }

        // Get site ID for ARP device creation
        var siteID float64
        if nb != nil {
            sid, err := nb.GetSiteID(cfg.NetBox.Site)
            if err == nil {
                siteID = sid
            }
        }

        // Push to NetBox if enabled
        if nb != nil && !cfg.NetBox.DryRun {
            fmt.Printf("\n→ Pushing to NetBox site=%s\n", cfg.NetBox.Site)

            // Determine device role from sysObjectID
            deviceRole := "generic"
            if strings.Contains(deviceInfo.SysObjectID, "2604") {
                deviceRole = "firewall"
            } else if strings.Contains(deviceInfo.SysObjectID, "9.9.1") {
                deviceRole = "switch"
            }

            deviceID, err := nb.PushDevice(deviceInfo, cfg.NetBox.Site, deviceRole)
            if err != nil {
                log.Printf("❌ Failed to push device: %v\n", err)
                continue
            }

            // Update with Sophos-specific information if available
            if sophosInfo != nil {
                fmt.Println("→ Updating device with Sophos-specific information...")
                if err := nb.UpdateDeviceWithSophosInfo(deviceID, sophosInfo); err != nil {
                    log.Printf("⚠ Failed to update Sophos info: %v\n", err)
                }
            }

            if err := nb.PushInterfaces(deviceID, ifaces); err != nil {
                log.Printf("⚠ Failed to push interfaces: %v", err)
            }
        }

        // Push ARP devices to NetBox if enabled
        if nb != nil && !cfg.NetBox.DryRun && len(arp) > 0 {
            _, err := nb.PushARPEntries(deviceInfo.SysName, siteID, arp)
            if err != nil {
                log.Printf("⚠ Failed to push ARP devices: %v\n", err)
            }
        }
    }

    log.Println("\n✓ Scan complete")
}
