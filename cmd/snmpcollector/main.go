package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"snmp-collector/internal/config"
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
		nb, err = nbclient.New(cfg.NetBox.URL, cfg.NetBox.Token, cfg.NetBox.Insecure)  // ← ADD insecure flag
		if err != nil {
			log.Fatalf("failed to create NetBox client: %v", err)
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


		// Get site ID for ARP device v creation
		var siteID float64
		if nb != nil {
			// Need to add method to get site ID
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
