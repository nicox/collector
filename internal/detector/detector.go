package detector

import (
    "strings"
    "snmp-collector/internal/snmpclient"
)

type DeviceInfo struct {
    Manufacturer string
    DeviceType   string
    Model        string
    Serial       string
}

// Enterprise OIDs for detection
var enterpriseOIDs = map[string]struct {
    Manufacturer string
    DeviceType   string
    ModelOID     string
    SerialOID    string
}{
    ".1.3.6.1.4.1.2604.5.1.1.2.0": { // Sophos XG/XGS
        Manufacturer: "Sophos",
        DeviceType:   "firewall",
        ModelOID:     ".1.3.6.1.4.1.2604.5.1.1.2.0",
        SerialOID:    ".1.3.6.1.4.1.2604.5.1.1.4.0",
    },
    ".1.3.6.1.4.1.12356.101.4.1.1.0": { // Fortinet FortiGate
        Manufacturer: "Fortinet",
        DeviceType:   "firewall",
        ModelOID:     ".1.3.6.1.4.1.12356.101.4.1.1.0",
        SerialOID:    ".1.3.6.1.4.1.12356.101.4.1.2.0",
    },
    ".1.3.6.1.4.1.9.9.25.1.1.1.2.3": { // Cisco IOS
        Manufacturer: "Cisco",
        DeviceType:   "switch",
        ModelOID:     ".1.3.6.1.4.1.9.9.25.1.1.1.2.3",
        SerialOID:    ".1.3.6.1.4.1.9.5.1.2.19.0",
    },
}

// Check OIDs to probe for enterprise detection
var probeOIDs = []string{
    ".1.3.6.1.4.1.2604.5.1.1.2.0",      // Sophos
    ".1.3.6.1.4.1.12356.101.4.1.1.0",   // Fortinet
    ".1.3.6.1.4.1.9.9.25.1.1.1.2.3",    // Cisco
    ".1.3.6.1.4.1.14179.2.2.1.1.3",     // Cisco WLC
    ".1.3.6.1.4.1.41112.1.6.3.3",       // Ubiquiti
}

func DetectDevice(client *snmpclient.SNMPClient) (*DeviceInfo, error) {
    info := &DeviceInfo{}

    // First: Try enterprise-specific OIDs
    for _, probeOID := range probeOIDs {
        result, err := client.Get(probeOID)
        if err == nil && result != "" && result != "No Such Object" && result != "No Such Instance" {
            if enterprise, ok := enterpriseOIDs[probeOID]; ok {
                info.Manufacturer = enterprise.Manufacturer
                info.DeviceType = enterprise.DeviceType
                info.Model = result
                
                // Get serial
                if enterprise.SerialOID != "" {
                    if serial, err := client.Get(enterprise.SerialOID); err == nil {
                        info.Serial = serial
                    }
                }
                return info, nil
            }
        }
    }

    // Fallback: Check sysObjectID and sysDescr
    sysObjectID, _ := client.Get(".1.3.6.1.2.1.1.2.0")
    sysDescr, _ := client.Get(".1.3.6.1.2.1.1.1.0")

    // Detect by sysObjectID prefix
    info.Manufacturer, info.DeviceType = detectBySysObjectID(sysObjectID, sysDescr)

    // Try to get model/serial from ENTITY-MIB
    if model, err := client.Get(".1.3.6.1.2.1.47.1.1.1.1.13.1"); err == nil && model != "" {
        info.Model = model
    }
    if serial, err := client.Get(".1.3.6.1.2.1.47.1.1.1.1.11.1"); err == nil && serial != "" {
        info.Serial = serial
    }

    return info, nil
}

func detectBySysObjectID(sysObjectID, sysDescr string) (manufacturer, deviceType string) {
    sysDescrLower := strings.ToLower(sysDescr)

    // Check sysObjectID prefixes
    switch {
    case strings.HasPrefix(sysObjectID, ".1.3.6.1.4.1.2604"):
        return "Sophos", "firewall"
    case strings.HasPrefix(sysObjectID, ".1.3.6.1.4.1.12356"):
        return "Fortinet", "firewall"
    case strings.HasPrefix(sysObjectID, ".1.3.6.1.4.1.9."):
        if strings.Contains(sysDescrLower, "adaptive security") {
            return "Cisco", "firewall"
        }
        return "Cisco", "switch"
    case strings.HasPrefix(sysObjectID, ".1.3.6.1.4.1.14179"):
        return "Cisco", "wireless-controller"
    case strings.HasPrefix(sysObjectID, ".1.3.6.1.4.1.41112"):
        return "Ubiquiti", "switch"
    case strings.HasPrefix(sysObjectID, ".1.3.6.1.4.1.8072"):
        // net-snmp - need deeper inspection
        return detectLinuxDevice(sysDescr)
    }

    // Fallback to sysDescr inspection
    return detectLinuxDevice(sysDescr)
}

func detectLinuxDevice(sysDescr string) (string, string) {
    lower := strings.ToLower(sysDescr)
    
    switch {
    case strings.Contains(lower, "sophos"):
        return "Sophos", "firewall"
    case strings.Contains(lower, "pfsense"):
        return "Netgate", "firewall"
    case strings.Contains(lower, "opnsense"):
        return "OPNsense", "firewall"
    case strings.Contains(lower, "vyos"):
        return "VyOS", "router"
    case strings.Contains(lower, "mikrotik"):
        return "MikroTik", "router"
    case strings.Contains(lower, "synology"):
        return "Synology", "nas"
    case strings.Contains(lower, "qnap"):
        return "QNAP", "nas"
    case strings.Contains(lower, "proxmox"):
        return "Proxmox", "server"
    case strings.Contains(lower, "vmware"):
        return "VMware", "server"
    default:
        return "Linux", "server"
    }
}
