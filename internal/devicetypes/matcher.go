package devicetypes

import (
    "strings"
)

// MatchModel attempts to match a discovered model string to a device type
func MatchModel(manufacturer, discoveredModel string) string {
    // Normalize the model string
    model := strings.TrimSpace(discoveredModel)
    
    // Remove common prefixes/suffixes
    model = strings.TrimPrefix(model, "Cisco ")
    model = strings.TrimPrefix(model, "AIR-")
    model = strings.TrimSuffix(model, "-E")
    model = strings.TrimSuffix(model, "-B")
    
    // Handle Cisco AP naming variations
    if strings.Contains(strings.ToUpper(manufacturer), "CISCO") {
        // AIR-AP1852I-E-K9 -> AIR-AP1852I-E-K9
        // AP1852I -> AIR-AP1852I-E-K9 (needs lookup)
        if strings.HasPrefix(model, "AP") && !strings.HasPrefix(model, "AIR-") {
            model = "AIR-" + model
        }
    }
    
    return model
}

// ExtractManufacturerFromOID extracts manufacturer from sysObjectID
func ExtractManufacturerFromOID(sysObjectID string) string {
    // Cisco: .1.3.6.1.4.1.9
    if strings.Contains(sysObjectID, ".1.3.6.1.4.1.9") {
        return "Cisco"
    }
    // Aruba: .1.3.6.1.4.1.14823
    if strings.Contains(sysObjectID, ".1.3.6.1.4.1.14823") {
        return "Aruba"
    }
    // Ubiquiti: .1.3.6.1.4.1.41112
    if strings.Contains(sysObjectID, ".1.3.6.1.4.1.41112") {
        return "Ubiquiti"
    }
    // HP/Aruba: .1.3.6.1.4.1.11
    if strings.Contains(sysObjectID, ".1.3.6.1.4.1.11") {
        return "HP"
    }
    
    return "Unknown"
}

// DetermineDeviceRole determines the role based on device type
func DetermineDeviceRole(model string) string {
    model = strings.ToUpper(model)
    
    if strings.Contains(model, "AP") || strings.Contains(model, "AIR-") {
        return "access-point"
    }
    if strings.Contains(model, "WLC") || strings.Contains(model, "CONTROLLER") {
        return "wireless-controller"
    }
    if strings.Contains(model, "SWITCH") || strings.Contains(model, "CATALYST") {
        return "switch"
    }
    if strings.Contains(model, "ROUTER") || strings.Contains(model, "ASR") {
        return "router"
    }
    
    return "other"
}
