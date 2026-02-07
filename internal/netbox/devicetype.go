package netbox

import (
	"fmt"
	"regexp"
	"strings"
)

// DeviceTypeInfo holds parsed manufacturer and model information
type DeviceTypeInfo struct {
	Manufacturer string
	Model        string
	Slug         string
}

// ParseDeviceType extracts manufacturer and model from SNMP data
func ParseDeviceType(sysObjectID, sysDescr string) *DeviceTypeInfo {
	// Detect manufacturer from Enterprise OID
	manufacturer := detectManufacturerFromOID(sysObjectID)
	
	// Parse model from sysDescr based on manufacturer
	model := parseModelFromDescr(manufacturer, sysDescr)
	
	// Fallback to generic if detection fails
	if manufacturer == "" || manufacturer == "Unknown" {
		manufacturer = "Unknown"
	}
	if model == "" {
		model = "Generic"
	}
	
	return &DeviceTypeInfo{
		Manufacturer: manufacturer,
		Model:        model,
		Slug:         strings.ToLower(strings.ReplaceAll(model, " ", "-")),
	}
}

// detectManufacturerFromOID maps enterprise OIDs to manufacturers
func detectManufacturerFromOID(oid string) string {
	// Map of enterprise numbers to manufacturers
	// Format: .1.3.6.1.4.1.<enterprise-number>...
	enterpriseMap := map[string]string{
		"2604":  "Sophos",
		"9":     "Cisco",
		"2011":  "Huawei",
		"25506": "HP",
		"12356": "Fortinet",
		"14988": "Mikrotik",
		"8072":  "Net-SNMP",
		"6876":  "VMware",
		"10002": "Ubiquiti",
		"171":   "D-Link",
		"1588":  "Brocade",
		"6027":  "Force10",
		"4526":  "NetGear",
		"11":    "HP",
		"674":   "Dell",
		"311":   "Microsoft",
		"2636":  "Juniper Networks",
		"12532": "Hewlett Packard Enterprise",
	}
	
	// Extract enterprise number from OID
	// OID format: .1.3.6.1.4.1.<enterprise>.<rest>
	parts := strings.Split(strings.Trim(oid, "."), ".")
	
	if len(parts) >= 7 && parts[0] == "1" && parts[1] == "3" && 
	   parts[2] == "6" && parts[3] == "1" && parts[4] == "4" && parts[5] == "1" {
		enterprise := parts[6]
		if mfr, ok := enterpriseMap[enterprise]; ok {
			return mfr
		}
	}
	
	return "Unknown"
}

// parseModelFromDescr extracts device model from sysDescr based on manufacturer
func parseModelFromDescr(manufacturer, sysDescr string) string {
	switch manufacturer {
	case "Sophos":
		return parseSophosModel(sysDescr)
	case "Cisco":
		return parseCiscoModel(sysDescr)
	case "HP", "Hewlett Packard Enterprise":
		return parseHPModel(sysDescr)
	case "Fortinet":
		return parseFortinetModel(sysDescr)
	case "Ubiquiti":
		return parseUbiquitiModel(sysDescr)
	default:
		// Try generic extraction
		return parseGenericModel(sysDescr)
	}
}

// parseSophosModel extracts Sophos firewall model
// Example sysDescr: "Sophos XG230 Firewall version SFOS 19.0.1 MR-1"
func parseSophosModel(sysDescr string) string {
	// Pattern: "Sophos <MODEL>"
	re := regexp.MustCompile(`Sophos\s+([A-Z]{2,3}\s*\d+\w*)`)
	matches := re.FindStringSubmatch(sysDescr)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	
	// Fallback: look for SG/XG patterns
	re = regexp.MustCompile(`(?i)(SG|XG|XGS)\s*(\d+\w*)`)
	matches = re.FindStringSubmatch(sysDescr)
	if len(matches) >= 3 {
		return fmt.Sprintf("%s %s", strings.ToUpper(matches[1]), matches[2])
	}
	
	return "Unknown Sophos"
}

// parseCiscoModel extracts Cisco device model
func parseCiscoModel(sysDescr string) string {
	// Cisco formats vary widely, look for common patterns
	patterns := []string{
		`Cisco\s+([\w-]+\s*\d+[\w-]*)`,         // Cisco Catalyst 2960
		`(Catalyst\s+\d+[\w-]*)`,                // Catalyst 3850
		`(ASR\s+\d+[\w-]*)`,                     // ASR 1000
		`(ISR\s+\d+[\w-]*)`,                     // ISR 4000
		`(Nexus\s+\d+[\w-]*)`,                   // Nexus 9000
		`(WS-C\d+[\w-]*)`,                       // WS-C2960X-48FPD-L
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(sysDescr)
		if len(matches) >= 2 {
			return strings.TrimSpace(matches[1])
		}
	}
	
	return "Unknown Cisco"
}

// parseHPModel extracts HP/HPE switch model
func parseHPModel(sysDescr string) string {
	// HP ProCurve or HPE patterns
	patterns := []string{
		`(ProCurve\s+[\w-]+\s+\d+[\w-]*)`,
		`(Aruba\s+\d+[\w-]*)`,
		`([\w-]+\s+Switch\s+\d+[\w-]*)`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(sysDescr)
		if len(matches) >= 2 {
			return strings.TrimSpace(matches[1])
		}
	}
	
	return "Unknown HP"
}

// parseFortinetModel extracts Fortinet model
func parseFortinetModel(sysDescr string) string {
	re := regexp.MustCompile(`(FortiGate-\d+\w*)`)
	matches := re.FindStringSubmatch(sysDescr)
	if len(matches) >= 2 {
		return matches[1]
	}
	return "Unknown FortiGate"
}

// parseUbiquitiModel extracts Ubiquiti model
func parseUbiquitiModel(sysDescr string) string {
	patterns := []string{
		`(UniFi\s+[\w-]+)`,
		`(EdgeRouter\s+[\w-]+)`,
		`(USW-[\w-]+)`,
		`(UAP-[\w-]+)`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(sysDescr)
		if len(matches) >= 2 {
			return strings.TrimSpace(matches[1])
		}
	}
	
	return "Unknown Ubiquiti"
}

// parseGenericModel attempts to extract a model name from any vendor
func parseGenericModel(sysDescr string) string {
	// Take first meaningful word or number combo
	words := strings.Fields(sysDescr)
	if len(words) > 0 {
		// Limit to first 5 words to avoid too long model names
		maxWords := 5
		if len(words) < maxWords {
			maxWords = len(words)
		}
		model := strings.Join(words[:maxWords], " ")
		
		// Truncate if too long
		if len(model) > 50 {
			model = model[:50]
		}
		return model
	}
	return "Generic"
}
