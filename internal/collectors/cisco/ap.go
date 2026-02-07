package cisco

import (
	"fmt"
	"strings"

	// g "github.com/gosnmp/gosnmp"
	"snmp-collector/internal/snmpclient"
)

const (
	// Entity MIB - Physical Entity
	oidEntPhysicalDescr      = ".1.3.6.1.2.1.47.1.1.1.1.2.1"
	oidEntPhysicalName       = ".1.3.6.1.2.1.47.1.1.1.1.7.1"
	oidEntPhysicalModelName  = ".1.3.6.1.2.1.47.1.1.1.1.13.1"
	oidEntPhysicalSerialNum  = ".1.3.6.1.2.1.47.1.1.1.1.11.1"
	oidEntPhysicalSoftwareRev = ".1.3.6.1.2.1.47.1.1.1.1.10.1"

	// Cisco-specific
	oidCiscoImageString      = ".1.3.6.1.4.1.9.9.25.1.1.1.2.2"
	oidSysDescr              = ".1.3.6.1.2.1.1.1.0"
)

type CiscoAPInfo struct {
	Model            string
	SerialNumber     string
	Firmware         string
	Description      string
	Location         string
	IPAddress        string
	MACAddress       string
	Manufacturer     string
}

type APCollector struct {
	client *snmpclient.Client
}

func NewAPCollector(client *snmpclient.Client) *APCollector {
	return &APCollector{client: client}
}

// IsCiscoAP checks if the device is a Cisco AP
func (c *APCollector) IsCiscoAP(sysObjectID string) bool {
	// Cisco enterprise OID: .1.3.6.1.4.1.9
	return strings.Contains(sysObjectID, ".1.3.6.1.4.1.9")
}

// Discover collects information from a Cisco AP
func (c *APCollector) Discover() (*CiscoAPInfo, error) {
	info := &CiscoAPInfo{
		Manufacturer: "Cisco",
	}

	fmt.Println("  → Collecting Cisco AP information...")

	// Try Entity MIB first (most reliable)
	if err := c.collectEntityInfo(info); err != nil {
		fmt.Printf("  ⚠ Entity MIB collection failed: %v\n", err)
		// Try alternative methods
		if err := c.collectAlternativeInfo(info); err != nil {
			return nil, fmt.Errorf("failed to collect AP info: %w", err)
		}
	}

	// Get firmware/IOS version
	if err := c.collectFirmwareInfo(info); err != nil {
		fmt.Printf("  ⚠ Failed to get firmware info: %v\n", err)
	}

	return info, nil
}

func (c *APCollector) collectEntityInfo(info *CiscoAPInfo) error {
	oids := []string{
		oidEntPhysicalModelName,
		oidEntPhysicalSerialNum,
		oidEntPhysicalDescr,
		oidEntPhysicalSoftwareRev,
	}

	// Access the underlying SNMP client
	pkt, err := c.client.GetRaw(oids)
	if err != nil {
		return err
	}

	if len(pkt.Variables) >= 3 {
		info.Model = c.toString(pkt.Variables[0].Value)
		info.SerialNumber = c.toString(pkt.Variables[1].Value)
		info.Description = c.toString(pkt.Variables[2].Value)

		if len(pkt.Variables) >= 4 {
			info.Firmware = c.toString(pkt.Variables[3].Value)
		}

		fmt.Printf("  ✓ Model: %s\n", info.Model)
		fmt.Printf("  ✓ Serial: %s\n", info.SerialNumber)
		if info.Firmware != "" {
			fmt.Printf("  ✓ Firmware: %s\n", info.Firmware)
		}

		return nil
	}

	return fmt.Errorf("insufficient data from Entity MIB")
}

func (c *APCollector) collectAlternativeInfo(info *CiscoAPInfo) error {
	// Try sysDescr as fallback
	pkt, err := c.client.GetRaw([]string{oidSysDescr})
	if err != nil {
		return err
	}

	if len(pkt.Variables) > 0 {
		sysDescr := c.toString(pkt.Variables[0].Value)
		info.Description = sysDescr

		// Try to parse model from sysDescr
		// Example: "Cisco AP Software, C1140 Software..."
		if strings.Contains(sysDescr, "Cisco") {
			parts := strings.Fields(sysDescr)
			for i, part := range parts {
				if strings.HasPrefix(part, "C") || strings.HasPrefix(part, "AIR-") {
					if i < len(parts) {
						info.Model = part
						break
					}
				}
			}
		}

		fmt.Printf("  ✓ Description: %s\n", sysDescr)
		if info.Model != "" {
			fmt.Printf("  ✓ Model (parsed): %s\n", info.Model)
		}
	}

	return nil
}

func (c *APCollector) collectFirmwareInfo(info *CiscoAPInfo) error {
	// Try Cisco image string OID
	pkt, err := c.client.GetRaw([]string{oidCiscoImageString})
	if err == nil && len(pkt.Variables) > 0 {
		info.Firmware = c.toString(pkt.Variables[0].Value)
		fmt.Printf("  ✓ Firmware: %s\n", info.Firmware)
		return nil
	}

	// If we already got it from Entity MIB, we're done
	if info.Firmware != "" {
		return nil
	}

	return fmt.Errorf("could not determine firmware version")
}

func (c *APCollector) toString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		return fmt.Sprintf("%v", v)
	}
}
