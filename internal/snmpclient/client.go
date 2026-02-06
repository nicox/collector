package snmpclient

import (
	"fmt"
	"time"
	"strconv"
	"strings"
	"net"
	"context"
	//"sync"

	g "github.com/gosnmp/gosnmp"
)

func toString(val interface{}) string {
	switch v := val.(type) {
	case []byte:
		return string(v)
	case int, int64, uint64:
		return fmt.Sprintf("%d", v)
	case string:
		return v
	default:
		if bs, ok := v.([]uint8); ok {
			return string(bs)  // handle []uint8 here
		}
		return fmt.Sprintf("%v", v)
	}
}


// parseOID extracts index from OID (e.g. ".1.3.6.1.2.1.2.2.1.2.5" → "5")
func parseOIDIndex(oid string) string {
	parts := strings.Split(oid, ".")
	if len(parts) < 1 {
		return ""
	}
	return parts[len(parts)-1]
}

type LLDPNeighbor struct {
	LocalPortIndex string
	RemoteSysName  string
}

type ARPEntry struct {
	IPAddr   string
	MACAddr  string
	Hostname string // ← ADD THIS
}

type MacEntry struct {
	MacAddr string
	IfIndex string
}

type Config struct {
	Target       string
	Port         uint16
	User         string
	AuthProtocol string
	AuthPassword string
	PrivProtocol string
	PrivPassword string
	Timeout      time.Duration
	Retries      int
}

type Client struct {
	s *g.GoSNMP
}

// DeviceInfo for NetBox dcim.devices
type DeviceInfo struct {
	SysName     string
	SysDescr    string
	SysObjectID string
	SysContact  string
	SysUpTime   string
}

// InterfaceInfo for NetBox dcim.interfaces
type InterfaceInfo struct {
	Index     string
	Name      string
	Alias     string
	Speed     string
	Type      string
	IPs       []string  
}

// SophosFirewallInfo contains Sophos-specific information
type SophosFirewallInfo struct {
    SerialNumber      string
    Model             string
    FirmwareVersion   string
    DeviceType        string
    LicenseStatus     string
    LicenseExpiry     string
    CPUUsage          string
    MemoryTotal       string
    MemoryFree        string
    MemoryUsagePercent float64
    DiskUsage         string
    ActiveConnections string
    TotalConnections  string
    HAEnabled         bool
    HAStatus          string
    HAPeerSerial      string
    HAMode            string
}


func (c *Client) GetDeviceInfo() (*DeviceInfo, error) {
	oIDs := []string{
		oidSysObjectID,
		oidSysDescr,
		oidSysName,
		oidSysContact,
		oidSysUpTime,
	}
	pkt, err := c.s.Get(oIDs)
	if err != nil {
		return nil, err
	}

	info := &DeviceInfo{}
	info.SysObjectID = toString(pkt.Variables[0].Value)
	info.SysDescr = toString(pkt.Variables[1].Value)
	info.SysName = toString(pkt.Variables[2].Value)
	info.SysContact = toString(pkt.Variables[3].Value)
	info.SysUpTime = toString(pkt.Variables[4].Value)

	return info, nil
}

func (c *Client) WalkInterfaces() ([]InterfaceInfo, error) {
	ifaces := make(map[string]*InterfaceInfo)

	// Walk each attribute separately and merge
	err := c.s.BulkWalk(oidIfDescr, func(pdu g.SnmpPDU) error {
		index := parseOIDIndex(pdu.Name)
		if _, ok := ifaces[index]; !ok {
			ifaces[index] = &InterfaceInfo{Index: index}
		}
		ifaces[index].Name = toString(pdu.Value)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = c.s.BulkWalk(oidIfAlias, func(pdu g.SnmpPDU) error {
		index := parseOIDIndex(pdu.Name)
		if _, ok := ifaces[index]; !ok {
			ifaces[index] = &InterfaceInfo{Index: index}
		}
		ifaces[index].Alias = toString(pdu.Value)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = c.s.BulkWalk(oidIfSpeed, func(pdu g.SnmpPDU) error {
		index := parseOIDIndex(pdu.Name)
		if _, ok := ifaces[index]; !ok {
			ifaces[index] = &InterfaceInfo{Index: index}
		}
		ifaces[index].Speed = toString(pdu.Value)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = c.s.BulkWalk(oidIfType, func(pdu g.SnmpPDU) error {
		index := parseOIDIndex(pdu.Name)
		if _, ok := ifaces[index]; !ok {
			ifaces[index] = &InterfaceInfo{Index: index}
		}
		ifaces[index].Type = toString(pdu.Value)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Get IP addresses and associate with interfaces
	ipsByIfIndex, err := c.WalkIPAddresses()
	if err == nil {
		for ifIndex, ips := range ipsByIfIndex {
			if iface, ok := ifaces[ifIndex]; ok {
				iface.IPs = ips
			}
		}
	}

	// Convert map to slice
	var result []InterfaceInfo
	for _, iface := range ifaces {
		result = append(result, *iface)
	}
	return result, nil
}


func New(cfg Config) (*Client, error) {
	authProto, err := parseAuthProtocol(cfg.AuthProtocol)
	if err != nil {
		return nil, err
	}
	privProto, err := parsePrivProtocol(cfg.PrivProtocol)
	if err != nil {
		return nil, err
	}

	snmp := &g.GoSNMP{
		Target:             cfg.Target,
		Port:               cfg.Port,
		Version:            g.Version3,
		Timeout:            cfg.Timeout,
		Retries:            cfg.Retries,
		SecurityModel:      g.UserSecurityModel,
		MsgFlags:           g.AuthPriv,
		SecurityParameters: &g.UsmSecurityParameters{
			UserName:                 cfg.User,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: cfg.AuthPassword,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        cfg.PrivPassword,
		},
	}

	if err := snmp.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect: %w", err)
	}

	return &Client{s: snmp}, nil
}

func (c *Client) Close() {
	if c.s != nil {
		_ = c.s.Conn.Close()
	}
}

// reverseLookup performs reverse DNS lookup
// reverseLookupWithTimeout performs reverse DNS lookup with 1s timeout
func reverseLookupWithTimeout(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}


func parseAuthProtocol(p string) (g.SnmpV3AuthProtocol, error) {
	switch p {
	case "MD5":
		return g.MD5, nil
	case "SHA":
		return g.SHA, nil
	case "SHA224":
		return g.SHA224, nil
	case "SHA256":
		return g.SHA256, nil
	case "SHA384":
		return g.SHA384, nil
	case "SHA512":
		return g.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported auth protocol %q", p)
	}
}

func parsePrivProtocol(p string) (g.SnmpV3PrivProtocol, error) {
	switch p {
	case "DES":
		return g.DES, nil
	case "AES":
		return g.AES, nil
	default:
		return 0, fmt.Errorf("unsupported priv protocol %q", p)
	}
}

// For now use numeric OIDs; later we’ll plug in the MIB loader.
const (
	oidSysDescr            = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID         = ".1.3.6.1.2.1.1.2.0"
	oidSysName             = ".1.3.6.1.2.1.1.5.0"
	oidSysContact          = ".1.3.6.1.2.1.1.4.0"
	oidSysUpTime           = ".1.3.6.1.2.1.1.3.0"
	oidIfDescr             = ".1.3.6.1.2.1.2.2.1.2"
	oidIfAlias             = ".1.3.6.1.2.1.31.1.1.1.18"
	oidIfSpeed             = ".1.3.6.1.2.1.2.2.1.5"
	oidIfType              = ".1.3.6.1.2.1.2.2.1.3"

	// LLDP
	oidLldpLocPortId       = ".1.0.8802.1.1.2.1.3.7.1.2"
	oidLldpRemChassisId    = ".1.0.8802.1.1.2.1.4.1.1.4"
	oidLldpRemPortId       = ".1.0.8802.1.1.2.1.4.1.1.7"
	oidLldpRemSysName      = ".1.0.8802.1.1.2.1.4.1.1.9"
	oidLldpRemSysDescr     = ".1.0.8802.1.1.2.1.4.1.1.10"

	// BRIDGE-MIB MAC
	oidDot1dTpFdbAddress   = ".1.3.6.1.2.1.17.4.3.1.1"
	oidDot1dTpFdbPort      = ".1.3.6.1.2.1.17.4.3.1.2"
	oidDot1dTpFdbStatus    = ".1.3.6.1.2.1.17.4.3.1.3"

	// IP-MIB ARP
	//oidIpNetToMediaNetAddress  = ".1.3.6.1.2.1.4.22.1.1"
	//oidIpNetToMediaIfIndex     = ".1.3.6.1.2.1.4.22.1.2"
	//oidIpNetToMediaPhysAddress = ".1.3.6.1.2.1.4.22.1.3"


	oidIpNetToPhysicalPhysAddress = ".1.3.6.1.2.1.4.35.1.3" // ipNetToPhysicalPhysAddress (newer)
	oidIpNetToPhysicalNetAddress  = ".1.3.6.1.2.1.4.35.1.2" // ipNetToPhysicalNetAddr

	oidIpNetToMediaTable        = ".1.3.6.1.2.1.3.1.1"      // ipNetToMediaTable
	oidIpNetToMediaPhysAddress  = ".1.3.6.1.2.1.3.1.1.2"    // ipNetToMediaPhysAddress ← FIX
	oidIpNetToMediaNetAddress   = ".1.3.6.1.2.1.3.1.1.3"    // ipNetToMediaNetAddr
	oidIpNetToMediaIfIndex      = ".1.3.6.1.2.1.3.1.1.1"    // ipNetToMediaIfIndex

	oidIpAdEntAddr      = ".1.3.6.1.2.1.4.20.1.1"  // ipAdEntAddr (IP address)
	oidIpAdEntIfIndex   = ".1.3.6.1.2.1.4.20.1.2"  // ipAdEntIfIndex (interface index)
	oidIpAdEntNetMask   = ".1.3.6.1.2.1.4.20.1.3"  // ipAdEntNetMask

	// Sophos Firewall OIDs - Updated for SFOS (XG/XGS)
   
        // Sophos SFOS-FIREWALL-MIB (.1.3.6.1.4.1.2604.1.1.1)
    oidSophosModel           = ".1.3.6.1.4.1.2604.1.1.1.2.1.2.0"
    
    // License Information
    oidSophosLicenseExpiry   = ".1.3.6.1.4.1.2604.1.1.1.3.2.0"
    
    // System Resources
    oidSophosMemoryFree      = ".1.3.6.1.4.1.2604.1.1.1.1.1.3.0"
    
    // Connection Statistics
    oidSophosActiveConns     = ".1.3.6.1.4.1.2604.1.1.1.7.1.0"
    oidSophosTotalConns      = ".1.3.6.1.4.1.2604.1.1.1.7.2.0"
    
    	
    // Sophos SFOS MIB (.1.3.6.1.4.1.2604.5.1)
    oidSophosHostname        = ".1.3.6.1.4.1.2604.5.1.1.1.0"
    oidSophosDeviceType      = ".1.3.6.1.4.1.2604.5.1.1.2.0"
    oidSophosFirmwareVersion = ".1.3.6.1.4.1.2604.5.1.1.3.0"
    oidSophosSerialNumber    = ".1.3.6.1.4.1.2604.5.1.1.4.0"
    oidSophosLicenseStatus   = ".1.3.6.1.4.1.2604.5.1.1.5.0"
    oidSophosFirmwareDate    = ".1.3.6.1.4.1.2604.5.1.1.6.0"
    
    // System Resources
    oidSophosCPUUsage        = ".1.3.6.1.4.1.2604.5.1.2.4.2.0"  // CPU usage percentage
    oidSophosMemoryUsage     = ".1.3.6.1.4.1.2604.5.1.2.5.4.0"  // Memory usage percentage
    oidSophosMemoryTotal     = ".1.3.6.1.4.1.2604.5.1.2.5.1.0"  // Total memory MB
    oidSophosMemoryUsed      = ".1.3.6.1.4.1.2604.5.1.2.5.3.0"  // Used memory MB
    oidSophosDiskUsage       = ".1.3.6.1.4.1.2604.5.1.2.5.2.0"  // Disk usage percentage
    
    // HA Information
    oidSophosHAStatus        = ".1.3.6.1.4.1.2604.5.1.4.1.0"    // HA status (0=disabled)
    oidSophosHAPeerSerial    = ".1.3.6.1.4.1.2604.5.1.4.2.0"    // HA peer serial
    oidSophosHAMode          = ".1.3.6.1.4.1.2604.5.1.4.4.0"    // HA mode
    
    // Service Status (.1.3.6.1.4.1.2604.5.1.3.x.0)
    oidSophosServiceHTTP     = ".1.3.6.1.4.1.2604.5.1.3.1.0"
    oidSophosServiceFTP      = ".1.3.6.1.4.1.2604.5.1.3.2.0"
    oidSophosServiceSMTP     = ".1.3.6.1.4.1.2604.5.1.3.3.0"

)

// WalkIPAddresses gets IP addresses mapped to interfaces
func (c *Client) WalkIPAddresses() (map[string][]string, error) {
	// Map: ifIndex -> []IP addresses
	ifIndexToIPs := make(map[string][]string)

	err := c.s.BulkWalk(oidIpAdEntIfIndex, func(pdu g.SnmpPDU) error {
		// OID: .1.3.6.1.2.1.4.20.1.2.A.B.C.D where A.B.C.D is the IP
		// The IP is in the OID index, extract it
		parts := strings.Split(pdu.Name, ".")
		if len(parts) < 4 {
			return nil
		}

		// Last 4 octets are the IP address
		ipOctets := parts[len(parts)-4:]
		ip := fmt.Sprintf("%s.%s.%s.%s", ipOctets[0], ipOctets[1], ipOctets[2], ipOctets[3])

		// Value is the interface index
		ifIndexStr := toString(pdu.Value)

		if ifIndexStr != "" && ip != "" {
			ifIndexToIPs[ifIndexStr] = append(ifIndexToIPs[ifIndexStr], ip)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return ifIndexToIPs, nil
}

// WalkLLDP walks LLDP neighbors
func (c *Client) WalkLLDP() ([]LLDPNeighbor, error) {
	var neighbors []LLDPNeighbor

	// Walk key LLDP tables
	tables := map[string]string{
		oidLldpLocPortId:   "locPortId",
		oidLldpRemChassisId: "remChassisId",
		oidLldpRemPortId:   "remPortId",
		oidLldpRemSysName:  "remSysName",
		oidLldpRemSysDescr: "remSysDescr",
	}

	for oid, _ := range tables {  // ← CHANGE: use _ instead of field
	table := make(map[string]string)
	err := c.s.BulkWalk(oid, func(pdu g.SnmpPDU) error {
		table[pdu.Name] = toString(pdu.Value)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// TODO: Parse multi-index OIDs and merge (complex; skip for MVP)
	_ = table  // discard table too since it's not used
}

	// For Sophos/Linux, LLDP might be sparse. Walk remSysName as proxy:
	neighborsMap := make(map[string]LLDPNeighbor)
	err := c.s.BulkWalk(oidLldpRemSysName, func(pdu g.SnmpPDU) error {
		remoteName := toString(pdu.Value)
		if remoteName == "" {
			return nil
		}
		// Extract local port from OID index (simplified)
		parts := strings.Split(pdu.Name, ".")
		if len(parts) >= 3 {
			localPort := parts[len(parts)-2] // lldpRemLocalPortNum index
			neighborsMap[localPort] = LLDPNeighbor{
				LocalPortIndex: localPort,
				RemoteSysName:  remoteName,
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	for _, n := range neighborsMap {
		neighbors = append(neighbors, n)
	}
	return neighbors, nil
}

// WalkARP walks ARP table
func (c *Client) WalkARP() ([]ARPEntry, error) {
	var entries []ARPEntry

	err := c.s.BulkWalk(oidIpNetToMediaTable, func(pdu g.SnmpPDU) error {
		// OID format: .1.3.6.1.2.1.3.1.1.X.ifIndex.IP.octet1.octet2.octet3.octet4
		// X = 1:ifIndex, 2:physAddr, 3:netAddr, 4:type

		parts := strings.Split(pdu.Name, ".")
		if len(parts) < 13 {
			return nil
		}

		// Column indicator (parts[10] should be 1, 2, 3, or 4)
		col := parts[10]

		// Only process physAddr column (2)
		if col != "2" {
			return nil
		}

		// Convert MAC from bytes to hex string
		var mac string
		switch v := pdu.Value.(type) {
		case []byte:
			if len(v) == 0 {
				return nil
			}
			macParts := make([]string, len(v))
			for i, b := range v {
				macParts[i] = fmt.Sprintf("%02x", b)
			}
			mac = strings.Join(macParts, ":")
		default:
			return nil
		}

		if mac == "" || mac == "00:00:00:00:00:00" {
			return nil
		}

		// Extract IP from OID suffix (last 4 parts)
		ipOctets := parts[len(parts)-4:]
		ip := fmt.Sprintf("%s.%s.%s.%s", ipOctets[0], ipOctets[1], ipOctets[2], ipOctets[3])

		// Reverse DNS lookup
		hostname := reverseLookupWithTimeout(ip)

		entries = append(entries, ARPEntry{
			IPAddr:   ip,
			MACAddr:  mac,
			Hostname: hostname,
		})
		return nil
	})

	if err != nil {
		return nil, err
	}
	return entries, nil
}


// WalkMacTable walks MAC forwarding table (BRIDGE-MIB)
func (c *Client) WalkMacTable() ([]MacEntry, error) {
	var entries []MacEntry

	err := c.s.BulkWalk(oidDot1dTpFdbAddress, func(pdu g.SnmpPDU) error {
		mac := toString(pdu.Value)
		if mac == "" {
			return nil
		}
		parts := strings.Split(pdu.Name, ".")
		portIndex := ""
		if len(parts) >= 2 {
			portIndex = parts[len(parts)-1]
		}

		entries = append(entries, MacEntry{
			MacAddr: mac,
			IfIndex: portIndex,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// Helper
func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func (c *Client) GetSysDescr() (string, error) {
	pkt, err := c.s.Get([]string{oidSysDescr})
	if err != nil {
		return "", err
	}
	if len(pkt.Variables) == 0 {
		return "", fmt.Errorf("no vars in response")
	}
	return fmt.Sprintf("%v", pkt.Variables[0].Value), nil
}

func (c *Client) WalkIfDescr() (map[string]string, error) {
	out := make(map[string]string)
	err := c.s.BulkWalk(oidIfDescr, func(pdu g.SnmpPDU) error {
		out[pdu.Name] = fmt.Sprintf("%v", pdu.Value)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetSophosFirewallInfo retrieves Sophos-specific information
func (c *Client) GetSophosFirewallInfo() (*SophosFirewallInfo, error) {
    info := &SophosFirewallInfo{}
    
    fmt.Println("  → Attempting to collect Sophos device information...")
    
    // Get basic system information (all available OIDs)
    basicOIDs := []string{
        oidSophosHostname,
        oidSophosDeviceType,
        oidSophosFirmwareVersion,
        oidSophosSerialNumber,
        oidSophosLicenseStatus,
        oidSophosFirmwareDate,
    }
    
    basicPkt, err := c.s.Get(basicOIDs)
    if err == nil && len(basicPkt.Variables) >= 4 {
        info.Model = toString(basicPkt.Variables[1].Value)
        info.FirmwareVersion = toString(basicPkt.Variables[2].Value)
        info.SerialNumber = toString(basicPkt.Variables[3].Value)
        
        if len(basicPkt.Variables) >= 5 {
            info.LicenseStatus = toString(basicPkt.Variables[4].Value)
        }
        
        fmt.Printf("  ✓ Model: %s\n", info.Model)
        fmt.Printf("  ✓ Serial: %s\n", info.SerialNumber)
        fmt.Printf("  ✓ Firmware: %s\n", info.FirmwareVersion)
        if info.LicenseStatus != "" {
            fmt.Printf("  ✓ License: %s\n", info.LicenseStatus)
        }
    } else {
        return nil, fmt.Errorf("failed to get basic Sophos info: %w", err)
    }
    
    // Get resource metrics
    resourceOIDs := []string{
        oidSophosCPUUsage,
        oidSophosMemoryUsage,
        oidSophosMemoryTotal,
        oidSophosMemoryUsed,
        oidSophosDiskUsage,
    }
    
    resourcePkt, err := c.s.Get(resourceOIDs)
    if err == nil && len(resourcePkt.Variables) >= 5 {
        info.CPUUsage = toString(resourcePkt.Variables[0].Value)
        memUsagePercent := toString(resourcePkt.Variables[1].Value)
        info.MemoryTotal = toString(resourcePkt.Variables[2].Value)
        memUsed := toString(resourcePkt.Variables[3].Value)
        info.DiskUsage = toString(resourcePkt.Variables[4].Value)
        
        // Parse memory usage percentage
        if memPct, err := strconv.ParseFloat(memUsagePercent, 64); err == nil {
            info.MemoryUsagePercent = memPct
        }
        
        // Store memory values for NetBox
        info.MemoryFree = memUsed // We'll use this field for used memory
        
        fmt.Printf("  ✓ CPU Usage: %s%%\n", info.CPUUsage)
        fmt.Printf("  ✓ Memory Usage: %.0f%%\n", info.MemoryUsagePercent)
        fmt.Printf("  ✓ Disk Usage: %s%%\n", info.DiskUsage)
    }
    
    // Get HA information
    haOIDs := []string{
        oidSophosHAStatus,
        oidSophosHAPeerSerial,
        oidSophosHAMode,
    }
    
    haPkt, err := c.s.Get(haOIDs)
    if err == nil && len(haPkt.Variables) >= 3 {
        haStatus := toString(haPkt.Variables[0].Value)
        info.HAPeerSerial = toString(haPkt.Variables[1].Value)
        haMode := toString(haPkt.Variables[2].Value)
        
        // Convert HA status (0 = disabled, 1+ = enabled)
        if haStatus == "0" {
            info.HAEnabled = false
            info.HAStatus = "disabled"
        } else {
            info.HAEnabled = true
            info.HAStatus = "enabled"
            info.HAMode = haMode
            fmt.Printf("  ✓ HA: Enabled (Mode: %s, Peer: %s)\n", info.HAMode, info.HAPeerSerial)
        }
    }
    
    return info, nil
}


// IsSophosDevice checks if the device is a Sophos firewall
func (c *Client) IsSophosDevice() bool {
    pkt, err := c.s.Get([]string{oidSophosModel})
    if err != nil || len(pkt.Variables) == 0 {
        return false
    }
    model := toString(pkt.Variables[0].Value)
    return model != ""
}

// DebugWalkSophosOIDs walks the Sophos OID tree to discover available OIDs
func (c *Client) DebugWalkSophosOIDs() error {
    fmt.Println("\n→ Walking Sophos OID tree (.1.3.6.1.4.1.2604)...")
    count := 0
    
    err := c.s.Walk(".1.3.6.1.4.1.2604", func(variable g.SnmpPDU) error {
        count++
        if count <= 50 { // Limit output
            fmt.Printf("  %s = %v (type: %v)\n", variable.Name, variable.Value, variable.Type)
        }
        return nil
    })
    
    if err != nil {
        return fmt.Errorf("walk failed: %w", err)
    }
    
    fmt.Printf("  Found %d OIDs under Sophos tree\n", count)
    return nil
}
