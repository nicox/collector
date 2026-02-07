package netbox

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"snmp-collector/internal/snmpclient"
	"strings"
	"strconv"
	"time"
)

type NetBoxClient struct {
	url    string
	token  string
	client *http.Client
}

func New(url, token string, insecure bool) (*NetBoxClient, error) {
	url = strings.TrimSuffix(url, "/")

	// Create HTTP client with optional insecure TLS
	transport := &http.Transport{}
	if insecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	return &NetBoxClient{
		url:    url,
		token:  token,
		client: &http.Client{Transport: transport},
	}, nil
}
/*
// GetOrCreateDeviceRole gets or creates a device role
func (n *NetBoxClient) GetOrCreateDeviceRole(roleName string) (float64, error) {
	// Try to get existing
	encodedRole := url.QueryEscape(roleName)
	resp, status, err := n.doRequest("GET", fmt.Sprintf("/dcim/device-roles/?name=%s", encodedRole), nil)
	if err != nil {
		return 0, err
	}

	if status == 200 {
		results, ok := resp["results"].([]interface{})
		if ok && len(results) > 0 {
			role, ok := results[0].(map[string]interface{})
			if ok {
				if id, ok := role["id"].(float64); ok {
					fmt.Printf(" ✓ Found role: %s (ID=%d)\n", roleName, int(id))
					return id, nil
				}
			}
		}
	}

	// Create role
	fmt.Printf(" → Creating role: %s\n", roleName)
	payload := map[string]interface{}{
		"name": roleName,
		"slug": strings.ToLower(roleName),
	}

	resp, status, err = n.doRequest("POST", "/dcim/device-roles/", payload)
	if err != nil {
		return 0, fmt.Errorf("failed to create role: %w", err)
	}
	if status >= 400 {
		return 0, fmt.Errorf("API error %d creating role", status)
	}

	roleID, ok := resp["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("no ID in role response")
	}

	fmt.Printf(" ✓ Created role (ID=%d)\n", int(roleID))
	return roleID, nil
}
*/

// GetOrCreateManufacturer gets or creates a manufacturer
func (n *NetBoxClient) GetOrCreateManufacturer(name string) (float64, error) {
	// Try to get existing
	encodedName := url.QueryEscape(name)
	resp, status, err := n.doRequest("GET", fmt.Sprintf("/dcim/manufacturers/?name=%s", encodedName), nil)
	if err != nil {
		return 0, err
	}

	if status == 200 {
		results, ok := resp["results"].([]interface{})
		if ok && len(results) > 0 {
			mfr, ok := results[0].(map[string]interface{})
			if ok {
				if id, ok := mfr["id"].(float64); ok {
					fmt.Printf(" ✓ Found manufacturer: %s (ID=%d)\n", name, int(id))
					return id, nil
				}
			}
		}
	}

	// Create manufacturer
	fmt.Printf(" → Creating manufacturer: %s\n", name)
	payload := map[string]interface{}{
		"name": name,
		"slug": strings.ToLower(name),
	}

	resp, status, err = n.doRequest("POST", "/dcim/manufacturers/", payload)
	if err != nil {
		return 0, fmt.Errorf("failed to create manufacturer: %w", err)
	}
	if status >= 400 {
		return 0, fmt.Errorf("API error %d creating manufacturer", status)
	}

	mfrID, ok := resp["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("no ID in manufacturer response")
	}

	fmt.Printf(" ✓ Created manufacturer (ID=%d)\n", int(mfrID))
	return mfrID, nil
}

// CreateDefaultDeviceType creates a generic/unknown device type
func (n *NetBoxClient) CreateDefaultDeviceType() (float64, error) {
	// First get or create Unknown manufacturer
	mfrID, err := n.GetOrCreateManufacturer("Unknown")
	if err != nil {
		return 0, fmt.Errorf("failed to get manufacturer: %w", err)
	}

	// Check if Generic device type exists
	resp, status, err := n.doRequest("GET", "/dcim/device-types/?model=Generic", nil)
	if err == nil && status == 200 {
		results, ok := resp["results"].([]interface{})
		if ok && len(results) > 0 {
			dt, ok := results[0].(map[string]interface{})
			if ok {
				if id, ok := dt["id"].(float64); ok {
					return id, nil
				}
			}
		}
	}

	// Create Generic device type
	fmt.Printf(" → Creating default device type: Generic\n")
	payload := map[string]interface{}{
		"manufacturer": int(mfrID),
		"model":        "Generic",
		"slug":         "generic",
	}

	resp, status, err = n.doRequest("POST", "/dcim/device-types/", payload)
	if err != nil {
		return 0, fmt.Errorf("failed to create device type: %w", err)
	}
	if status >= 400 {
		return 0, fmt.Errorf("API error %d creating device type", status)
	}

	dtID, ok := resp["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("no ID in device type response")
	}

	fmt.Printf(" ✓ Created device type (ID=%d)\n", int(dtID))
	return dtID, nil
}

// GetOrCreateDeviceTypeWithManufacturer gets or creates a device type with specific manufacturer
func (n *NetBoxClient) GetOrCreateDeviceTypeWithManufacturer(manufacturerID float64, model, slug string) (float64, error) {
	// Try to get existing device type by model name and manufacturer
	encodedModel := url.QueryEscape(model)
	resp, status, err := n.doRequest("GET", fmt.Sprintf("/dcim/device-types/?model=%s&manufacturer_id=%d", encodedModel, int(manufacturerID)), nil)
	if err != nil {
		return 0, err
	}

	if status == 200 {
		results, ok := resp["results"].([]interface{})
		if ok && len(results) > 0 {
			deviceType, ok := results[0].(map[string]interface{})
			if ok {
				if id, ok := deviceType["id"].(float64); ok {
					fmt.Printf(" ✓ Found device type: %s (ID=%d)\n", model, int(id))
					return id, nil
				}
			}
		}
	}

	// Device type not found, create it
	fmt.Printf(" → Creating device type: %s\n", model)

	// Ensure slug is valid (lowercase, alphanumeric + hyphens only)
	if slug == "" {
		slug = strings.ToLower(strings.ReplaceAll(model, " ", "-"))
	}
	// Remove invalid characters from slug
	re := regexp.MustCompile(`[^a-z0-9-]`)
	slug = re.ReplaceAllString(slug, "")

	payload := map[string]interface{}{
		"manufacturer": int(manufacturerID),
		"model":        model,
		"slug":         slug,
	}

	resp, status, err = n.doRequest("POST", "/dcim/device-types/", payload)
	if err != nil {
		return 0, fmt.Errorf("failed to create device type: %w", err)
	}
	if status >= 400 {
		return 0, fmt.Errorf("API error %d creating device type", status)
	}

	dtID, ok := resp["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("no ID in device type response")
	}

	fmt.Printf(" ✓ Created device type (ID=%d)\n", int(dtID))
	return dtID, nil
}

// doRequest helper for API calls
func (n *NetBoxClient) doRequest(method, path string, body interface{}) (map[string]interface{}, int, error) {
	url := fmt.Sprintf("%s%s", n.url, path)

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Token %s", n.token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	// DEBUG: Log response for troubleshooting
	if resp.StatusCode >= 400 {
		fmt.Printf("DEBUG: %s %s -> %d\n%s\n", method, path, resp.StatusCode, string(respBody))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to parse response (status %d): %w\nBody: %s", resp.StatusCode, err, string(respBody))
	}

	return result, resp.StatusCode, nil
}

// GetSiteID looks up a site by name
func (n *NetBoxClient) GetSiteID(siteName string) (float64, error) {
	encodedSite := url.QueryEscape(siteName)
	resp, status, err := n.doRequest("GET", fmt.Sprintf("/dcim/sites/?name=%s", encodedSite), nil)
	if err != nil {
		return 0, err
	}

	if status >= 400 {
		return 0, fmt.Errorf("failed to get site: status %d", status)
	}

	results, ok := resp["results"].([]interface{})
	if !ok || len(results) == 0 {
		return 0, fmt.Errorf("site %q not found", siteName)
	}

	site, ok := results[0].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid site response")
	}

	siteID, ok := site["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("no ID in site response")
	}

	return siteID, nil
}

// PushARPEntries creates IP addresses in NetBox from ARP entries discovered on source device
func (n *NetBoxClient) PushARPEntries(sourceSysName string, sourceSiteID float64, arpEntries []snmpclient.ARPEntry) (int, error) {
	if len(arpEntries) == 0 {
		return 0, nil
	}

	fmt.Printf("→ Creating/updating IP addresses from ARP entries (%d found):\n", len(arpEntries))
	createdCount := 0

	for _, entry := range arpEntries {
		ipAddr := entry.IPAddr
		mac := entry.MACAddr

		// Check if IP address already exists
		encodedIP := url.QueryEscape(ipAddr)
		resp, _, _ := n.doRequest("GET", fmt.Sprintf("/ipam/ip-addresses/?address=%s", encodedIP), nil)

		if results, ok := resp["results"].([]interface{}); ok && len(results) > 0 {
			ipObject, ok := results[0].(map[string]interface{})
			if ok {
				if id, ok := ipObject["id"].(float64); ok {
					// IP exists; update description with discovery info
					fmt.Printf(" ✓ IP %s exists (ID=%d), updating description\n", ipAddr, int(id))

					description := fmt.Sprintf("Discovered via ARP on %s | MAC: %s", sourceSysName, mac)
					if entry.Hostname != "" {
						description = fmt.Sprintf("%s | Hostname: %s", entry.Hostname, description)
					}

					updatePayload := map[string]interface{}{
						"description": description,
					}
					n.doRequest("PATCH", fmt.Sprintf("/ipam/ip-addresses/%d/", int(id)), updatePayload)
					continue
				}
			}
		}

		// Create new IP address entry
		description := fmt.Sprintf("Discovered via ARP on %s | MAC: %s", sourceSysName, mac)
		if entry.Hostname != "" {
			description = fmt.Sprintf("%s | Hostname: %s", entry.Hostname, description)
		}

		payload := map[string]interface{}{
			"address":     ipAddr + "/32", // NetBox requires CIDR notation
			"status":      "active",
			"description": description,
			"dns_name":    entry.Hostname,
		}

		// Add custom field for MAC address if available
		if mac != "" {
			payload["custom_fields"] = map[string]interface{}{
				"mac_address": mac,
			}
		}

		resp, status, err := n.doRequest("POST", "/ipam/ip-addresses/", payload)
		if err != nil {
			fmt.Printf(" ❌ Failed to create IP %s: %v\n", ipAddr, err)
			continue
		}
		if status >= 400 {
			fmt.Printf(" ❌ API error %d creating IP %s\n", status, ipAddr)
			continue
		}

		ipID, ok := resp["id"].(float64)
		if !ok {
			continue
		}

		fmt.Printf(" ✓ Created IP %s (ID=%d)\n", ipAddr, int(ipID))
		createdCount++
	}

	fmt.Printf(" Created %d/%d IP addresses from ARP entries\n", createdCount, len(arpEntries))
	return createdCount, nil
}

// createInterfaceForARPDevice creates an interface with the MAC address as name
func (n *NetBoxClient) createInterfaceForARPDevice(deviceID float64, macAddress string) error {
	payload := map[string]interface{}{
		"device":      int(deviceID),
		"name":        macAddress,
		"type":
		"virtual",
		"description": "MAC address interface",
	}

	resp, status, err := n.doRequest("POST", "/dcim/interfaces/", payload)
	if err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}
	if status >= 400 {
		return fmt.Errorf("API error %d", status)
	}

	if _, ok := resp["id"]; ok {
		fmt.Printf(" ✓ Created interface: %s\n", macAddress)
	}

	return nil
}

// UpdateDeviceNotes appends discovery info to device notes
func (n *NetBoxClient) UpdateDeviceNotes(deviceID float64, sourceSysName, ip, mac string) error {
	// Get existing device
	resp, status, err := n.doRequest("GET", fmt.Sprintf("/dcim/devices/%d/", int(deviceID)), nil)
	if err != nil || status >= 400 {
		return fmt.Errorf("failed to get device: %w", err)
	}

	// Append to comments
	existingComments := ""
	if comments, ok := resp["comments"].(string); ok {
		existingComments = comments
	}

	newComments := fmt.Sprintf("%s\n[Discovered from ARP on %s: IP=%s MAC=%s]",
		existingComments, sourceSysName, ip, mac)

	// Update device
	payload := map[string]interface{}{
		"comments": newComments,
	}

	_, status, err = n.doRequest("PATCH", fmt.Sprintf("/dcim/devices/%d/", int(deviceID)), payload)
	if err != nil || status >= 400 {
		return fmt.Errorf("failed to update device notes: %w", err)
	}

	return nil
}

// PushDevice creates a device in NetBox with proper manufacturer and device type detection
func (n *NetBoxClient) PushDevice(deviceInfo *snmpclient.DeviceInfo, siteName, deviceRole string) (float64, error) {
	if deviceInfo == nil || deviceInfo.SysName == "" {
		return 0, fmt.Errorf("invalid device info")
	}

	// Check if device already exists
	encodedName := url.QueryEscape(deviceInfo.SysName)
	resp, _, _ := n.doRequest("GET", fmt.Sprintf("/dcim/devices/?name=%s", encodedName), nil)
	if results, ok := resp["results"].([]interface{}); ok && len(results) > 0 {
		device, ok := results[0].(map[string]interface{})
		if ok {
			if id, ok := device["id"].(float64); ok {
				fmt.Printf(" ✓ Device %s already exists (ID=%d)\n", deviceInfo.SysName, int(id))
				return id, nil
			}
		}
	}

	fmt.Printf("→ Creating device in NetBox:\n")
	fmt.Printf(" Name: %s\n", deviceInfo.SysName)
	fmt.Printf(" SysObjectID: %s\n", deviceInfo.SysObjectID)
	fmt.Printf(" SysDescr: %s\n", deviceInfo.SysDescr)

	// Parse manufacturer and model from SNMP data
	deviceTypeInfo := ParseDeviceType(deviceInfo.SysObjectID, deviceInfo.SysDescr)
	fmt.Printf(" Detected Manufacturer: %s\n", deviceTypeInfo.Manufacturer)
	fmt.Printf(" Detected Model: %s\n", deviceTypeInfo.Model)

	// Get site ID
	siteID, err := n.GetSiteID(siteName)
	if err != nil {
		return 0, fmt.Errorf("failed to get site: %w", err)
	}

	// Get or create manufacturer
	mfrID, err := n.GetOrCreateManufacturer(deviceTypeInfo.Manufacturer)
	if err != nil {
		return 0, fmt.Errorf("failed to get manufacturer: %w", err)
	}

	// Get or create device type
	deviceTypeID, err := n.GetOrCreateDeviceTypeWithManufacturer(mfrID, deviceTypeInfo.Model, deviceTypeInfo.Slug)
	if err != nil {
		return 0, fmt.Errorf("failed to get device type: %w", err)
	}

	// Get or create device role
	roleID, err := n.GetOrCreateDeviceRole(deviceRole)
	if err != nil {
		return 0, fmt.Errorf("failed to get role: %w", err)
	}

	// Create device payload
	payload := map[string]interface{}{
		"name":        deviceInfo.SysName,
		"site":        int(siteID),
		"device_type": int(deviceTypeID),
		"role":        int(roleID),
		"comments":    deviceInfo.SysDescr,
		"asset_tag":   deviceInfo.SysName,
	}

	resp, status, err := n.doRequest("POST", "/dcim/devices/", payload)
	if err != nil {
		return 0, fmt.Errorf("failed to create device: %w", err)
	}
	if status >= 400 {
		return 0, fmt.Errorf("API error %d: failed to create device", status)
	}

	deviceID, ok := resp["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("no ID in device response")
	}

	fmt.Printf(" ✓ Created device with ID=%d\n", int(deviceID))
	return deviceID, nil
}

// PushInterfaces creates interfaces for a device
func (n *NetBoxClient) PushInterfaces(deviceID float64, ifaces []snmpclient.InterfaceInfo) error {
	if deviceID == 0 || len(ifaces) == 0 {
		return fmt.Errorf("invalid device ID or empty interfaces")
	}

	fmt.Printf("→ Creating interfaces for device %d:\n", int(deviceID))
	successCount := 0

	for _, iface := range ifaces {
		if iface.Name == "" {
			continue
		}

		// Map interface type number to NetBox type
		ifType := "1000base-t"
		if iface.Type == "1" {
			ifType = "virtual"
		} else if iface.Type == "6" {
			ifType = "1000base-t"
		}

		payload := map[string]interface{}{
			"device":      int(deviceID),
			"name":        iface.Name,
			"type":        ifType,
			"description": iface.Alias,
		}

		resp, status, err := n.doRequest("POST", "/dcim/interfaces/", payload)
		if err != nil {
			fmt.Printf(" ❌ Failed to create interface %s: %v\n", iface.Name, err)
			continue
		}
		if status >= 400 {
			fmt.Printf(" ❌ API error %d creating interface %s\n", status, iface.Name)
			continue
		}

		interfaceID, ok := resp["id"].(float64)
		if !ok {
			continue
		}

		fmt.Printf(" ✓ Created interface: %s\n", iface.Name)
		successCount++

		// Add IP addresses to this interface
		if len(iface.IPs) > 0 {
			for _, ip := range iface.IPs {
				if err := n.addIPToInterface(interfaceID, ip); err != nil {
					fmt.Printf(" ⚠ Failed to add IP %s: %v\n", ip, err)
				} else {
					fmt.Printf(" ✓ Added IP: %s\n", ip)
				}
			}
		}
	}

	fmt.Printf(" Created %d/%d interfaces\n", successCount, len(ifaces))
	return nil
}

// addIPToInterface creates an IP address assignment in NetBox
func (n *NetBoxClient) addIPToInterface(interfaceID float64, ip string) error {
	payload := map[string]interface{}{
		"address":              ip + "/32", // NetBox requires CIDR notation
		"assigned_object_type": "dcim.interface",
		"assigned_object_id":   int(interfaceID),
		"status":               "active",
	}

	_, status, err := n.doRequest("POST", "/ipam/ip-addresses/", payload)
	if err != nil {
		return fmt.Errorf("failed to create IP: %w", err)
	}
	if status >= 400 {
		return fmt.Errorf("API error %d", status)
	}

	return nil
}

// EnsureSophosCustomFields creates custom fields for Sophos firewalls if they don't exist
func (n *NetBoxClient) EnsureSophosCustomFields() error {
    customFields := []map[string]interface{}{
        {
            "name":         "firmware_version",
            "label":        "Firmware Version",
            "type":         "text",
            "object_types": []string{"dcim.device"},  // Changed from content_types
            "description":  "Current firmware version",
            "group_name":   "Software",
        },
        {
            "name":         "license_status",
            "label":        "License Status",
            "type":         "text",
            "object_types": []string{"dcim.device"},
            "description":  "Current license status",
            "group_name":   "Licensing",
        },
        {
            "name":         "license_expiry",
            "label":        "License Expiration",
            "type":         "date",
            "object_types": []string{"dcim.device"},
            "description":  "License expiration date",
            "group_name":   "Licensing",
        },
        {
            "name":         "cpu_usage_percent",
            "label":        "CPU Usage %",
            "type":         "integer",
            "object_types": []string{"dcim.device"},
            "description":  "Current CPU usage percentage",
            "group_name":   "Statistics",
        },
        {
            "name":         "memory_total_mb",
            "label":        "Total Memory (MB)",
            "type":         "integer",
            "object_types": []string{"dcim.device"},
            "description":  "Total system memory in megabytes",
            "group_name":   "Hardware",
        },
        {
            "name":         "memory_usage_percent",
            "label":        "Memory Usage %",
            "type":         "integer",
            "object_types": []string{"dcim.device"},
            "description":  "Current memory usage percentage",
            "group_name":   "Statistics",
        },
        {
            "name":         "disk_usage_percent",
            "label":        "Disk Usage %",
            "type":         "integer",
            "object_types": []string{"dcim.device"},
            "description":  "Current disk usage percentage",
            "group_name":   "Statistics",
        },
        {
            "name":         "active_connections",
            "label":        "Active Connections",
            "type":         "integer",
            "object_types": []string{"dcim.device"},
            "description":  "Current number of active connections",
            "group_name":   "Statistics",
        },
        {
            "name":         "ha_enabled",
            "label":        "HA Enabled",
            "type":         "boolean",
            "object_types": []string{"dcim.device"},
            "description":  "High Availability configuration status",
            "group_name":   "Clustering",
        },
        {
            "name":         "ha_status",
            "label":        "HA Status",
            "type":         "text",
            "object_types": []string{"dcim.device"},
            "description":  "High Availability current status",
            "group_name":   "Clustering",
        },
        {
            "name":         "ha_peer_serial",
            "label":        "HA Peer Serial",
            "type":         "text",
            "object_types": []string{"dcim.device"},
            "description":  "Serial number of HA peer device",
            "group_name":   "Clustering",
        },
        {
            "name":         "last_discovered",
            "label":        "Last Discovered",
            "type":         "date",
            "object_types": []string{"dcim.device"},
            "description":  "Timestamp of last successful discovery",
            "group_name":   "Discovery",
        },
    }
    
    for _, field := range customFields {
        // Check if field exists
        name := field["name"].(string)
        resp, _, _ := n.doRequest("GET", fmt.Sprintf("/extras/custom-fields/?name=%s", url.QueryEscape(name)), nil)
        
        if results, ok := resp["results"].([]interface{}); ok && len(results) > 0 {
            fmt.Printf(" ✓ Custom field '%s' already exists\n", name)
            continue
        }
        
        // Create field
        fmt.Printf(" → Creating custom field: %s\n", name)
        _, status, err := n.doRequest("POST", "/extras/custom-fields/", field)
        if err != nil || status >= 400 {
            fmt.Printf(" ❌ Failed to create custom field %s: %v (status: %d)\n", name, err, status)
            continue
        }
        fmt.Printf(" ✓ Created custom field: %s\n", name)
    }
    
    return nil
}

// UpdateDeviceWithSophosInfo updates a device with Sophos-specific information
func (n *NetBoxClient) UpdateDeviceWithSophosInfo(deviceID float64, sophosInfo *snmpclient.SophosFirewallInfo) error {
    if sophosInfo == nil {
        return fmt.Errorf("sophosInfo is nil")
    }
    
    customFields := map[string]interface{}{}
    
    if sophosInfo.FirmwareVersion != "" {
        customFields["firmware_version"] = sophosInfo.FirmwareVersion
    }
    if sophosInfo.LicenseStatus != "" {
        customFields["license_status"] = sophosInfo.LicenseStatus
    }
    
    // Only add license expiry if it's a valid date (not empty or "Not Available")
    if sophosInfo.LicenseExpiry != "" && 
       sophosInfo.LicenseExpiry != "Not Available" &&
       sophosInfo.LicenseExpiry != "0" {
        // Try to parse and reformat the date if needed
        if parsedDate, err := time.Parse("2006-01-02", sophosInfo.LicenseExpiry); err == nil {
            customFields["license_expiry"] = parsedDate.Format("2006-01-02")
        } else if parsedDate, err := time.Parse("02/01/2006", sophosInfo.LicenseExpiry); err == nil {
            customFields["license_expiry"] = parsedDate.Format("2006-01-02")
        }
        // If parsing fails, skip the field
    }
    
    // Parse and add numeric values
    if cpuUsage, err := strconv.Atoi(sophosInfo.CPUUsage); err == nil {
        customFields["cpu_usage_percent"] = cpuUsage
    }
    
    if memTotal, err := strconv.ParseFloat(sophosInfo.MemoryTotal, 64); err == nil && memTotal > 0 {
        customFields["memory_total_mb"] = int(memTotal)
    }
    
    if sophosInfo.MemoryUsagePercent > 0 {
        customFields["memory_usage_percent"] = int(sophosInfo.MemoryUsagePercent)
    }
    
    if diskUsage, err := strconv.Atoi(sophosInfo.DiskUsage); err == nil {
        customFields["disk_usage_percent"] = diskUsage
    }
    
    // HA information
    customFields["ha_enabled"] = sophosInfo.HAEnabled
    if sophosInfo.HAStatus != "" {
        customFields["ha_status"] = sophosInfo.HAStatus
    }
    if sophosInfo.HAPeerSerial != "" && sophosInfo.HAEnabled {
        customFields["ha_peer_serial"] = sophosInfo.HAPeerSerial
    }
    
    // Add discovery timestamp
    customFields["last_discovered"] = time.Now().Format("2006-01-02")
    
    // Update device
    payload := map[string]interface{}{
        "custom_fields": customFields,
    }
    
    // Also update device serial field
    if sophosInfo.SerialNumber != "" {
        payload["serial"] = sophosInfo.SerialNumber
    }
    
    // Update comments with additional info
    comments := fmt.Sprintf("Sophos %s\nSerial: %s\nFirmware: %s\nLast Discovery: %s",
        sophosInfo.Model,
        sophosInfo.SerialNumber,
        sophosInfo.FirmwareVersion,
        time.Now().Format("2006-01-02 15:04:05"))
    
    if sophosInfo.HAEnabled {
        comments += fmt.Sprintf("\nHA: Enabled (Peer: %s)", sophosInfo.HAPeerSerial)
    }
    
    if sophosInfo.LicenseStatus != "" {
        comments += fmt.Sprintf("\nLicense: %s", sophosInfo.LicenseStatus)
    }
    
    payload["comments"] = comments
    
    _, status, err := n.doRequest("PATCH", fmt.Sprintf("/dcim/devices/%d/", int(deviceID)), payload)
    if err != nil || status >= 400 {
        return fmt.Errorf("failed to update device (status %d): %w", status, err)
    }
    
    fmt.Printf(" ✓ Updated device with Sophos information\n")
    fmt.Printf("   - Serial: %s\n", sophosInfo.SerialNumber)
    fmt.Printf("   - Firmware: %s\n", sophosInfo.FirmwareVersion)
    fmt.Printf("   - CPU: %s%%, Memory: %.0f%%, Disk: %s%%\n", 
        sophosInfo.CPUUsage, sophosInfo.MemoryUsagePercent, sophosInfo.DiskUsage)
    
    return nil
}

// EnsureManufacturer creates manufacturer if it doesn't exist
func (n *NetBoxClient) EnsureManufacturer(name string) (float64, error) {
    slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
    
    // Check if exists
    resp, _, _ := n.doRequest("GET", fmt.Sprintf("/dcim/manufacturers/?slug=%s", url.QueryEscape(slug)), nil)
    
    if results, ok := resp["results"].([]interface{}); ok && len(results) > 0 {
        if mfg, ok := results[0].(map[string]interface{}); ok {
            return mfg["id"].(float64), nil
        }
    }
    
    // Create manufacturer
    payload := map[string]interface{}{
        "name": name,
        "slug": slug,
    }
    
    resp, status, err := n.doRequest("POST", "/dcim/manufacturers/", payload)
    if err != nil || status >= 400 {
        return 0, fmt.Errorf("failed to create manufacturer: %w", err)
    }
    
    return resp["id"].(float64), nil
}

// EnsureDeviceType creates device type if it doesn't exist
func (n *NetBoxClient) EnsureDeviceType(manufacturerID float64, model, slug string) (float64, error) {
    // Check if exists
    resp, _, _ := n.doRequest("GET", fmt.Sprintf("/dcim/device-types/?slug=%s", url.QueryEscape(slug)), nil)
    
    if results, ok := resp["results"].([]interface{}); ok && len(results) > 0 {
        if dt, ok := results[0].(map[string]interface{}); ok {
            fmt.Printf(" ✓ Device type '%s' already exists\n", model)
            return dt["id"].(float64), nil
        }
    }
    
    // Create device type
    payload := map[string]interface{}{
        "manufacturer": int(manufacturerID),
        "model":        model,
        "slug":         slug,
    }
    
    resp, status, err := n.doRequest("POST", "/dcim/device-types/", payload)
    if err != nil || status >= 400 {
        return 0, fmt.Errorf("failed to create device type: %w", err)
    }
    
    fmt.Printf(" ✓ Created device type: %s\n", model)
    return resp["id"].(float64), nil
}

// CreateDeviceWithType creates a device with proper device type
func (n *NetBoxClient) CreateDeviceWithType(name, manufacturer, model, role, site string) (float64, error) {
    fmt.Printf("→ Creating device '%s' (%s %s)\n", name, manufacturer, model)
    
    // Ensure manufacturer exists
    mfgID, err := n.EnsureManufacturer(manufacturer)
    if err != nil {
        return 0, fmt.Errorf("failed to ensure manufacturer: %w", err)
    }
    
    // Generate slug for device type
    slug := strings.ToLower(strings.ReplaceAll(model, " ", "-"))
    slug = strings.ReplaceAll(slug, "/", "-")
    
    // Ensure device type exists
    dtID, err := n.EnsureDeviceType(mfgID, model, slug)
    if err != nil {
        return 0, fmt.Errorf("failed to ensure device type: %w", err)
    }
    
    // Get site ID
    siteID, err := n.GetSiteID(site)
    if err != nil {
        return 0, fmt.Errorf("failed to get site: %w", err)
    }
    
    // Get device role ID
    roleID, err := n.GetOrCreateDeviceRole(role)
    if err != nil {
        return 0, fmt.Errorf("failed to get device role: %w", err)
    }
    
    // Check if device already exists
    resp, _, _ := n.doRequest("GET", fmt.Sprintf("/dcim/devices/?name=%s", url.QueryEscape(name)), nil)
    
    if results, ok := resp["results"].([]interface{}); ok && len(results) > 0 {
        if device, ok := results[0].(map[string]interface{}); ok {
            fmt.Printf(" ✓ Device '%s' already exists (ID=%.0f)\n", name, device["id"].(float64))
            return device["id"].(float64), nil
        }
    }
    
    // Create device
    payload := map[string]interface{}{
        "name":        name,
        "device_type": int(dtID),
        "role":        int(roleID),
        "site":        int(siteID),
        "status":      "active",
    }
    
    resp, status, err := n.doRequest("POST", "/dcim/devices/", payload)
    if err != nil || status >= 400 {
        return 0, fmt.Errorf("failed to create device: %w", err)
    }
    
    deviceID := resp["id"].(float64)
    fmt.Printf(" ✓ Created device '%s' (ID=%.0f)\n", name, deviceID)
    
    return deviceID, nil
}

// GetOrCreateDeviceRole ensures device role exists
func (n *NetBoxClient) GetOrCreateDeviceRole(name string) (float64, error) {
    slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
    
    // Check if exists
    resp, _, _ := n.doRequest("GET", fmt.Sprintf("/dcim/device-roles/?slug=%s", url.QueryEscape(slug)), nil)
    
    if results, ok := resp["results"].([]interface{}); ok && len(results) > 0 {
        if role, ok := results[0].(map[string]interface{}); ok {
            return role["id"].(float64), nil
        }
    }
    
    // Create role
    payload := map[string]interface{}{
        "name":        name,
        "slug":        slug,
        "color":       "9e9e9e",
        "vm_role":     false,
    }
    
    resp, status, err := n.doRequest("POST", "/dcim/device-roles/", payload)
    if err != nil || status >= 400 {
        return 0, fmt.Errorf("failed to create device role: %w", err)
    }
    
    return resp["id"].(float64), nil
}
