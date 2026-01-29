package netbox

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"snmp-collector/internal/snmpclient"
	"strings"
	"net/url"
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
					fmt.Printf("  ✓ Found role: %s (ID=%d)\n", roleName, int(id))
					return id, nil
				}
			}
		}
	}

	// Create role
	fmt.Printf("  → Creating role: %s\n", roleName)
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

	fmt.Printf("  ✓ Created role (ID=%d)\n", int(roleID))
	return roleID, nil
}

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
					return id, nil
				}
			}
		}
	}

	// Create manufacturer
	fmt.Printf("  → Creating manufacturer: %s\n", name)
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

	fmt.Printf("  ✓ Created manufacturer (ID=%d)\n", int(mfrID))
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
	fmt.Printf("  → Creating default device type: Generic\n")
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

	fmt.Printf("  ✓ Created device type (ID=%d)\n", int(dtID))
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


// GetOrCreateDeviceType gets or creates a device type
// GetOrCreateDeviceType gets or creates a device type
func (n *NetBoxClient) GetOrCreateDeviceType(manufacturer, model string) (float64, error) {
	// URL encode the model to handle spaces
	encodedModel := url.QueryEscape(model)

	// Try to get existing
	resp, status, err := n.doRequest("GET", fmt.Sprintf("/dcim/device-types/?model=%s", encodedModel), nil)
	if err != nil {
		return 0, err
	}

	if status == 200 {
		results, ok := resp["results"].([]interface{})
		if ok && len(results) > 0 {
			deviceType, ok := results[0].(map[string]interface{})
			if ok {
				if id, ok := deviceType["id"].(float64); ok {
					fmt.Printf("  ✓ Found device type: %s (ID=%d)\n", model, int(id))
					return id, nil
				}
			}
		}
	}

	// Device type not found, use generic default
	fmt.Printf("  ⚠ Device type %q not found, using Generic default\n", model)
	return n.CreateDefaultDeviceType()
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
                    fmt.Printf("  ✓ IP %s exists (ID=%d), updating description\n", ipAddr, int(id))
                    
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
            fmt.Printf("  ❌ Failed to create IP %s: %v\n", ipAddr, err)
            continue
        }

        if status >= 400 {
            fmt.Printf("  ❌ API error %d creating IP %s\n", status, ipAddr)
            continue
        }

        ipID, ok := resp["id"].(float64)
        if !ok {
            continue
        }

        fmt.Printf("  ✓ Created IP %s (ID=%d)\n", ipAddr, int(ipID))
        createdCount++
    }

    fmt.Printf("  Created %d/%d IP addresses from ARP entries\n", createdCount, len(arpEntries))
    return createdCount, nil
}

// createInterfaceForARPDevice creates an interface with the MAC address as name
func (n *NetBoxClient) createInterfaceForARPDevice(deviceID float64, macAddress string) error {
	payload := map[string]interface{}{
		"device":      int(deviceID),
		"name":        macAddress,
		"type":        "virtual",
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
		fmt.Printf("    ✓ Created interface: %s\n", macAddress)
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


// PushDevice creates a device in NetBox
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
				fmt.Printf("  ✓ Device %s already exists (ID=%d)\n", deviceInfo.SysName, int(id))
				return id, nil
			}
		}
	}

	fmt.Printf("→ Creating device in NetBox:\n")
	fmt.Printf("  Name: %s\n", deviceInfo.SysName)
	fmt.Printf("  Site: %s\n", siteName)
	fmt.Printf("  Role: %s\n", deviceRole)

	// Get site ID
	siteID, err := n.GetSiteID(siteName)
	if err != nil {
		return 0, fmt.Errorf("failed to get site: %w", err)
	}

	// Get or create device role
	roleID, err := n.GetOrCreateDeviceRole(deviceRole)
	if err != nil {
		return 0, fmt.Errorf("failed to get role: %w", err)
	}

	// Get device type (for now, use model from sysDescr)
	deviceTypeID, err := n.GetOrCreateDeviceType("Unknown", deviceInfo.SysDescr)
	if err != nil {
		return 0, fmt.Errorf("failed to get device type: %w", err)
	}

	// Create device payload
	payload := map[string]interface{}{
		"name":        deviceInfo.SysName,
		"site":        int(siteID),
		"device_type": int(deviceTypeID),
		"role":        int(roleID),  // ← ADD ROLE
		"comments":    deviceInfo.SysDescr,
		//"serial":      deviceInfo.SysObjectID,
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

	fmt.Printf("  ✓ Created device with ID=%d\n", int(deviceID))
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
			fmt.Printf("  ❌ Failed to create interface %s: %v\n", iface.Name, err)
			continue
		}

		if status >= 400 {
			fmt.Printf("  ❌ API error %d creating interface %s\n", status, iface.Name)
			continue
		}

		interfaceID, ok := resp["id"].(float64)
		if !ok {
			continue
		}

		fmt.Printf("  ✓ Created interface: %s\n", iface.Name)
		successCount++

		// Add IP addresses to this interface
		if len(iface.IPs) > 0 {
			for _, ip := range iface.IPs {
				if err := n.addIPToInterface(interfaceID, ip); err != nil {
					fmt.Printf("    ⚠ Failed to add IP %s: %v\n", ip, err)
				} else {
					fmt.Printf("    ✓ Added IP: %s\n", ip)
				}
			}
		}
	}

	fmt.Printf("  Created %d/%d interfaces\n", successCount, len(ifaces))
	return nil
}

// addIPToInterface creates an IP address assignment in NetBox
func (n *NetBoxClient) addIPToInterface(interfaceID float64, ip string) error {
	payload := map[string]interface{}{
		"address":   ip + "/32",  // NetBox requires CIDR notation
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

