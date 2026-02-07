package devicetypes

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"
)

const (
    DeviceTypeLibraryURL = "https://api.github.com/repos/netbox-community/devicetype-library/contents/device-types"
    CacheDir            = "/tmp/devicetype-cache"
    CacheDuration       = 24 * time.Hour
)

type DeviceTypeDefinition struct {
    Manufacturer string `yaml:"manufacturer" json:"manufacturer"`
    Model        string `yaml:"model" json:"model"`
    Slug         string `yaml:"slug" json:"slug"`
    PartNumber   string `yaml:"part_number" json:"part_number"`
    UHeight      float64 `yaml:"u_height" json:"u_height"`
    IsFullDepth  bool   `yaml:"is_full_depth" json:"is_full_depth"`
    Comments     string `yaml:"comments" json:"comments"`
}

type GitHubFile struct {
    Name        string `json:"name"`
    Path        string `json:"path"`
    Type        string `json:"type"`
    DownloadURL string `json:"download_url"`
    URL         string `json:"url"`
}

type Loader struct {
    cacheDir string
    client   *http.Client
}

func NewLoader() *Loader {
    return &Loader{
        cacheDir: CacheDir,
        client: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

// GetDeviceType fetches a device type definition by manufacturer and model
func (l *Loader) GetDeviceType(manufacturer, model string) (*DeviceTypeDefinition, error) {
    // Normalize manufacturer name
    mfg := strings.ToLower(strings.ReplaceAll(manufacturer, " ", "-"))
    
    // Check cache first
    cached, err := l.loadFromCache(mfg, model)
    if err == nil {
        return cached, nil
    }
    
    // Fetch from GitHub
    return l.fetchFromGitHub(mfg, model)
}

// FetchManufacturerDeviceTypes fetches all device types for a manufacturer
func (l *Loader) FetchManufacturerDeviceTypes(manufacturer string) ([]DeviceTypeDefinition, error) {
    mfg := strings.ToLower(strings.ReplaceAll(manufacturer, " ", "-"))
    
    url := fmt.Sprintf("%s/%s", DeviceTypeLibraryURL, mfg)
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Accept", "application/vnd.github.v3+json")
    
    resp, err := l.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
    }
    
    var files []GitHubFile
    if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
        return nil, err
    }
    
    var deviceTypes []DeviceTypeDefinition
    
    for _, file := range files {
        if !strings.HasSuffix(file.Name, ".yaml") {
            continue
        }
        
        dt, err := l.downloadDeviceType(file.DownloadURL)
        if err != nil {
            fmt.Printf("  ⚠ Failed to download %s: %v\n", file.Name, err)
            continue
        }
        
        deviceTypes = append(deviceTypes, *dt)
        
        // Cache it
        l.saveToCache(mfg, dt)
    }
    
    return deviceTypes, nil
}

func (l *Loader) downloadDeviceType(url string) (*DeviceTypeDefinition, error) {
    resp, err := l.client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    // Parse YAML (we'll use a simple approach for now)
    dt := &DeviceTypeDefinition{}
    
    // Simple YAML parsing for key fields
    lines := strings.Split(string(body), "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if strings.HasPrefix(line, "manufacturer:") {
            dt.Manufacturer = strings.TrimSpace(strings.TrimPrefix(line, "manufacturer:"))
        } else if strings.HasPrefix(line, "model:") {
            dt.Model = strings.TrimSpace(strings.TrimPrefix(line, "model:"))
        } else if strings.HasPrefix(line, "slug:") {
            dt.Slug = strings.TrimSpace(strings.TrimPrefix(line, "slug:"))
        } else if strings.HasPrefix(line, "part_number:") {
            dt.PartNumber = strings.TrimSpace(strings.TrimPrefix(line, "part_number:"))
        }
    }
    
    return dt, nil
}

func (l *Loader) fetchFromGitHub(manufacturer, model string) (*DeviceTypeDefinition, error) {
    // Fetch all device types for manufacturer
    deviceTypes, err := l.FetchManufacturerDeviceTypes(manufacturer)
    if err != nil {
        return nil, err
    }
    
    // Find matching model
    for _, dt := range deviceTypes {
        if strings.EqualFold(dt.Model, model) {
            return &dt, nil
        }
    }
    
    return nil, fmt.Errorf("device type not found: %s %s", manufacturer, model)
}

func (l *Loader) loadFromCache(manufacturer, model string) (*DeviceTypeDefinition, error) {
    cacheFile := filepath.Join(l.cacheDir, manufacturer, fmt.Sprintf("%s.json", model))
    
    info, err := os.Stat(cacheFile)
    if err != nil {
        return nil, err
    }
    
    // Check if cache is expired
    if time.Since(info.ModTime()) > CacheDuration {
        return nil, fmt.Errorf("cache expired")
    }
    
    data, err := os.ReadFile(cacheFile)
    if err != nil {
        return nil, err
    }
    
    var dt DeviceTypeDefinition
    if err := json.Unmarshal(data, &dt); err != nil {
        return nil, err
    }
    
    return &dt, nil
}

func (l *Loader) saveToCache(manufacturer string, dt *DeviceTypeDefinition) error {
    cacheDir := filepath.Join(l.cacheDir, manufacturer)
    if err := os.MkdirAll(cacheDir, 0755); err != nil {
        return err
    }
    
    cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s.json", dt.Model))
    
    data, err := json.Marshal(dt)
    if err != nil {
        return err
    }
    
    return os.WriteFile(cacheFile, data, 0644)
}
