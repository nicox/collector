package config

import (
    "fmt"
    "os"
    "time"

    "gopkg.in/yaml.v3"
)

type SNMPConfig struct {
    AuthProto string `yaml:"auth_proto"`
    AuthPass  string `yaml:"auth_pass"`
    PrivProto string `yaml:"priv_proto"`
    PrivPass  string `yaml:"priv_pass"`
    Timeout   int    `yaml:"timeout"` // seconds
    Retries   int    `yaml:"retries"`
}

type NetBoxConfig struct {
    URL      string `yaml:"url"`
    Token    string `yaml:"token"`
    Site     string `yaml:"site"`
    DryRun   bool   `yaml:"dry_run"`
    Insecure bool   `yaml:"insecure"`
}

type Device struct {
    Name   string `yaml:"name"`
    Target string `yaml:"target"`
    Port   int    `yaml:"port"`
    User   string `yaml:"user"`
}

type Config struct {
    SNMP    SNMPConfig   `yaml:"snmp"`
    NetBox  NetBoxConfig `yaml:"netbox"`
    Devices []Device     `yaml:"devices"`
}

// Load reads YAML config from file
func Load(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read config: %w", err)
    }

    cfg := &Config{
        SNMP: SNMPConfig{
            AuthProto: "SHA",
            PrivProto: "AES",
            Timeout:   5,
            Retries:   1,
        },
        NetBox: NetBoxConfig{
            Site:     "Default",
            DryRun:   true,
            Insecure: false,
        },
    }

    if err := yaml.Unmarshal(data, cfg); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }

    return cfg, nil
}

// GetSNMPTimeout returns SNMP timeout as duration
func (c *Config) GetSNMPTimeout() time.Duration {
    return time.Duration(c.SNMP.Timeout) * time.Second
}
