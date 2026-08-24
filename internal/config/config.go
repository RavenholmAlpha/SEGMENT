// Package config loads YAML configuration for the server and client
// CLIs (design doc §10). Values in the file are defaults; per-value
// command-line flags override them when set explicitly.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Pacing mirrors tunnel.Pacing in YAML form.
type Pacing struct {
	Enabled    bool `yaml:"enabled"`
	BurstKB    int  `yaml:"burst_kb"`
	MinPauseMS int  `yaml:"min_pause_ms"`
	MaxPauseMS int  `yaml:"max_pause_ms"`
}

// Server is the segment-server configuration.
type Server struct {
	Listen   string `yaml:"listen"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	PSK      string `yaml:"psk"`
	Insecure bool   `yaml:"insecure"`
	Pacing   Pacing `yaml:"pacing"`
}

// Client is the segment-client configuration.
type Client struct {
	Server      string `yaml:"server"`
	SNI         string `yaml:"sni"`
	PSK         string `yaml:"psk"`
	SOCKS       string `yaml:"socks"`
	CredFile    string `yaml:"cred_file"`
	Fingerprint string `yaml:"tls_fingerprint"` // chrome (default) | go
	Insecure    bool   `yaml:"insecure"`
	CAFile      string `yaml:"ca_file"`
}

// Load reads a YAML file into v. Missing file is an error only when
// required is set.
func Load(path string, v any, required bool) error {
	if path == "" {
		if required {
			return errors.New("config: no config file given")
		}
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return nil
		}
		return fmt.Errorf("config: %w", err)
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// ValidateServer sanity-checks a server config.
func ValidateServer(c *Server) error {
	if len(c.PSK) < 32 {
		return errors.New("config: psk must be at least 32 bytes")
	}
	if !c.Insecure && (c.Cert == "" || c.Key == "") {
		return errors.New("config: cert and key are required unless insecure")
	}
	return nil
}

// ValidateClient sanity-checks a client config.
func ValidateClient(c *Client) error {
	if c.Server == "" {
		return errors.New("config: server is required")
	}
	if len(c.PSK) < 32 {
		return errors.New("config: psk must be at least 32 bytes")
	}
	return nil
}

// TicketTTL is the server-side session ticket lifetime used by the
// CLI defaults.
const TicketTTL = 24 * time.Hour
