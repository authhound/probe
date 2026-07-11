// Package config handles the on-disk probe config. Its defining rule: secrets
// and credentials live ONLY here, on the probe host, and are never placed in a
// check Result — so nothing sensitive is ever printed or (in premium) uploaded.
package config

import (
	"encoding/json"
	"os"
)

// Config is written by `authhound-probe connect` and read by scheduled runs.
// In v1 (one-shot `test`), everything comes from flags and this file is optional.
type Config struct {
	// Cloud is populated only after `connect`. When empty, the probe runs in
	// standalone mode: local plan, terminal output, nothing leaves the host.
	Cloud *CloudConfig `json:"cloud,omitempty"`

	// Targets can be predefined so scheduled runs know what to test. Secrets
	// stay in this file on the probe and are never uploaded.
	Targets []TargetConfig `json:"targets,omitempty"`
}

// CloudConfig is the premium seam. Presence of a token flips the probe from
// standalone to connected: a cloud PlanSource + CloudSink + scheduler. v1 does
// not act on it beyond storing it, so `connect` is forward-compatible.
type CloudConfig struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}

type TargetConfig struct {
	Name          string `json:"name"`
	Address       string `json:"address"`
	Secret        string `json:"secret"`
	NASIdentifier string `json:"nas_identifier,omitempty"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the config with owner-only permissions, since it holds secrets.
func Save(path string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
