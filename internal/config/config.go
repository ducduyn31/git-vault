// Package config reads and writes git-vault's repo-tracked settings file
// (.git-vault.yaml). It holds only non-secret settings — actual key or
// session material always lives in internal/session's cache, never here.
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultFileName is the repo-relative path git-vault's settings file is
// conventionally stored at.
const DefaultFileName = ".git-vault.yaml"

// Config holds git-vault's non-secret, repo-tracked settings.
type Config struct {
	Provider  string `yaml:"provider"`
	IssuerURL string `yaml:"issuer_url,omitempty"`
	ClientID  string `yaml:"client_id,omitempty"`
}

// Load reads and parses the config file at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Save writes c to path.
func Save(path string, c Config) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
