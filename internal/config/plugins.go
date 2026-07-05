package config

import (
	"fmt"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
)

// PluginConfig configures an external plugin.
type PluginConfig struct {
	Name    string
	Path    string
	Enabled bool
	Config map[string]interface{}
}

// LoadPlugins loads plugin configuration from .gollaw.yaml.
func LoadPlugins(configPath string) ([]PluginConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Plugins []PluginConfig `yaml:"plugins"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return raw.Plugins, nil
}

// ValidatePlugin checks that a plugin path exists and is executable.
func ValidatePlugin(p PluginConfig) error {
	if p.Name == "" {
		return fmt.Errorf("plugin name is required")
	}
	if p.Path == "" {
		return fmt.Errorf("plugin %q: path is required", p.Name)
	}
	info, err := os.Stat(p.Path)
	if err != nil {
		return fmt.Errorf("plugin %q: path does not exist: %w", p.Name, err)
	}
	if info.IsDir() {
		return fmt.Errorf("plugin %q: path is a directory, not a file", p.Name)
	}
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("plugin %q: not executable", p.Name)
	}
	return nil
}

// IsPluginAvailable checks if a plugin binary is available on PATH.
func IsPluginAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
