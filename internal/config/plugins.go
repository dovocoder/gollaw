package config

// pluginConfig configures an external plugin.
type pluginConfig struct {
	Name    string
	Path    string
	Enabled bool
	Config  map[string]interface{}
}
