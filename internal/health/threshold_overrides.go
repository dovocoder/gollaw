package health

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ThresholdOverride holds per-package threshold overrides.
type ThresholdOverride struct {
	Package         string `yaml:"package"         json:"package"`
	MaxCyclomatic   int    `yaml:"max-cyclomatic"  json:"maxCyclomatic"`
	MaxCognitive    int    `yaml:"max-cognitive"   json:"maxCognitive"`
	MaxFunctionLines int   `yaml:"max-function-lines" json:"maxFunctionLines"`
	MinDupLines     int    `yaml:"min-dup-lines"   json:"minDupLines"`
}

// ThresholdConfig holds all threshold configuration including per-package overrides.
type ThresholdConfig struct {
	Overrides             []ThresholdOverride `yaml:"overrides" json:"overrides"`
	DefaultMaxCyclomatic  int                 `yaml:"default-max-cyclomatic" json:"defaultMaxCyclomatic"`
	DefaultMaxCognitive   int                 `yaml:"default-max-cognitive" json:"defaultMaxCognitive"`
	DefaultMaxFunctionLines int               `yaml:"default-max-function-lines" json:"defaultMaxFunctionLines"`
	DefaultMinDupLines    int                 `yaml:"default-min-dup-lines" json:"defaultMinDupLines"`
}

// thresholdsFile is the YAML structure for the thresholds section of .gollaw.yaml.
type thresholdsFile struct {
	Thresholds ThresholdConfig `yaml:"thresholds"`
}

// DefaultThresholdConfig returns sensible default thresholds.
func DefaultThresholdConfig() *ThresholdConfig {
	return &ThresholdConfig{
		Overrides:               nil,
		DefaultMaxCyclomatic:    15,
		DefaultMaxCognitive:     20,
		DefaultMaxFunctionLines: 50,
		DefaultMinDupLines:      6,
	}
}

// LoadThresholds reads threshold configuration from a .gollaw.yaml file.
// If the file doesn't exist or has no thresholds section, defaults are returned.
func LoadThresholds(configPath string) (*ThresholdConfig, error) {
	if configPath == "" {
		return DefaultThresholdConfig(), nil
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultThresholdConfig(), nil
		}
		return nil, fmt.Errorf("read config %s: %w", configPath, err)
	}

	var tf thresholdsFile
	if err := yaml.Unmarshal(raw, &tf); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", configPath, err)
	}

	cfg := tf.Thresholds

	// Apply defaults for zero values
	d := DefaultThresholdConfig()
	if cfg.DefaultMaxCyclomatic == 0 {
		cfg.DefaultMaxCyclomatic = d.DefaultMaxCyclomatic
	}
	if cfg.DefaultMaxCognitive == 0 {
		cfg.DefaultMaxCognitive = d.DefaultMaxCognitive
	}
	if cfg.DefaultMaxFunctionLines == 0 {
		cfg.DefaultMaxFunctionLines = d.DefaultMaxFunctionLines
	}
	if cfg.DefaultMinDupLines == 0 {
		cfg.DefaultMinDupLines = d.DefaultMinDupLines
	}

	return &cfg, nil
}

// GetThreshold returns the threshold value for a given package and kind.
// kind is one of: "max-cyclomatic", "max-cognitive", "max-function-lines", "min-dup-lines".
// If a per-package override exists, it's used; otherwise the default is returned.
func GetThreshold(t *ThresholdConfig, pkgPath string, kind string) int {
	if t == nil {
		return 0
	}

	// Check for per-package override
	for _, o := range t.Overrides {
		if matchPackage(o.Package, pkgPath) {
			return thresholdFromOverride(&o, kind)
		}
	}

	// Fall back to default
	return thresholdFromDefault(t, kind)
}

// matchPackage checks if an override package pattern matches a package path.
// Supports prefix matching (e.g. "internal/api" matches "internal/api/v2").
func matchPackage(pattern, pkgPath string) bool {
	if pattern == pkgPath {
		return true
	}
	// Prefix match with package boundary
	if strings.HasPrefix(pkgPath, pattern+"/") {
		return true
	}
	return false
}

func thresholdFromOverride(o *ThresholdOverride, kind string) int {
	switch kind {
	case "max-cyclomatic":
		if o.MaxCyclomatic > 0 {
			return o.MaxCyclomatic
		}
	case "max-cognitive":
		if o.MaxCognitive > 0 {
			return o.MaxCognitive
		}
	case "max-function-lines":
		if o.MaxFunctionLines > 0 {
			return o.MaxFunctionLines
		}
	case "min-dup-lines":
		if o.MinDupLines > 0 {
			return o.MinDupLines
		}
	}
	// Fall back to 0 — caller should handle with default
	return 0
}

func thresholdFromDefault(t *ThresholdConfig, kind string) int {
	switch kind {
	case "max-cyclomatic":
		return t.DefaultMaxCyclomatic
	case "max-cognitive":
		return t.DefaultMaxCognitive
	case "max-function-lines":
		return t.DefaultMaxFunctionLines
	case "min-dup-lines":
		return t.DefaultMinDupLines
	default:
		return 0
	}
}

// ValidateThresholds checks the threshold configuration and returns a list of
// warning strings for any invalid thresholds.
func ValidateThresholds(t *ThresholdConfig) []string {
	var warnings []string

	if t == nil {
		return warnings
	}

	// Validate defaults
	if t.DefaultMaxCyclomatic < 1 {
		warnings = append(warnings, "default max-cyclomatic is < 1, should be at least 1")
	}
	if t.DefaultMaxCognitive < 1 {
		warnings = append(warnings, "default max-cognitive is < 1, should be at least 1")
	}
	if t.DefaultMaxFunctionLines < 1 {
		warnings = append(warnings, "default max-function-lines is < 1, should be at least 1")
	}
	if t.DefaultMinDupLines < 1 {
		warnings = append(warnings, "default min-dup-lines is < 1, should be at least 1")
	}

	// Validate overrides
	for i, o := range t.Overrides {
		if o.Package == "" {
			warnings = append(warnings, fmt.Sprintf("override at index %d has empty package name", i))
		}
		if o.MaxCyclomatic < 0 {
			warnings = append(warnings, fmt.Sprintf("override for %s: max-cyclomatic is < 0", o.Package))
		}
		if o.MaxCognitive < 0 {
			warnings = append(warnings, fmt.Sprintf("override for %s: max-cognitive is < 0", o.Package))
		}
		if o.MaxFunctionLines < 0 {
			warnings = append(warnings, fmt.Sprintf("override for %s: max-function-lines is < 0", o.Package))
		}
		if o.MinDupLines < 0 {
			warnings = append(warnings, fmt.Sprintf("override for %s: min-dup-lines is < 0", o.Package))
		}
		// Check that at least one threshold is set
		if o.MaxCyclomatic == 0 && o.MaxCognitive == 0 && o.MaxFunctionLines == 0 && o.MinDupLines == 0 {
			warnings = append(warnings, fmt.Sprintf("override for %s: no thresholds set (all zero)", o.Package))
		}
	}

	return warnings
}
