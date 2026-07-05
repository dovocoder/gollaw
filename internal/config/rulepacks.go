package config

// rulePackRef references a rule pack from config.
type rulePackRef struct {
	Name      string
	Enabled   bool
	Overrides map[string]int
}
