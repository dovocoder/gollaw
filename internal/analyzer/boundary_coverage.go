package analyzer

// boundaryCoverageAnalyzer finds packages not covered by any architecture rule.
type boundaryCoverageAnalyzer struct{}

func newBoundaryCoverageAnalyzer() *boundaryCoverageAnalyzer { return &boundaryCoverageAnalyzer{} }

func (a *boundaryCoverageAnalyzer) Name() string        { return "boundary-coverage" }
func (a *boundaryCoverageAnalyzer) Category() Category    { return CategoryArchitecture }
func (a *boundaryCoverageAnalyzer) Description() string     { return "Finds packages not covered by any architecture rule" }

func (a *boundaryCoverageAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	if len(ctx.Config.Rules) == 0 {
		return nil, nil
	}
	var findings []Finding
	for pkgPath := range ctx.TypesByPkg {
		covered := false
		for _, rule := range ctx.Config.Rules {
			if pkgHasSuffix(pkgPath, rule.Package) || pkgHasSuffix(pkgPath, rule.MustNotUse) {
				covered = true
				break
			}
		}
		if !covered {
			findings = append(findings, Finding{
				Analyzer:  a.Name(),
				Category:  CategoryArchitecture,
				Severity:  SeverityInfo,
				Message:    "package not covered by any architecture rule",
				Detail:     "Package " + pkgPath + " is not mentioned in any architecture rule. Consider adding it to a zone or adding a rule.",
				File:       pkgPath,
				Line:       1,
				Suggestion: "Add a rule involving this package, or explicitly mark it as uncovered",
				RuleID:     "GLW-BC001",
			})
		}
	}
	return findings, nil
}
