package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestFeatureFlagsAnalyzerIgnoresBuildTagMentionsInBodyComments(t *testing.T) {
	findings := analyzeFeatureFlagsSource(t, `package sample

// shouldCheckFile explains //go:build handling without being a build tag.
func shouldCheckFile(path string) bool {
	return true
}
`)

	assertFeatureFlagsRuleCount(t, findings, "GLW-FF001", 0)
}

func TestFeatureFlagsAnalyzerFlagsLeadingBuildTag(t *testing.T) {
	findings := analyzeFeatureFlagsSource(t, `//go:build integration

package sample

func guarded() {}
`)

	assertFeatureFlagsRuleCount(t, findings, "GLW-FF001", 1)
}

func analyzeFeatureFlagsSource(t *testing.T, src string) []Finding {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse source: %v", err)
	}
	ctx := &Context{
		FSET:        fset,
		SyntaxByPkg: map[string][]*ast.File{"sample": {file}},
	}
	findings, err := newFeatureFlagsAnalyzer().Analyze(ctx)
	if err != nil {
		t.Fatalf("analyze feature flags: %v", err)
	}
	return findings
}

func assertFeatureFlagsRuleCount(t *testing.T, findings []Finding, ruleID string, want int) {
	t.Helper()

	got := 0
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			got++
		}
	}
	if got != want {
		t.Fatalf("rule %s findings = %d, want %d; findings=%+v", ruleID, got, want, findings)
	}
}
