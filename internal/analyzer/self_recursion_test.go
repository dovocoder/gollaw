package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestSelfRecursionAnalyzerFlagsImmediateReceiverRecursion(t *testing.T) {
	findings := analyzeSelfRecursionSource(t, `package sample

type Client struct{}

func (c *Client) connectedClient() error {
	err := c.connectedClient()
	return err
}
`)

	assertSelfRecursionRuleCount(t, findings, "GLW-SR001", 1)
}

func TestSelfRecursionAnalyzerAllowsGuardedRecursiveWalk(t *testing.T) {
	findings := analyzeSelfRecursionSource(t, `package sample

type Node struct{ Children []*Node }

func walk(n *Node) int {
	if n == nil {
		return 0
	}
	total := 1
	for _, child := range n.Children {
		total += walk(child)
	}
	return total
}
`)

	assertSelfRecursionRuleCount(t, findings, "GLW-SR001", 0)
}

func assertSelfRecursionRuleCount(t *testing.T, findings []Finding, ruleID string, want int) {
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

func analyzeSelfRecursionSource(t *testing.T, src string) []Finding {
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
	findings, err := newSelfRecursionAnalyzer().Analyze(ctx)
	if err != nil {
		t.Fatalf("analyze self recursion: %v", err)
	}
	return findings
}
