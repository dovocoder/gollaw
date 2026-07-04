package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
)

// Severity describes how impactful a finding is.
type Severity string

const (
	SeverityCritical Severity = "critical" // will break something or is a security risk
	SeverityWarning  Severity = "warning"  // should be fixed, code smell
	SeverityInfo     Severity = "info"     // informational, not actionable
	SeverityHint     Severity = "hint"     // style / minor improvement
)

// Category groups findings by the kind of issue.
type Category string

const (
	CategoryDeadCode      Category = "dead-code"
	CategoryUnused        Category = "unused"
	CategoryComplexity    Category = "complexity"
	CategoryDuplication   Category = "duplication"
	CategoryDependencies  Category = "dependencies"
	CategoryArchitecture  Category = "architecture"
	CategoryCodeSmell     Category = "code-smell"
)

// Finding is a single issue discovered by an analyzer.
type Finding struct {
	Analyzer   string   `json:"analyzer"`
	Category   Category `json:"category"`
	Severity   Severity `json:"severity"`
	Message    string   `json:"message"`
	Detail     string   `json:"detail,omitempty"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	EndLine    int      `json:"endLine,omitempty"`
	Column     int      `json:"column,omitempty"`
	Suggestion string   `json:"suggestion,omitempty"`
	RuleID     string   `json:"ruleId"`
}

// Position holds a source position.
type Position struct {
	Filename string
	Offset   int
	Line     int
	Column   int
}

// NodeInfo extracts position info from an ast.Node.
func NodeInfo(fset *token.FileSet, node ast.Node) (file string, line, endLine int) {
	start := fset.Position(node.Pos())
	end := fset.Position(node.End())
	file = start.Filename
	line = start.Line
	endLine = end.Line
	return
}

// ObjectInfo extracts position info from a types.Object.
func ObjectInfo(fset *token.FileSet, obj types.Object) (file string, line int) {
	pos := fset.Position(obj.Pos())
	return pos.Filename, pos.Line
}
