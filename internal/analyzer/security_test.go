package analyzer

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestSecurityAnalyzerFlagsDynamicSQLAtDatabaseCall(t *testing.T) {
	findings := analyzeSecuritySource(t, `package sample

type DB struct{}
func (d *DB) Query(query string, args ...any) {}

func tableColumns(db *DB, table string) {
	db.Query("PRAGMA table_info(" + table + ")")
}
`)

	assertSecurityRuleCount(t, findings, "GLW-SC030", 1)
}

func TestSecurityAnalyzerAllowsConstantSQLComposition(t *testing.T) {
	findings := analyzeSecuritySource(t, `package sample

type DB struct{}
func (d *DB) Exec(query string, args ...any) {}

const staleRowsSQL = "SELECT id FROM rows WHERE ts < ?"

func deleteRows(db *DB, cutoff int64) {
	db.Exec("DELETE FROM rows WHERE id IN (" + staleRowsSQL + ")", cutoff)
}
`)

	assertSecurityRuleCount(t, findings, "GLW-SC030", 0)
}

func TestSecurityAnalyzerIgnoresSQLTextInErrorFormatting(t *testing.T) {
	findings := analyzeSecuritySource(t, `package sample

import "fmt"

func problem(table string) error {
	return fmt.Errorf("SELECT from %s failed", table)
}
`)

	assertSecurityRuleCount(t, findings, "GLW-SC030", 0)
}

func analyzeSecuritySource(t *testing.T, src string) []Finding {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse source: %v", err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{Importer: importer.Default()}
	pkgTypes, err := conf.Check("sample", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("type-check source: %v", err)
	}
	ctx := &Context{
		FSET: fset,
		Packages: []*packages.Package{
			{
				PkgPath:   "sample",
				Types:     pkgTypes,
				TypesInfo: info,
				Syntax:    []*ast.File{file},
			},
		},
		SyntaxByPkg: map[string][]*ast.File{"sample": {file}},
	}
	findings, err := newSecurityAnalyzer().Analyze(ctx)
	if err != nil {
		t.Fatalf("analyze security: %v", err)
	}
	return findings
}

func assertSecurityRuleCount(t *testing.T, findings []Finding, ruleID string, want int) {
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
