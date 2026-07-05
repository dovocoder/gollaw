package analyzer

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
)

// dupBlock is a code block with its structural hash.
type dupBlock struct {
	file    string
	line    int
	endLine int
	decl    string
}

// duplicationAnalyzer finds duplicate code blocks using AST structural
// fingerprinting.
type duplicationAnalyzer struct{}

func newDuplicationAnalyzer() *duplicationAnalyzer { return &duplicationAnalyzer{} }

func (a *duplicationAnalyzer) Name() string        { return "duplication" }
func (a *duplicationAnalyzer) Category() Category  { return CategoryDuplication }
func (a *duplicationAnalyzer) Description() string { return "Duplicate code blocks via AST structural hashing" }

func (a *duplicationAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	minLines := ctx.Config.MinDupLines
	if minLines == 0 {
		minLines = 6
	}

	blocksByHash := a.collectBlocks(ctx, minLines)
	dupFindings := a.findDuplicates(blocksByHash)
	return a.createDuplicationFindings(dupFindings), nil
}

// collectBlocks gathers all statement blocks and their structural hashes,
// including function-body-level and sliding-window-level blocks.
func (a *duplicationAnalyzer) collectBlocks(ctx *Context, minLines int) map[string][]dupBlock {
	blocksByHash := make(map[string][]dupBlock)
	a.collectFunctionBodyBlocks(ctx, minLines, blocksByHash)
	a.collectStatementWindowBlocks(ctx, minLines, blocksByHash)
	return blocksByHash
}

// collectFunctionBodyBlocks hashes entire function bodies for duplication.
func (a *duplicationAnalyzer) collectFunctionBodyBlocks(ctx *Context, minLines int, blocksByHash map[string][]dupBlock) {
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				bodyHash, stmtCount := hashBlock(fn.Body)
				if stmtCount < minLines {
					continue
				}
				start := ctx.FSET.Position(fn.Body.Pos())
				end := ctx.FSET.Position(fn.Body.End())
				b := dupBlock{
					file:    start.Filename,
					line:    start.Line,
					endLine: end.Line,
					decl:    funcLabel(fn),
				}
				blocksByHash[bodyHash] = append(blocksByHash[bodyHash], b)
			}
		}
	}
}

// collectStatementWindowBlocks uses a sliding window over statements to
// find smaller duplications.
func (a *duplicationAnalyzer) collectStatementWindowBlocks(ctx *Context, minLines int, blocksByHash map[string][]dupBlock) {
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				collectStatementRuns(ctx.FSET, fn, minLines, blocksByHash)
			}
		}
	}
}

// findDuplicates identifies hashes with more than one block and returns
// the duplicate pairs (original + duplicate).
func (a *duplicationAnalyzer) findDuplicates(blocksByHash map[string][]dupBlock) []dupPair {
	var pairs []dupPair
	seen := make(map[string]bool) // dedup by file:line pairs

	for hash, blocks := range blocksByHash {
		if len(blocks) < 2 {
			continue
		}
		// Sort by file:line.
		sort.Slice(blocks, func(i, j int) bool {
			if blocks[i].file != blocks[j].file {
				return blocks[i].file < blocks[j].file
			}
			return blocks[i].line < blocks[j].line
		})

		// Report the first occurrence as the "original" and subsequent as duplicates.
		orig := blocks[0]
		for _, dup := range blocks[1:] {
			dedupKey := fmt.Sprintf("%s:%d-%s:%d", orig.file, orig.line, dup.file, dup.line)
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true
			pairs = append(pairs, dupPair{orig: orig, dup: dup, hash: hash})
		}
	}
	return pairs
}

// dupPair holds a duplicate block and its original.
type dupPair struct {
	orig dupBlock
	dup  dupBlock
	hash string
}

// createDuplicationFindings converts duplicate pairs into Finding objects,
// sorted by file:line.
func (a *duplicationAnalyzer) createDuplicationFindings(pairs []dupPair) []Finding {
	var findings []Finding
	for _, p := range pairs {
		dup := p.dup
		orig := p.orig
		hash := p.hash
		findings = append(findings, Finding{
			Analyzer:  a.Name(),
			Category:  a.Category(),
			Severity:  SeverityWarning,
			Message:    fmt.Sprintf("duplicate code block (%d lines) in %s", dup.endLine-dup.line+1, dup.decl),
			Detail:     fmt.Sprintf("first occurrence: %s:%d (hash: %s)", orig.file, orig.line, hash[:12]),
			File:       dup.file,
			Line:       dup.line,
			EndLine:    dup.endLine,
			RuleID:     "GLW-DP001",
			Suggestion: "Extract the duplicated logic into a shared helper function.",
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	return findings
}

// hashBlock produces a structural hash of an ast.BlockStmt.
func hashBlock(block *ast.BlockStmt) (string, int) {
	var buf bytes.Buffer
	stmtCount := 0
	for _, stmt := range block.List {
		fmt.Fprintf(&buf, "%T|", stmt)
		stmtCount++
		// Add structural info for key statement types.
		ast.Inspect(stmt, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch n := n.(type) {
			case *ast.CallExpr:
				if ident, ok := n.Fun.(*ast.Ident); ok {
					fmt.Fprintf(&buf, "call:%s|", ident.Name)
				} else if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						fmt.Fprintf(&buf, "call:%s.%s|", ident.Name, sel.Sel.Name)
					} else {
						fmt.Fprintf(&buf, "call:.%s|", sel.Sel.Name)
					}
				}
			case *ast.AssignStmt:
				fmt.Fprintf(&buf, "assign:%d|", len(n.Lhs))
			case *ast.IfStmt:
				fmt.Fprintf(&buf, "if|")
			case *ast.ForStmt:
				fmt.Fprintf(&buf, "for|")
			case *ast.RangeStmt:
				fmt.Fprintf(&buf, "range|")
			case *ast.ReturnStmt:
				fmt.Fprintf(&buf, "return:%d|", len(n.Results))
			case *ast.BinaryExpr:
				fmt.Fprintf(&buf, "binop:%s|", n.Op)
			}
			return true
		})
	}
	h := sha256.Sum256(buf.Bytes())
	return fmt.Sprintf("%x", h), stmtCount
}

// hashStatements hashes a slice of statements.
func hashStatements(stmts []ast.Stmt) string {
	var buf bytes.Buffer
	for _, stmt := range stmts {
		fmt.Fprintf(&buf, "%T|", stmt)
		ast.Inspect(stmt, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch n := n.(type) {
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					fmt.Fprintf(&buf, "call.%s|", sel.Sel.Name)
				} else if ident, ok := n.Fun.(*ast.Ident); ok {
					fmt.Fprintf(&buf, "call.%s|", ident.Name)
				}
			case *ast.Ident:
				fmt.Fprintf(&buf, "id.%s|", n.Name)
			case *ast.BinaryExpr:
				fmt.Fprintf(&buf, "op.%s|", n.Op)
			}
			return true
		})
	}
	h := sha256.Sum256(buf.Bytes())
	return fmt.Sprintf("%x", h)
}

// collectStatementRuns uses a sliding window of N consecutive statements
// to find smaller duplications.
func collectStatementRuns(fset *token.FileSet, fn *ast.FuncDecl, minLines int, blocksByHash map[string][]dupBlock) {
	stmts := fn.Body.List
	windowSize := 4 // statements per window

	for i := 0; i+windowSize <= len(stmts); i++ {
		run := stmts[i : i+windowSize]
		start := fset.Position(run[0].Pos())
		end := fset.Position(run[windowSize-1].End())
		if end.Line-start.Line+1 < minLines {
			continue
		}

		h := hashStatements(run)
		blocksByHash[h] = append(blocksByHash[h], dupBlock{
			file:    start.Filename,
			line:    start.Line,
			endLine: end.Line,
			decl:    funcLabel(fn),
		})
	}
}

var _ = strings.TrimSpace
