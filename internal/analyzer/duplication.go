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
	hash    string
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

	// Collect all statement blocks and their structural hash.
	blocksByHash := make(map[string][]dupBlock)

	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				// Hash each maximal run of consecutive statements.
				stmts := fn.Body.List
				for i := 0; i < len(stmts); i++ {
					for j := i + 1; j <= len(stmts); j++ {
						run := stmts[i:j]
						startPos := ctx.FSET.Position(run[0].Pos())
						endPos := ctx.FSET.Position(run[len(run)-1].End())
						lineCount := endPos.Line - startPos.Line + 1
						if lineCount < minLines {
							continue
						}

						h := hashStatements(run)
						// Only keep the first (longest) run per starting position
						// to avoid O(n^3) explosion. We use a window approach:
						// expand as long as the hash matches.
						_ = h
						break // move to next start
					}
				}

				// Simpler: hash the entire function body and compare.
				bodyHash, stmtCount := hashBlock(fn.Body)
				if stmtCount < minLines {
					continue
				}
				start := ctx.FSET.Position(fn.Body.Pos())
				end := ctx.FSET.Position(fn.Body.End())
				b := dupBlock{
					hash:    bodyHash,
					file:    start.Filename,
					line:    start.Line,
					endLine: end.Line,
					decl:    funcLabel(fn),
				}
				blocksByHash[bodyHash] = append(blocksByHash[bodyHash], b)
			}
		}
	}

	// Also collect smaller statement-level duplication via a sliding window.
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

	// Find hashes with >1 block (duplicates).
	var findings []Finding
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
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	return findings, nil
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
			hash:    h,
			file:    start.Filename,
			line:    start.Line,
			endLine: end.Line,
			decl:    funcLabel(fn),
		})
	}
}

var _ = strings.TrimSpace
