package suppress

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// Suppressions holds all parsed suppression directives from source comments.
type Suppressions struct {
	//gollaw:keep
	// fileIgnoreAll maps file paths that have a //gollaw:ignore-all comment.
	fileIgnoreAll map[string]bool

	//gollaw:keep
	// declIgores maps file → line → analyzer name → true.
	// The line is the line of the declaration the suppression applies to.
	declIgnores map[string]map[int]map[string]bool

	//gollaw:keep
	// entries records every suppression comment found, for staleness checking.
	entries []SuppressionEntry
}

// SuppressionEntry records a single suppression comment and its metadata.
//gollaw:keep
type SuppressionEntry struct {
	File     string
	Line     int // line of the comment
	DeclLine int // line of the declaration it applies to (0 for file-level)
	Type     string // "keep", "ignore", "ignore-all"
	Analyzer string // analyzer name for "ignore" type, empty otherwise
	Text     string // original comment text
}

// StaleSuppression represents a suppression that no longer matches any finding.
//gollaw:keep
type StaleSuppression struct {
	File     string
	Line     int
	DeclLine int
	Type     string
	Analyzer string
	Message  string
}

const (
	prefixKeep       = "//gollaw:keep"
	prefixIgnore     = "//gollaw:ignore"
	prefixIgnoreAll  = "//gollaw:ignore-all"
)

// ParseSuppressions scans all files for gollaw suppression comments and
// returns a Suppressions value.
func ParseSuppressions(fset *token.FileSet, files []*ast.File) (*Suppressions, error) {
	sup := &Suppressions{
		fileIgnoreAll: make(map[string]bool),
		declIgnores:   make(map[string]map[int]map[string]bool),
	}

	for _, file := range files {
		fileName := fset.Position(file.Pos()).Filename
		if fileName == "" {
			continue
		}

		// Build a map of comment line → comment group for quick lookup.
		commentByLine := make(map[int]*ast.CommentGroup)
		for _, cg := range file.Comments {
			pos := fset.Position(cg.Pos())
			commentByLine[pos.Line] = cg
		}

		// Process comments for file-level ignore-all.
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				text := strings.TrimSpace(c.Text)
				if text == prefixIgnoreAll {
					fileName := fset.Position(c.Pos()).Filename
					sup.fileIgnoreAll[fileName] = true
					pos := fset.Position(c.Pos())
					sup.entries = append(sup.entries, SuppressionEntry{
						File:     fileName,
						Line:     pos.Line,
						DeclLine: 0,
						Type:     "ignore-all",
						Text:     text,
					})
				}
			}
		}

		// Walk declarations to find suppression comments above them.
		ast.Inspect(file, func(n ast.Node) bool {
			switch decl := n.(type) {
			case *ast.GenDecl:
				// For gen declarations (var, const, type), check doc comment
				if decl.Doc != nil {
					sup.parseDeclComment(fset, decl.Doc, decl.Pos())
				}
				// Also check individual specs
				for _, spec := range decl.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok && vs.Doc != nil {
						sup.parseDeclComment(fset, vs.Doc, vs.Pos())
					}
					if ts, ok := spec.(*ast.TypeSpec); ok && ts.Doc != nil {
						sup.parseDeclComment(fset, ts.Doc, ts.Pos())
					}
				}
			case *ast.FuncDecl:
				if decl.Doc != nil {
					sup.parseDeclComment(fset, decl.Doc, decl.Pos())
				}
			}
			return true
		})

		// Also scan for inline suppression comments on the same line as a declaration.
		// These apply to the declaration on the next line or same line.
		ast.Inspect(file, func(n ast.Node) bool {
			switch decl := n.(type) {
			case *ast.FuncDecl:
				sup.checkInlineComment(fset, file, decl.Pos(), commentByLine)
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					sup.checkInlineComment(fset, file, spec.Pos(), commentByLine)
				}
			}
			return true
		})
	}

	return sup, nil
}

// Entries returns all parsed suppression entries.
func (s *Suppressions) Entries() []SuppressionEntry {
	if s == nil {
		return nil
	}
	return s.entries
}

// parseDeclComment checks a doc comment block for suppression directives
// and records them for the declaration at declPos.
func (s *Suppressions) parseDeclComment(fset *token.FileSet, doc *ast.CommentGroup, declPos token.Pos) {
	declFile := fset.Position(declPos).Filename
	declLine := fset.Position(declPos).Line

	for _, c := range doc.List {
		text := strings.TrimSpace(c.Text)
		s.parseSuppressionText(text, declFile, declLine, fset.Position(c.Pos()).Line)
	}
}

// checkInlineComment checks if there's a suppression comment on the line
// before a declaration (looking back from commentByLine).
func (s *Suppressions) checkInlineComment(fset *token.FileSet, file *ast.File, declPos token.Pos, commentByLine map[int]*ast.CommentGroup) {
	declFile := fset.Position(declPos).Filename
	declLine := fset.Position(declPos).Line

	// Check the line directly above the declaration.
	if cg, ok := commentByLine[declLine-1]; ok {
		for _, c := range cg.List {
			text := strings.TrimSpace(c.Text)
			s.parseSuppressionText(text, declFile, declLine, fset.Position(c.Pos()).Line)
		}
	}
}

// parseSuppressionText parses a single comment text and records the suppression.
func (s *Suppressions) parseSuppressionText(text, fileName string, declLine, commentLine int) {
	switch {
	case text == prefixKeep:
		s.addDeclIgnore(fileName, declLine, "deadcode")
		s.addDeclIgnore(fileName, declLine, "unused")
		s.entries = append(s.entries, SuppressionEntry{
			File:     fileName,
			Line:     commentLine,
			DeclLine: declLine,
			Type:     "keep",
			Analyzer: "",
			Text:     text,
		})
	case text == prefixIgnoreAll:
		// Already handled at file level
	case strings.HasPrefix(text, prefixIgnore+" "):
		analyzerName := strings.TrimSpace(strings.TrimPrefix(text, prefixIgnore+" "))
		if analyzerName != "" {
			s.addDeclIgnore(fileName, declLine, analyzerName)
			s.entries = append(s.entries, SuppressionEntry{
				File:     fileName,
				Line:     commentLine,
				DeclLine: declLine,
				Type:     "ignore",
				Analyzer: analyzerName,
				Text:     text,
			})
		}
	}
}

// addDeclIgnore records that a declaration at the given line should have
// findings from the named analyzer suppressed.
func (s *Suppressions) addDeclIgnore(fileName string, declLine int, analyzerName string) {
	if s.declIgnores[fileName] == nil {
		s.declIgnores[fileName] = make(map[int]map[string]bool)
	}
	if s.declIgnores[fileName][declLine] == nil {
		s.declIgnores[fileName][declLine] = make(map[string]bool)
	}
	s.declIgnores[fileName][declLine][analyzerName] = true
}

// IsSuppressed checks whether a finding is suppressed by any directive.
//gollaw:keep
func IsSuppressed(f analyzer.Finding, sup *Suppressions) bool {
	if sup == nil {
		return false
	}

	// File-level ignore-all.
	if sup.fileIgnoreAll[f.File] {
		return true
	}

	// Per-declaration ignores: check the finding's line and surrounding lines
	// (the finding line might be within the declaration, not at its start).
	if fileMap, ok := sup.declIgnores[f.File]; ok {
		for declLine, analyzers := range fileMap {
			if matchesDecl(f.Line, declLine) {
				// "keep" suppresses ALL analyzers for this declaration
				if analyzers["deadcode"] {
					return true
				}
				if analyzers[f.Analyzer] {
					return true
				}
			}
		}
	}

	return false
}

// matchesDecl checks if a finding line falls within the declaration at declLine.
// Since we don't track declaration end lines in suppressions, we use a proximity
// heuristic: the finding line must be >= declLine (findings are within or
// after the declaration start).
func matchesDecl(findingLine, declLine int) bool {
	// The finding is at or after the declaration line, within a reasonable range.
	// For functions, findings can span many lines. We accept any line >= declLine
	// since the suppression is tied to the declaration.
	return findingLine >= declLine
}

// FilterSuppressed returns only the findings that are NOT suppressed.
func FilterSuppressed(findings []analyzer.Finding, sup *Suppressions) []analyzer.Finding {
	if sup == nil {
		return findings
	}
	result := make([]analyzer.Finding, 0, len(findings))
	for _, f := range findings {
		if !IsSuppressed(f, sup) {
			result = append(result, f)
		}
	}
	return result
}

// FindStale returns suppressions that no longer match any finding.
// A suppression is stale if no finding exists at its target location
// for the suppressed analyzer.
func FindStale(findings []analyzer.Finding, sup *Suppressions) []StaleSuppression {
	if sup == nil || len(sup.entries) == 0 {
		return nil
	}

	// Build a quick lookup: (file, line) → set of analyzers with findings.
	type findingKey struct {
		file     string
		line     int
		analyzer string
	}
	findingSet := make(map[findingKey]bool)
	for _, f := range findings {
		// For per-declaration suppressions, match against the decl line.
		// Since findings report their own line (which may differ from the decl
		// line), we check all entries for the same file.
		findingSet[findingKey{f.File, f.Line, f.Analyzer}] = true
	}

	var stale []StaleSuppression
	for _, entry := range sup.entries {
		if entry.Type == "ignore-all" {
			// File-level: stale if the file has no findings at all.
			hasFinding := false
			for _, f := range findings {
				if f.File == entry.File {
					hasFinding = true
					break
				}
			}
			if !hasFinding {
				stale = append(stale, StaleSuppression{
					File:     entry.File,
					Line:     entry.Line,
					DeclLine: 0,
					Type:     entry.Type,
					Message:  fmt.Sprintf("file-level ignore-all at %s:%d has no findings to suppress", entry.File, entry.Line),
				})
			}
			continue
		}

		// Per-declaration: check if any finding matches.
		matched := false
		for _, f := range findings {
			if f.File != entry.File {
				continue
			}
			if !matchesDecl(f.Line, entry.DeclLine) {
				continue
			}
			if entry.Type == "keep" {
				// "keep" suppresses deadcode and unused
				if f.Analyzer == "deadcode" || f.Analyzer == "unused" {
					matched = true
					break
				}
			} else if entry.Type == "ignore" {
				if f.Analyzer == entry.Analyzer {
					matched = true
					break
				}
			}
		}

		if !matched {
			msg := fmt.Sprintf("suppression at %s:%d (type=%s", entry.File, entry.Line, entry.Type)
			if entry.Analyzer != "" {
				msg += fmt.Sprintf(", analyzer=%s", entry.Analyzer)
			}
			if entry.DeclLine > 0 {
				msg += fmt.Sprintf(", declLine=%d", entry.DeclLine)
			}
			msg += ") no longer matches any finding"
			stale = append(stale, StaleSuppression{
				File:     entry.File,
				Line:     entry.Line,
				DeclLine: entry.DeclLine,
				Type:     entry.Type,
				Analyzer: entry.Analyzer,
				Message:  msg,
			})
		}
	}

	return stale
}
