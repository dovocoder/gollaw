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
	// fileIgnoreAll maps file paths that have a //gollaw:ignore-all comment.
	fileIgnoreAll map[string]bool

	// declIgores maps file → line → analyzer name → true.
	// The line is the line of the declaration the suppression applies to.
	declIgnores map[string]map[int]map[string]bool

	// entries records every suppression comment found, for staleness checking.
	entries []suppressionEntry
}

// suppressionEntry records a single suppression comment and its metadata.
type suppressionEntry struct {
	File     string
	Line     int // line of the comment
	DeclLine int // line of the declaration it applies to (0 for file-level)
	Type     string // "keep", "ignore", "ignore-all"
	Analyzer string // analyzer name for "ignore" type, empty otherwise
	Text     string // original comment text
}

// staleSuppression represents a suppression that no longer matches any finding.
type staleSuppression struct {
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

		processFileLevelComments(fset, file, sup)
		processDeclComments(fset, file, sup, commentByLine)
	}

	return sup, nil
}

// processFileLevelComments scans file comments for file-level ignore-all directives.
func processFileLevelComments(fset *token.FileSet, file *ast.File, sup *Suppressions) {
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			text := strings.TrimSpace(c.Text)
			if text == prefixIgnoreAll {
				fileName := fset.Position(c.Pos()).Filename
				sup.fileIgnoreAll[fileName] = true
				pos := fset.Position(c.Pos())
				sup.entries = append(sup.entries, suppressionEntry{
					File:     fileName,
					Line:     pos.Line,
					DeclLine: 0,
					Type:     "ignore-all",
					Text:     text,
				})
			}
		}
	}
}

// processDeclComments walks declarations to find suppression comments above them
// and scans for inline suppression comments.
func processDeclComments(fset *token.FileSet, file *ast.File, sup *Suppressions, commentByLine map[int]*ast.CommentGroup) {
	// Walk declarations to find suppression comments above them.
	// Also handle the file's package-level doc comment.
	if file.Doc != nil {
		sup.parseDeclComment(fset, file.Doc, file.Pos())
	}
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

// Entries returns all parsed suppression entries.
func (s *Suppressions) Entries() []suppressionEntry {
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
	case text == prefixKeep || strings.HasPrefix(text, prefixKeep+" "):
		// Suppress ALL analyzers for this declaration.
		s.addDeclIgnore(fileName, declLine, "*")
		s.entries = append(s.entries, suppressionEntry{
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
			s.entries = append(s.entries, suppressionEntry{
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

// isSuppressed checks whether a finding is suppressed by any directive.
func isSuppressed(f analyzer.Finding, sup *Suppressions) bool {
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
				// "*" means "keep" — suppress ALL analyzers for this declaration
				if analyzers["*"] {
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
// heuristic: the finding line must be >= declLine-1 (findings are within or
// after the declaration start; -1 accounts for package-level findings reported
// at line 1 when the package clause is at line 2 after a doc comment).
func matchesDecl(findingLine, declLine int) bool {
	return findingLine >= declLine-1
}

// FilterSuppressed returns only the findings that are NOT suppressed.
func FilterSuppressed(findings []analyzer.Finding, sup *Suppressions) []analyzer.Finding {
	if sup == nil {
		return findings
	}
	result := make([]analyzer.Finding, 0, len(findings))
	for _, f := range findings {
		if !isSuppressed(f, sup) {
			result = append(result, f)
		}
	}
	return result
}

// FindStale returns suppressions that no longer match any finding.
// A suppression is stale if no finding exists at its target location
// for the suppressed analyzer.
func FindStale(findings []analyzer.Finding, sup *Suppressions) []staleSuppression {
	if sup == nil || len(sup.entries) == 0 {
		return nil
	}

	var stale []staleSuppression
	for _, entry := range sup.entries {
		if !checkStaleEntry(entry, findings) {
			continue
		}
		stale = append(stale, staleSuppression{
			File:     entry.File,
			Line:     entry.Line,
			DeclLine: entry.DeclLine,
			Type:     entry.Type,
			Analyzer: entry.Analyzer,
			Message:  staleMsg(entry),
		})
	}

	return stale
}

// checkStaleEntry returns true if the suppression entry no longer matches
// any finding.
func checkStaleEntry(entry suppressionEntry, findings []analyzer.Finding) bool {
	if entry.Type == "ignore-all" {
		return !fileHasFindings(entry.File, findings)
	}
	return !checkEntryMatch(entry, findings)
}

// fileHasFindings returns true if any finding belongs to the given file.
func fileHasFindings(file string, findings []analyzer.Finding) bool {
	for _, f := range findings {
		if f.File == file {
			return true
		}
	}
	return false
}

// staleMsg builds a human-readable message for a stale suppression entry.
func staleMsg(entry suppressionEntry) string {
	if entry.Type == "ignore-all" {
		return fmt.Sprintf("file-level ignore-all at %s:%d has no findings to suppress", entry.File, entry.Line)
	}
	msg := fmt.Sprintf("suppression at %s:%d (type=%s", entry.File, entry.Line, entry.Type)
	if entry.Analyzer != "" {
		msg += fmt.Sprintf(", analyzer=%s", entry.Analyzer)
	}
	if entry.DeclLine > 0 {
		msg += fmt.Sprintf(", declLine=%d", entry.DeclLine)
	}
	return msg + ") no longer matches any finding"
}

// checkEntryMatch returns true if any finding matches the suppression entry.
func checkEntryMatch(entry suppressionEntry, findings []analyzer.Finding) bool {
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
				return true
			}
		} else if entry.Type == "ignore" {
			if f.Analyzer == entry.Analyzer {
				return true
			}
		}
	}
	return false
}
