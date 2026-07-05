package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// GlobMatcher matches file paths against a glob pattern.
type GlobMatcher struct {
	//gollaw:keep
	pattern string
}

// ValidateGlob validates that a glob pattern is well-formed.
func ValidateGlob(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("empty pattern")
	}
	// Check for unmatched braces
	braceCount := 0
	for _, c := range pattern {
		switch c {
		case '{':
			braceCount++
		case '}':
			braceCount--
			if braceCount < 0 {
				return fmt.Errorf("unmatched closing brace in pattern: %s", pattern)
			}
		}
	}
	if braceCount > 0 {
		return fmt.Errorf("unmatched opening brace in pattern: %s", pattern)
	}
	return nil
}

// CompilePatterns compiles glob patterns to matchers.
func CompilePatterns(patterns []string) ([]*GlobMatcher, error) {
	var matchers []*GlobMatcher
	for _, p := range patterns {
		if err := ValidateGlob(p); err != nil {
			return nil, err
		}
		matchers = append(matchers, &GlobMatcher{pattern: p})
	}
	return matchers, nil
}

// Match checks if a path matches this glob pattern.
func (m *GlobMatcher) Match(path string) bool {
	pattern := m.pattern
	// Handle ** (recursive match)
	if strings.Contains(pattern, "**") {
		return matchDoubleStar(pattern, path)
	}
	matched, err := filepath.Match(pattern, path)
	if err != nil {
		return false
	}
	if matched {
		return true
	}
	// Also try matching just the basename
	matched, _ = filepath.Match(pattern, filepath.Base(path))
	return matched
}

// MatchAny tests if a path matches any of the matchers.
func MatchAny(matchers []*GlobMatcher, path string) bool {
	for _, m := range matchers {
		if m.Match(path) {
			return true
		}
	}
	return false
}

// ListInvalidPatterns returns patterns that fail validation.
func ListInvalidPatterns(patterns []string) []string {
	var invalid []string
	for _, p := range patterns {
		if err := ValidateGlob(p); err != nil {
			invalid = append(invalid, p)
		}
	}
	return invalid
}

func matchDoubleStar(pattern, path string) bool {
	// Split pattern on ** and check if path contains all parts in order
	parts := strings.Split(pattern, "**")
	if len(parts) == 1 {
		matched, _ := filepath.Match(pattern, path)
		return matched
	}
	remaining := path
	for i, part := range parts {
		part = strings.Trim(part, "/")
		if part == "" {
			continue
		}
		if i == 0 {
			// First part must match the beginning
			if !strings.HasPrefix(remaining, part) {
				return false
			}
			remaining = strings.TrimPrefix(remaining, part)
		} else if i == len(parts)-1 {
			// Last part must match the end
			if !strings.HasSuffix(remaining, part) {
				return false
			}
		} else {
			idx := strings.Index(remaining, part)
			if idx < 0 {
				return false
			}
			remaining = remaining[idx+len(part):]
		}
	}
	return true
}
