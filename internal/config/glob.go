package config

import (
	"path/filepath"
	"strings"
)

// globMatcher matches file paths against a glob pattern.
type globMatcher struct {
	pattern string
}

// Match checks if a path matches this glob pattern.
func (m *globMatcher) Match(path string) bool {
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
