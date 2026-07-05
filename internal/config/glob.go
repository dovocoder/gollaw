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
		ok, rest := matchDoubleStarPart(i, len(parts), part, remaining)
		if !ok {
			return false
		}
		remaining = rest
	}
	return true
}

// matchDoubleStarPart matches a single segment of a ** pattern.
// Returns whether the part matched and the remaining unmatched path.
func matchDoubleStarPart(index, total int, part, remaining string) (bool, string) {
	if index == 0 {
		return matchFirstPart(part, remaining)
	}
	if index == total-1 {
		return matchLastPart(part, remaining)
	}
	return matchMiddlePart(part, remaining)
}

// matchFirstPart matches the first segment: must match the beginning.
func matchFirstPart(part, remaining string) (bool, string) {
	if !strings.HasPrefix(remaining, part) {
		return false, ""
	}
	return true, strings.TrimPrefix(remaining, part)
}

// matchLastPart matches the last segment: must match the end.
func matchLastPart(part, remaining string) (bool, string) {
	if !strings.HasSuffix(remaining, part) {
		return false, ""
	}
	return true, remaining
}

// matchMiddlePart matches a middle segment: must be found anywhere.
func matchMiddlePart(part, remaining string) (bool, string) {
	idx := strings.Index(remaining, part)
	if idx < 0 {
		return false, ""
	}
	return true, remaining[idx+len(part):]
}
