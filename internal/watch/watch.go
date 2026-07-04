// Package watch provides file-watching for continuous Gollaw analysis.
// It monitors .go files for changes and triggers a callback after a debounce period.
package watch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch watches the directory (recursively) for .go file changes.
// When changes are detected, it waits 500ms after the last change before
// calling onChange. The patterns parameter is reserved for future filtering
// (e.g. package patterns); currently all .go files trigger the callback.
//
// Watch blocks until the watcher is interrupted or an error occurs.
func Watch(dir string, patterns []string, onChange func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		// Fall back to polling if fsnotify is unavailable.
		return watchPoll(dir, patterns, onChange)
	}
	defer watcher.Close()

	// Add directories recursively.
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if !info.IsDir() {
			return nil
		}
		if shouldSkipDir(path) {
			return filepath.SkipDir
		}
		return watcher.Add(path)
	})
	if err != nil {
		return fmt.Errorf("walk directory: %w", err)
	}

	// Debounce timer.
	var timer *time.Timer
	var mu sync.Mutex

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Only care about .go files.
			if !strings.HasSuffix(event.Name, ".go") {
				continue
			}
			// Only trigger on write/create/rename/remove events.
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			mu.Lock()
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(500*time.Millisecond, onChange)
			mu.Unlock()

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
}

// watchPoll is a fallback polling-based watcher for when fsnotify is unavailable.
// It checks file modification times every 1 second and triggers onChange after
// a 500ms debounce.
func watchPoll(dir string, patterns []string, onChange func()) error {
	modTimes := make(map[string]int64)
	// Initial scan.
	scanFiles(dir, modTimes)

	var timer *time.Timer
	var mu sync.Mutex

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		current := make(map[string]int64)
		scanFiles(dir, current)

		changed := false
		// Check for new or modified files.
		for path, mtime := range current {
			if old, ok := modTimes[path]; !ok || old != mtime {
				if !strings.HasSuffix(path, ".go") {
					continue
				}
				changed = true
				break
			}
		}
		// Check for deleted files.
		if !changed {
			for path := range modTimes {
				if _, ok := current[path]; !ok {
					if strings.HasSuffix(path, ".go") {
						changed = true
						break
					}
				}
			}
		}

		modTimes = current

		if changed {
			mu.Lock()
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(500*time.Millisecond, onChange)
			mu.Unlock()
		}
	}

	return nil
}

// scanFiles walks the directory and records modification times for .go files.
func scanFiles(dir string, modTimes map[string]int64) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			modTimes[path] = info.ModTime().UnixNano()
		}
		return nil
	})
}

// shouldSkipDir returns true for directories that should not be watched.
func shouldSkipDir(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") && base != "." {
		return true
	}
	switch base {
	case "vendor", "node_modules", "testdata":
		return true
	}
	return false
}
