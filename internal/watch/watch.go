// Package watch provides file-watching for continuous Gollaw analysis.
// It monitors .go files for changes and triggers a callback after a debounce period.
package watch

import (
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

	if err := addWatchDirs(watcher, dir); err != nil {
		return err
	}

	d := newDebouncer(500*time.Millisecond, onChange)
	debounceEvent := func(_ fsnotify.Event) { d.trigger() }

	return watchLoop(watcher, debounceEvent)
}

// addWatchDirs recursively adds directories to the watcher, skipping
// hidden directories, vendor, node_modules, and testdata.
func addWatchDirs(watcher *fsnotify.Watcher, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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
}

// watchLoop processes fsnotify events and errors. The onEvent callback
// is invoked for each relevant .go file event. Returns on channel close
// or error.
func watchLoop(watcher *fsnotify.Watcher, onEvent func(fsnotify.Event)) error {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if isRelevantGoEvent(event) {
				onEvent(event)
			}

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

// isRelevantGoEvent returns true for write/create/rename/remove events
// on .go files.
func isRelevantGoEvent(event fsnotify.Event) bool {
	if !strings.HasSuffix(event.Name, ".go") {
		return false
	}
	return event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0
}

// debouncer wraps a timer-based debounce mechanism.
type debouncer struct {
	mu      sync.Mutex
	timer   *time.Timer
	delay   time.Duration
	onFire  func()
}

func newDebouncer(delay time.Duration, onFire func()) *debouncer {
	return &debouncer{delay: delay, onFire: onFire}
}

// trigger (re)schedules the debounced callback.
func (d *debouncer) trigger() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.delay, d.onFire)
}

// watchPoll is a fallback polling-based watcher for when fsnotify is unavailable.
// It checks file modification times every 1 second and triggers onChange after
// a 500ms debounce.
func watchPoll(dir string, patterns []string, onChange func()) error {
	modTimes := scanGoModTimes(dir)

	d := newDebouncer(500*time.Millisecond, onChange)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		current := scanGoModTimes(dir)
		if hasChangedFiles(modTimes, current) {
			d.trigger()
		}
		modTimes = current
	}

	return nil
}

// scanGoModTimes walks the directory tree and returns a map of .go file
// paths to their modification times (in UnixNano).
func scanGoModTimes(dir string) map[string]int64 {
	modTimes := make(map[string]int64)
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
	return modTimes
}

// hasChangedFiles compares two mod-time maps and returns true if any .go
// file was added, modified, or deleted.
func hasChangedFiles(old, current map[string]int64) bool {
	// Check for new or modified files.
	for path, mtime := range current {
		if oldMtime, ok := old[path]; !ok || oldMtime != mtime {
			if strings.HasSuffix(path, ".go") {
				return true
			}
		}
	}
	// Check for deleted files.
	for path := range old {
		if _, ok := current[path]; !ok {
			if strings.HasSuffix(path, ".go") {
				return true
			}
		}
	}
	return false
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
