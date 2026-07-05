package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// workspaceInfo holds Go workspace information from go.work.
type workspaceInfo struct {
	Root        string
	Modules     []moduleInfo
	GoVersion   string
}

// moduleInfo holds information about a single Go module.
type moduleInfo struct {
	Path    string
	Version string
	Replace string
}

// detectWorkspace finds and parses go.work from the given directory.
//gollaw:keep
func detectWorkspace(dir string) (*workspaceInfo, error) {
	goWorkPath := findFileUpward(dir, "go.work")
	if goWorkPath == "" {
		return nil, fmt.Errorf("no go.work found")
	}

	data, err := os.ReadFile(goWorkPath)
	if err != nil {
		return nil, err
	}

	info := &workspaceInfo{
		Root: filepath.Dir(goWorkPath),
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "go ") {
			info.GoVersion = strings.TrimPrefix(line, "go ")
		}
		if strings.HasPrefix(line, "use ") {
			modPath := strings.TrimPrefix(line, "use ")
			modPath = strings.TrimSpace(modPath)
			absPath := modPath
			if !filepath.IsAbs(absPath) {
				absPath = filepath.Join(info.Root, modPath)
			}
			modName := getModuleName(absPath)
			info.Modules = append(info.Modules, moduleInfo{Path: modName})
		}
	}

	return info, nil
}

// resolveModule finds the go.mod for the current directory.
//gollaw:keep
func resolveModule(dir string) (string, error) {
	goModPath := findFileUpward(dir, "go.mod")
	if goModPath == "" {
		return "", fmt.Errorf("no go.mod found")
	}
	return goModPath, nil
}

// listWorkspaceModules lists all modules in a workspace.
//gollaw:keep
func listWorkspaceModules(dir string) ([]moduleInfo, error) {
	info, err := detectWorkspace(dir)
	if err != nil {
		return nil, err
	}
	return info.Modules, nil
}

// isWorkspaceMode checks if go.work exists.
//gollaw:keep
func isWorkspaceMode(dir string) bool {
	return findFileUpward(dir, "go.work") != ""
}

//gollaw:keep
func findFileUpward(dir, filename string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for i := 0; i < 20; i++ {
		candidate := filepath.Join(abs, filename)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	return ""
}

//gollaw:keep
func getModuleName(dir string) string {
	goMod := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goMod)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimPrefix(line, "module ")
		}
	}
	return ""
}
