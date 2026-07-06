package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dovocoder/gollaw/internal/loader"
)

func TestDeadCodeAnalyzerFlagsUncalledPrivateMethod(t *testing.T) {
	findings := analyzeDeadCodeModule(t, map[string]string{
		"go.mod": "module sample\n\ngo 1.25\n",
		"main.go": `package main

func main() {}

type worker struct{}

func (worker) unusedPrivateMethod() {}
`,
	})

	assertDeadCodeContains(t, findings, "unusedPrivateMethod")
}

func TestDeadCodeAnalyzerKeepsCalledPrivateMethod(t *testing.T) {
	findings := analyzeDeadCodeModule(t, map[string]string{
		"go.mod": "module sample\n\ngo 1.25\n",
		"main.go": `package main

func main() {
	worker{}.usedPrivateMethod()
}

type worker struct{}

func (worker) usedPrivateMethod() {}
`,
	})

	assertDeadCodeNotContains(t, findings, "usedPrivateMethod")
}

func TestDeadCodeAnalyzerFollowsExportedFunctionMethodCall(t *testing.T) {
	findings := analyzeDeadCodeModule(t, map[string]string{
		"go.mod": "module sample\n\ngo 1.25\n",
		"worker.go": `package sample

func Start() {
	worker{}.run()
}

type worker struct{}

func (worker) run() {}
`,
	})

	assertDeadCodeNotContains(t, findings, "run")
}

func TestDeadCodeAnalyzerFollowsExportedConstructorRunMethod(t *testing.T) {
	findings := analyzeDeadCodeModule(t, map[string]string{
		"go.mod": "module sample\n\ngo 1.25\n",
		"server.go": `package sample

func Serve() error {
	s := &server{}
	return s.run()
}

type server struct{}

func (s *server) run() error {
	return s.write()
}

func (s *server) write() error {
	return nil
}
`,
	})

	assertDeadCodeNotContains(t, findings, "run")
	assertDeadCodeNotContains(t, findings, "write")
}

func TestDeadCodeAnalyzerKeepsFunctionValueInComposite(t *testing.T) {
	findings := analyzeDeadCodeModule(t, map[string]string{
		"go.mod": "module sample\n\ngo 1.25\n",
		"main.go": `package main

type migration struct {
	up func()
}

var migrations = []migration{{up: migrateFoo}}

func main() {
	for _, m := range migrations {
		m.up()
	}
}

func migrateFoo() {}
`,
	})

	assertDeadCodeNotContains(t, findings, "migrateFoo")
}

func TestDeadCodeAnalyzerFollowsGlobalDispatchClosures(t *testing.T) {
	findings := analyzeDeadCodeModule(t, map[string]string{
		"go.mod": "module sample\n\ngo 1.25\n",
		"server.go": `package sample

type server struct{}

type handler func(*server)

var dispatch = map[string]handler{
	"run": func(s *server) { s.run() },
}

func Serve(name string) {
	dispatch[name](&server{})
}

func (s *server) run() {}
`,
	})

	assertDeadCodeNotContains(t, findings, "run")
}

func analyzeDeadCodeModule(t *testing.T, files map[string]string) []Finding {
	t.Helper()

	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	loaded, err := loader.Load(loader.LoadConfig{Dir: dir, Patterns: []string{"./..."}})
	if err != nil {
		t.Fatalf("load module: %v", err)
	}
	ctx := &Context{
		FSET:        loaded.FSET,
		Packages:    loaded.Packages,
		SSA:         loaded.SSA,
		SSAByPkg:    loaded.SSAByPkg,
		TypesByPkg:  loaded.TypesByPkg,
		SyntaxByPkg: loaded.SyntaxByPkg,
	}
	findings, err := newDeadCodeAnalyzer().Analyze(ctx)
	if err != nil {
		t.Fatalf("analyze deadcode: %v", err)
	}
	return findings
}

func assertDeadCodeContains(t *testing.T, findings []Finding, name string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == "GLW-DC001" && strings.Contains(finding.Message, name) {
			return
		}
	}
	t.Fatalf("deadcode findings do not contain %q: %+v", name, findings)
}

func assertDeadCodeNotContains(t *testing.T, findings []Finding, name string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == "GLW-DC001" && strings.Contains(finding.Message, name) {
			t.Fatalf("deadcode findings unexpectedly contain %q: %+v", name, findings)
		}
	}
}
