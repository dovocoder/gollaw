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

func TestDeadCodeAnalyzerKeepsMigrationUpDownAndClosureHooks(t *testing.T) {
	findings := analyzeDeadCodeModule(t, map[string]string{
		"go.mod": "module sample\n\ngo 1.25\n",
		"migrations.go": `package main

type db struct{}

type migration struct {
	up       func(*db) error
	down     func(*db) error
	validate func(*db) error
}

var migrations = []migration{
	{up: migrateOne, down: rollbackOne, validate: func(d *db) error { return validateOne(d) }},
	{up: func(d *db) error { return migrateTwo(d) }},
}

func main() {
	for _, m := range migrations {
		_ = m.up(&db{})
		if m.down != nil {
			_ = m.down(&db{})
		}
		if m.validate != nil {
			_ = m.validate(&db{})
		}
	}
}

func migrateOne(*db) error { return nil }
func rollbackOne(*db) error { return nil }
func validateOne(*db) error { return nil }
func migrateTwo(*db) error { return nil }
`,
	})

	assertDeadCodeNotContains(t, findings, "migrateOne")
	assertDeadCodeNotContains(t, findings, "rollbackOne")
	assertDeadCodeNotContains(t, findings, "validateOne")
	assertDeadCodeNotContains(t, findings, "migrateTwo")
}

func TestDeadCodeAnalyzerKeepsMigrationMethodValuesAndExpressions(t *testing.T) {
	findings := analyzeDeadCodeModule(t, map[string]string{
		"go.mod": "module sample\n\ngo 1.25\n",
		"migrations.go": `package main

type db struct{}

type runner struct{}

type migration struct {
	up func(*db) error
}

var defaultRunner runner

var migrations = []migration{
	{up: defaultRunner.migrateByValue},
	{up: (*runner).migrateByExpression},
}

func main() {
	for _, m := range migrations {
		_ = m.up(&db{})
	}
}

func (runner) migrateByValue(*db) error { return nil }
func (*runner) migrateByExpression(*db) error { return nil }
`,
	})

	assertDeadCodeNotContains(t, findings, "migrateByValue")
	assertDeadCodeNotContains(t, findings, "migrateByExpression")
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

func TestDeadCodeAnalyzerFollowsCobraCommandHandlers(t *testing.T) {
	findings := analyzeDeadCodeModule(t, cobraModuleFiles(map[string]string{
		"go.mod": cobraGoMod(),
		"main.go": `package main

import "github.com/spf13/cobra"

func main() {
	_ = newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "root",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoot(args)
		},
	}
	cmd.AddCommand(newChildCmd())
	return cmd
}

func newChildCmd() *cobra.Command {
	return &cobra.Command{
		Use: "child",
		Run: func(cmd *cobra.Command, args []string) {
			runChild(args)
		},
	}
}

func runRoot([]string) error { return nil }
func runChild([]string) {}
`,
	}))

	assertDeadCodeNotContains(t, findings, "newRootCmd")
	assertDeadCodeNotContains(t, findings, "newChildCmd")
	assertDeadCodeNotContains(t, findings, "runRoot")
	assertDeadCodeNotContains(t, findings, "runChild")
}

func TestDeadCodeAnalyzerFollowsCobraConstructorRegistry(t *testing.T) {
	findings := analyzeDeadCodeModule(t, cobraModuleFiles(map[string]string{
		"go.mod": cobraGoMod(),
		"main.go": `package main

import "github.com/spf13/cobra"

type flags struct{}
type commandFactory func(*flags) *cobra.Command

var factories = []commandFactory{
	newAlphaCmd,
	func(f *flags) *cobra.Command { return newBetaCmd(f) },
}

func main() {
	f := &flags{}
	root := &cobra.Command{Use: "root"}
	for _, factory := range factories {
		root.AddCommand(factory(f))
	}
	_ = root.Execute()
}

func newAlphaCmd(*flags) *cobra.Command {
	return &cobra.Command{Use: "alpha", RunE: runAlpha}
}

func newBetaCmd(*flags) *cobra.Command {
	return &cobra.Command{Use: "beta", RunE: func(cmd *cobra.Command, args []string) error {
		return runBeta(args)
	}}
}

func runAlpha(*cobra.Command, []string) error { return nil }
func runBeta([]string) error { return nil }
`,
	}))

	assertDeadCodeNotContains(t, findings, "newAlphaCmd")
	assertDeadCodeNotContains(t, findings, "newBetaCmd")
	assertDeadCodeNotContains(t, findings, "runAlpha")
	assertDeadCodeNotContains(t, findings, "runBeta")
}

func TestDeadCodeAnalyzerFollowsCobraMethodValueHandlers(t *testing.T) {
	findings := analyzeDeadCodeModule(t, cobraModuleFiles(map[string]string{
		"go.mod": cobraGoMod(),
		"main.go": `package main

import "github.com/spf13/cobra"

type handler struct{}

var defaultHandler handler

func main() {
	_ = newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "root",
		RunE: defaultHandler.runRoot,
	}
}

func (handler) runRoot(*cobra.Command, []string) error {
	return nil
}
`,
	}))

	assertDeadCodeNotContains(t, findings, "runRoot")
}

func TestDeadCodeAnalyzerFollowsCobraPackageCommandCallbacks(t *testing.T) {
	findings := analyzeDeadCodeModule(t, cobraModuleFiles(map[string]string{
		"go.mod": cobraGoMod(),
		"main.go": `package main

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:               "root",
	Args:              validateArgs,
	PreRunE:           beforeRun,
	RunE:              runRoot,
	PostRunE:          afterRun,
	ValidArgsFunction: completeArgs,
}

var childCmd = &cobra.Command{
	Use: "child",
	Run: runChild,
}

func init() {
	rootCmd.AddCommand(childCmd)
}

func main() {
	_ = rootCmd.Execute()
}

func validateArgs(*cobra.Command, []string) error { return nil }
func beforeRun(*cobra.Command, []string) error { return nil }
func runRoot(*cobra.Command, []string) error { return nil }
func afterRun(*cobra.Command, []string) error { return nil }
func completeArgs(*cobra.Command, []string, string) ([]string, int) { return nil, 0 }
func runChild(*cobra.Command, []string) {}
`,
	}))

	assertDeadCodeNotContains(t, findings, "validateArgs")
	assertDeadCodeNotContains(t, findings, "beforeRun")
	assertDeadCodeNotContains(t, findings, "runRoot")
	assertDeadCodeNotContains(t, findings, "afterRun")
	assertDeadCodeNotContains(t, findings, "completeArgs")
	assertDeadCodeNotContains(t, findings, "runChild")
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

func cobraGoMod() string {
	return `module sample

go 1.25

require github.com/spf13/cobra v1.10.2

replace github.com/spf13/cobra => ./cobra
`
}

func cobraModuleFiles(files map[string]string) map[string]string {
	files["cobra/go.mod"] = "module github.com/spf13/cobra\n\ngo 1.25\n"
	files["cobra/cobra.go"] = `package cobra

type Command struct {
	Use               string
	Args              func(*Command, []string) error
	PreRunE           func(*Command, []string) error
	Run               func(*Command, []string)
	RunE              func(*Command, []string) error
	PostRunE          func(*Command, []string) error
	ValidArgsFunction func(*Command, []string, string) ([]string, int)
}

func (c *Command) AddCommand(children ...*Command) {}

func (c *Command) Execute() error {
	if c.RunE != nil {
		return c.RunE(c, nil)
	}
	if c.Run != nil {
		c.Run(c, nil)
	}
	return nil
}
`
	return files
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
