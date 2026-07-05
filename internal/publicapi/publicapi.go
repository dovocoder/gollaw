package publicapi

import (
	"encoding/json"
	"fmt"
	"go/types"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"golang.org/x/tools/go/packages"
)

// ExportInfo describes a single exported identifier.
type ExportInfo struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"` // function, type, const, var
	Package string  `json:"package"`
	File   string   `json:"file"`
	Line   int      `json:"line"`
	UsedBy []string `json:"usedBy"`
}

// APIReport summarises the public API surface of the codebase.
type APIReport struct {
	TotalExports      int          `json:"totalExports"`
	ConfirmedPublic   []ExportInfo `json:"confirmedPublic"`
	AccidentalExports []ExportInfo `json:"accidentalExports"`
	UnusedExports     []ExportInfo `json:"unusedExports"`
}

// AnalyzePublicAPI inspects every loaded package, collects exported identifiers,
// and classifies them as confirmed public API, accidental exports, or unused.
func AnalyzePublicAPI(ctx *analyzer.Context) (*APIReport, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil analyzer context")
	}

	entries := make(map[string]*exportEntry) // key: pkgPath.Name

	// Collect all exported identifiers from loaded packages.
	for pkgPath, typPkg := range ctx.TypesByPkg {
		scope := typPkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if obj == nil || !obj.Exported() {
				continue
			}
			// Skip the main function in package main.
			if name == "main" && pkgPath == "main" {
				continue
			}
			key := pkgPath + "." + name
			entries[key] = &exportEntry{
				obj:     obj,
				pkgPath: pkgPath,
				usedBy:  make(map[string]bool),
			}
		}
	}

	// Scan uses across all packages. A use counts if it comes from a *different*
	// package than the one that defines the export.
	scanUses(ctx.Packages, entries)

	report := &APIReport{
		TotalExports: len(entries),
	}

	// Also determine whether an export is used within its own package. We need
	// this to distinguish "accidental" (used only internally) from "unused"
	// (not used anywhere at all).
	ownPkgUsage := buildOwnPackageUsageSet(ctx)

	for key, e := range entries {
		info := ExportInfo{
			Name:    e.obj.Name(),
			Kind:    kindOfObject(e.obj),
			Package: e.pkgPath,
			File:    fileOf(ctx, e.obj),
			Line:    lineOf(ctx, e.obj),
			UsedBy:  sortedKeys(e.usedBy),
		}

		externalUse := len(e.usedBy) > 0
		internalUse := ownPkgUsage[key]

		switch {
		case externalUse:
			report.ConfirmedPublic = append(report.ConfirmedPublic, info)
		case internalUse:
			report.AccidentalExports = append(report.AccidentalExports, info)
		default:
			report.UnusedExports = append(report.UnusedExports, info)
		}
	}

	sort.Slice(report.ConfirmedPublic, func(i, j int) bool {
		if report.ConfirmedPublic[i].Package != report.ConfirmedPublic[j].Package {
			return report.ConfirmedPublic[i].Package < report.ConfirmedPublic[j].Package
		}
		return report.ConfirmedPublic[i].Name < report.ConfirmedPublic[j].Name
	})
	sort.Slice(report.AccidentalExports, func(i, j int) bool {
		if report.AccidentalExports[i].Package != report.AccidentalExports[j].Package {
			return report.AccidentalExports[i].Package < report.AccidentalExports[j].Package
		}
		return report.AccidentalExports[i].Name < report.AccidentalExports[j].Name
	})
	sort.Slice(report.UnusedExports, func(i, j int) bool {
		if report.UnusedExports[i].Package != report.UnusedExports[j].Package {
			return report.UnusedExports[i].Package < report.UnusedExports[j].Package
		}
		return report.UnusedExports[i].Name < report.UnusedExports[j].Name
	})

	return report, nil
}

// scanUses walks the TypesInfo.Uses map of every loaded package and records
// which packages reference each exported identifier from a different package.
func scanUses(pkgs []*packages.Package, entries map[string]*exportEntry) {
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		usingPkgPath := pkg.PkgPath
		for _, obj := range pkg.TypesInfo.Uses {
			if obj == nil || !obj.Exported() {
				continue
			}
			ownerPkg := obj.Pkg()
			if ownerPkg == nil {
				continue
			}
			ownerPath := ownerPkg.Path()
			if ownerPath == usingPkgPath {
				continue // same package — not an external use
			}
			key := ownerPath + "." + obj.Name()
			if e, ok := entries[key]; ok {
				e.usedBy[usingPkgPath] = true
			}
		}
	}
}

type exportEntry struct {
	//gollaw:keep
	obj     types.Object
	//gollaw:keep
	pkgPath string
	//gollaw:keep
	usedBy  map[string]bool
}

// buildOwnPackageUsageSet returns the set of "pkgPath.Name" keys that are
// referenced within their own package (i.e. the export is at least used
// internally, even if not externally).
func buildOwnPackageUsageSet(ctx *analyzer.Context) map[string]bool {
	own := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		usingPkgPath := pkg.PkgPath
		for _, obj := range pkg.TypesInfo.Uses {
			if obj == nil || !obj.Exported() {
				continue
			}
			ownerPkg := obj.Pkg()
			if ownerPkg == nil || ownerPkg.Path() != usingPkgPath {
				continue
			}
			own[usingPkgPath+"."+obj.Name()] = true
		}
	}
	return own
}

// FormatPublicAPIText renders the API report as a human-readable text table.
func FormatPublicAPIText(report *APIReport) string {
	if report == nil {
		return ""
	}
	var b strings.Builder

	fmt.Fprintf(&b, "Public API Report\n")
	fmt.Fprintf(&b, "=================\n\n")
	fmt.Fprintf(&b, "Total exported identifiers: %d\n", report.TotalExports)
	fmt.Fprintf(&b, "  Confirmed public API: %d\n", len(report.ConfirmedPublic))
	fmt.Fprintf(&b, "  Accidental exports:  %d\n", len(report.AccidentalExports))
	fmt.Fprintf(&b, "  Unused exports:       %d\n\n", len(report.UnusedExports))

	if len(report.ConfirmedPublic) > 0 {
		fmt.Fprintf(&b, "Confirmed Public API (used by external importers)\n")
		fmt.Fprintf(&b, "%-30s  %-10s  %-40s  %s\n", "NAME", "KIND", "PACKAGE", "USED BY")
		fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 100))
		for _, e := range report.ConfirmedPublic {
			usedBy := strings.Join(e.UsedBy, ", ")
			fmt.Fprintf(&b, "%-30s  %-10s  %-40s  %s\n", e.Name, e.Kind, e.Package, usedBy)
		}
		fmt.Fprintln(&b)
	}

	if len(report.AccidentalExports) > 0 {
		fmt.Fprintf(&b, "Accidental Exports (used only within own package — consider unexporting)\n")
		fmt.Fprintf(&b, "%-30s  %-10s  %-40s  %s\n", "NAME", "KIND", "PACKAGE", "FILE:LINE")
		fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 100))
		for _, e := range report.AccidentalExports {
			fmt.Fprintf(&b, "%-30s  %-10s  %-40s  %s:%d\n", e.Name, e.Kind, e.Package, e.File, e.Line)
		}
		fmt.Fprintln(&b)
	}

	if len(report.UnusedExports) > 0 {
		fmt.Fprintf(&b, "Unused Exports (not referenced anywhere)\n")
		fmt.Fprintf(&b, "%-30s  %-10s  %-40s  %s\n", "NAME", "KIND", "PACKAGE", "FILE:LINE")
		fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 100))
		for _, e := range report.UnusedExports {
			fmt.Fprintf(&b, "%-30s  %-10s  %-40s  %s:%d\n", e.Name, e.Kind, e.Package, e.File, e.Line)
		}
	}

	return b.String()
}

// FormatPublicAPIJSON renders the API report as JSON.
func FormatPublicAPIJSON(report *APIReport) ([]byte, error) {
	if report == nil {
		return []byte("null"), nil
	}
	return json.MarshalIndent(report, "", "  ")
}

// --- helpers ---

func kindOfObject(obj types.Object) string {
	switch obj.(type) {
	case *types.Func:
		return "function"
	case *types.TypeName:
		return "type"
	case *types.Const:
		return "const"
	case *types.Var:
		return "var"
	default:
		return "identifier"
	}
}

func fileOf(ctx *analyzer.Context, obj types.Object) string {
	return ctx.FSET.Position(obj.Pos()).Filename
}

func lineOf(ctx *analyzer.Context, obj types.Object) int {
	return ctx.FSET.Position(obj.Pos()).Line
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
