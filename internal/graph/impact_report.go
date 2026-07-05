package graph

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

// impactReport is a comprehensive impact analysis for a set of changed files.
type impactReport struct {
	ChangedPackages   []string
	AffectedPackages  []string
	TotalBlastRadius  int
	CoordinationGaps  []coordinationGap
	FanIOForChanged   []fanIOStats
	PartitionLayer    int
}

// BuildImpactReport builds a full impact report for the given changed files.
func BuildImpactReport(graph *ModuleGraph, changedFiles []string) *impactReport {
	report := &impactReport{}
	if graph == nil {
		return report
	}

	closure := impactClosure(graph, changedFiles)
	report.CoordinationGaps = closure.coordinationGaps

	changedPkgs := changedFileToPackages(graph, changedFiles)
	report.ChangedPackages = keysToSlice(changedPkgs)
	report.AffectedPackages = keysToSlice(computeAffected(graph, changedPkgs))
	report.TotalBlastRadius = len(report.ChangedPackages) + len(report.AffectedPackages)
	report.FanIOForChanged = computeFanIOForChanged(graph, changedPkgs)
	report.PartitionLayer = findPartitionLayer(graph, changedPkgs)
	return report
}

// keysToSlice returns the keys of a map as a slice.
func keysToSlice(m map[string]bool) []string {
	var result []string
	for k := range m {
		result = append(result, k)
	}
	return result
}

// computeFanIOForChanged returns fan-in/fan-out stats for changed packages.
func computeFanIOForChanged(graph *ModuleGraph, changedPkgs map[string]bool) []fanIOStats {
	allFanIO := computeFanIOWithThresholds(graph, defaultFanIOThresholds)
	var result []fanIOStats
	for _, s := range allFanIO {
		if changedPkgs[s.Package] {
			result = append(result, s)
		}
	}
	return result
}

// findPartitionLayer returns the partition layer of the first changed package found.
func findPartitionLayer(graph *ModuleGraph, changedPkgs map[string]bool) int {
	layers := partitionOrder(graph)
	for i, layer := range layers {
		for _, pkg := range layer {
			if changedPkgs[pkg] {
				return i
			}
		}
	}
	return 0
}

// FormatImpactText formats the impact report as a human-readable string.
func FormatImpactText(report *impactReport) string {
	if report == nil {
		return ""
	}
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)

	fmt.Fprintf(tw, "Impact Report\n")
	fmt.Fprintf(tw, "==============\n\n")
	fmt.Fprintf(tw, "Total Blast Radius:\t%d packages\n", report.TotalBlastRadius)
	fmt.Fprintf(tw, "Changed Packages:\t%d\n", len(report.ChangedPackages))
	fmt.Fprintf(tw, "Affected Packages:\t%d\n", len(report.AffectedPackages))
	fmt.Fprintf(tw, "Coordination Gaps:\t%d\n", len(report.CoordinationGaps))
	fmt.Fprintf(tw, "Partition Layer:\t%d\n\n", report.PartitionLayer)

	formatPackageList(tw, "Changed Packages:", report.ChangedPackages)
	formatPackageList(tw, "Affected Packages (transitive):", report.AffectedPackages)
	formatCoordinationGaps(tw, report.CoordinationGaps)
	formatFanIOSection(tw, report.FanIOForChanged)

	tw.Flush()
	return sb.String()
}

// formatPackageList writes a section header followed by a list of packages.
func formatPackageList(tw *tabwriter.Writer, header string, pkgs []string) {
	if len(pkgs) == 0 {
		return
	}
	fmt.Fprintf(tw, "%s\n", header)
	for _, p := range pkgs {
		fmt.Fprintf(tw, "  \t%s\n", p)
	}
	fmt.Fprintf(tw, "\n")
}

// formatCoordinationGaps writes the coordination gaps section.
func formatCoordinationGaps(tw *tabwriter.Writer, gaps []coordinationGap) {
	if len(gaps) == 0 {
		return
	}
	fmt.Fprintf(tw, "Coordination Gaps:\n")
	for _, gap := range gaps {
		changedFile := filepath.Base(gap.ChangedFile)
		consumerFile := filepath.Base(gap.ConsumerFile)
		fmt.Fprintf(tw, "  \t%s → %s\t%v\n", changedFile, consumerFile, gap.ConsumedSymbols)
	}
	fmt.Fprintf(tw, "\n")
}

// formatFanIOSection writes the fan-in/fan-out section for changed packages.
func formatFanIOSection(tw *tabwriter.Writer, stats []fanIOStats) {
	if len(stats) == 0 {
		return
	}
	fmt.Fprintf(tw, "Fan-In/Fan-Out for Changed Packages:\n")
	fmt.Fprintf(tw, "  \tPackage\tFanIn\tFanOut\tHighCoupling\n")
	for _, s := range stats {
		fmt.Fprintf(tw, "  \t%s\t%d\t%d\t%v\n", s.Package, s.FanIn, s.FanOut, s.IsHighCoupling)
	}
	fmt.Fprintf(tw, "\n")
}

// FormatImpactJSON formats the impact report as JSON.
func FormatImpactJSON(report *impactReport) ([]byte, error) {
	if report == nil {
		return []byte("null"), nil
	}
	return json.MarshalIndent(report, "", "  ")
}
