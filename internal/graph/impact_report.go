package graph

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

// ImpactReport is a comprehensive impact analysis for a set of changed files.
type ImpactReport struct {
	ChangedPackages   []string
	AffectedPackages  []string
	TotalBlastRadius  int
	CoordinationGaps  []CoordinationGap
	FanIOForChanged   []FanIOStats
	PartitionLayer    int
}

// BuildImpactReport builds a full impact report for the given changed files.
func BuildImpactReport(graph *ModuleGraph, changedFiles []string) *ImpactReport {
	report := &ImpactReport{}

	if graph == nil {
		return report
	}

	// Compute impact closure.
	closure := ImpactClosure(graph, changedFiles)
	report.CoordinationGaps = closure.CoordinationGaps

	// Determine changed packages.
	changedPkgs := changedFileToPackages(graph, changedFiles)
	for pkg := range changedPkgs {
		report.ChangedPackages = append(report.ChangedPackages, pkg)
	}

	// Determine affected packages (transitive reverse deps).
	reverseVisited := make(map[string]bool)
	reverseQueue := make([]string, 0, len(report.ChangedPackages))
	for _, pkg := range report.ChangedPackages {
		if !reverseVisited[pkg] {
			reverseVisited[pkg] = true
			reverseQueue = append(reverseQueue, pkg)
		}
	}
	for len(reverseQueue) > 0 {
		current := reverseQueue[0]
		reverseQueue = reverseQueue[1:]
		for _, importerID := range graph.ReverseDeps(current) {
			importerPath := graph.Nodes[importerID].Path
			if reverseVisited[importerPath] {
				continue
			}
			reverseVisited[importerPath] = true
			report.AffectedPackages = append(report.AffectedPackages, importerPath)
			reverseQueue = append(reverseQueue, importerPath)
		}
	}

	report.TotalBlastRadius = len(report.ChangedPackages) + len(report.AffectedPackages)

	// Fan-in/fan-out for changed packages.
	allFanIO := ComputeFanIOWithThresholds(graph, DefaultFanIOThresholds)
	for _, s := range allFanIO {
		if changedPkgs[s.Package] {
			report.FanIOForChanged = append(report.FanIOForChanged, s)
		}
	}

	// Partition layer of the changed packages.
	layers := PartitionOrder(graph)
	for i, layer := range layers {
		for _, pkg := range layer {
			if changedPkgs[pkg] {
				report.PartitionLayer = i
				return report
			}
		}
	}

	return report
}

// FormatImpactText formats the impact report as a human-readable string.
func FormatImpactText(report *ImpactReport) string {
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

	if len(report.ChangedPackages) > 0 {
		fmt.Fprintf(tw, "Changed Packages:\n")
		for _, p := range report.ChangedPackages {
			fmt.Fprintf(tw, "  \t%s\n", p)
		}
		fmt.Fprintf(tw, "\n")
	}

	if len(report.AffectedPackages) > 0 {
		fmt.Fprintf(tw, "Affected Packages (transitive):\n")
		for _, p := range report.AffectedPackages {
			fmt.Fprintf(tw, "  \t%s\n", p)
		}
		fmt.Fprintf(tw, "\n")
	}

	if len(report.CoordinationGaps) > 0 {
		fmt.Fprintf(tw, "Coordination Gaps:\n")
		for _, gap := range report.CoordinationGaps {
			changedFile := filepath.Base(gap.ChangedFile)
			consumerFile := filepath.Base(gap.ConsumerFile)
			fmt.Fprintf(tw, "  \t%s → %s\t%v\n", changedFile, consumerFile, gap.ConsumedSymbols)
		}
		fmt.Fprintf(tw, "\n")
	}

	if len(report.FanIOForChanged) > 0 {
		fmt.Fprintf(tw, "Fan-In/Fan-Out for Changed Packages:\n")
		fmt.Fprintf(tw, "  \tPackage\tFanIn\tFanOut\tHighCoupling\n")
		for _, s := range report.FanIOForChanged {
			fmt.Fprintf(tw, "  \t%s\t%d\t%d\t%v\n", s.Package, s.FanIn, s.FanOut, s.IsHighCoupling)
		}
		fmt.Fprintf(tw, "\n")
	}

	tw.Flush()
	return sb.String()
}

// FormatImpactJSON formats the impact report as JSON.
func FormatImpactJSON(report *ImpactReport) ([]byte, error) {
	if report == nil {
		return []byte("null"), nil
	}
	return json.MarshalIndent(report, "", "  ")
}
