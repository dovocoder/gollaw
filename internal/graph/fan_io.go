package graph

import "sort"

// FanIOStats holds fan-in/fan-out metrics for a single package.
type FanIOStats struct {
	Package       string
	FanIn         int
	FanOut        int
	IsHighCoupling bool
}

// fanIORankingResult holds the top-N most imported packages and top-N importers.
type fanIORankingResult struct {
	TopImported  []FanIOStats
	TopImporters []FanIOStats
}

// fanIOThresholds configures what counts as "high coupling".
type fanIOThresholds struct {
	MaxFanIn  int
	MaxFanOut int
}

// DefaultFanIOThresholds are the thresholds used when none are specified.
var DefaultFanIOThresholds = fanIOThresholds{
	MaxFanIn:  5,
	MaxFanOut: 10,
}

// ComputeFanIOWithThresholds computes fan-in/fan-out with custom thresholds.
func ComputeFanIOWithThresholds(graph *ModuleGraph, t fanIOThresholds) []FanIOStats {
	if graph == nil {
		return nil
	}
	stats := make([]FanIOStats, 0, len(graph.Nodes))
	for _, node := range graph.Nodes {
		fanIn := len(graph.reverseDeps[node.Path])
		fanOut := len(graph.forwardDeps[node.Path])
		stats = append(stats, FanIOStats{
			Package:        node.Path,
			FanIn:          fanIn,
			FanOut:         fanOut,
			IsHighCoupling: fanIn > t.MaxFanIn || fanOut > t.MaxFanOut,
		})
	}
	return stats
}

// fanIORanking returns the top-10 most imported packages and top-10 importers.
//gollaw:keep
func fanIORanking(graph *ModuleGraph) *fanIORankingResult {
	ranking := &fanIORankingResult{}
	if graph == nil {
		return ranking
	}

	all := ComputeFanIOWithThresholds(graph, DefaultFanIOThresholds)

	// Sort by fan-in (most imported first).
	sortedByIn := make([]FanIOStats, len(all))
	copy(sortedByIn, all)
	sort.Slice(sortedByIn, func(i, j int) bool {
		return sortedByIn[i].FanIn > sortedByIn[j].FanIn
	})
	limit := 10
	if len(sortedByIn) < limit {
		limit = len(sortedByIn)
	}
	ranking.TopImported = sortedByIn[:limit]

	// Sort by fan-out (most importers first).
	sortedByOut := make([]FanIOStats, len(all))
	copy(sortedByOut, all)
	sort.Slice(sortedByOut, func(i, j int) bool {
		return sortedByOut[i].FanOut > sortedByOut[j].FanOut
	})
	limit = 10
	if len(sortedByOut) < limit {
		limit = len(sortedByOut)
	}
	ranking.TopImporters = sortedByOut[:limit]

	return ranking
}
