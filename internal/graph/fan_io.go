package graph

import "sort"

// fanIOStats holds fan-in/fan-out metrics for a single package.
type fanIOStats struct {
	Package       string
	FanIn         int
	FanOut        int
	IsHighCoupling bool
}

// fanIORankingResult holds the top-N most imported packages and top-N importers.
type fanIORankingResult struct {
	TopImported  []fanIOStats
	TopImporters []fanIOStats
}

// fanIOThresholds configures what counts as "high coupling".
type fanIOThresholds struct {
	MaxFanIn  int
	MaxFanOut int
}

// defaultFanIOThresholds are the thresholds used when none are specified.
var defaultFanIOThresholds = fanIOThresholds{
	MaxFanIn:  5,
	MaxFanOut: 10,
}

// computeFanIOWithThresholds computes fan-in/fan-out with custom thresholds.
func computeFanIOWithThresholds(graph *ModuleGraph, t fanIOThresholds) []fanIOStats {
	if graph == nil {
		return nil
	}
	stats := make([]fanIOStats, 0, len(graph.Nodes))
	for _, node := range graph.Nodes {
		fanIn := len(graph.reverseDeps[node.Path])
		fanOut := len(graph.forwardDeps[node.Path])
		stats = append(stats, fanIOStats{
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

	all := computeFanIOWithThresholds(graph, defaultFanIOThresholds)

	// Sort by fan-in (most imported first).
	sortedByIn := make([]fanIOStats, len(all))
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
	sortedByOut := make([]fanIOStats, len(all))
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
