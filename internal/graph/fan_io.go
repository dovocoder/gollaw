package graph

// fanIOStats holds fan-in/fan-out metrics for a single package.
type fanIOStats struct {
	Package        string
	FanIn          int
	FanOut         int
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
