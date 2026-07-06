package reporter

import (
	"encoding/json"
	"testing"
)

func TestBuildReportUsesEmptyFindingsSlice(t *testing.T) {
	report := BuildReport("test", []string{"./..."}, []string{"security"}, CodebaseStats{}, nil)

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if string(raw["findings"]) != "[]" {
		t.Fatalf("findings JSON = %s, want []", raw["findings"])
	}
}
