package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunNoisegraphQuickstart(t *testing.T) {
	dir := t.TempDir()
	decisions := filepath.Join(dir, "decisions.jsonl")
	eventsOut := filepath.Join(dir, "events.json")
	reportOut := filepath.Join(dir, "report.json")
	input := `{"ts":"2026-02-20T00:00:00Z","decision":"keep","risk":70,"reasons":["rate_anomaly"],"fingerprint":"fp-1","event":{"source":"host-a","template":"Failed password for *","entity":{"source":"host-a","user":"admin"}}}
{"ts":"2026-02-20T00:00:10Z","decision":"suppress","risk":12,"reasons":["known_baseline"],"fingerprint":"fp-2","event":{"source":"host-a","template":"Healthcheck OK","entity":{"source":"host-a"}}}
`
	if err := os.WriteFile(decisions, []byte(input), 0600); err != nil {
		t.Fatalf("write decisions: %v", err)
	}
	rulesPath, err := filepath.Abs("../../data/rules.json")
	if err != nil {
		t.Fatalf("abs rules path: %v", err)
	}
	rep, err := runNoisegraphQuickstart(decisions, eventsOut, reportOut, rulesPath, "", "keep,escalate", 0.2, 20)
	if err != nil {
		t.Fatalf("run quickstart: %v", err)
	}
	if rep.EventsCount != 1 {
		t.Fatalf("expected 1 event, got %d", rep.EventsCount)
	}
	if _, err := os.Stat(eventsOut); err != nil {
		t.Fatalf("missing events output: %v", err)
	}
	if _, err := os.Stat(reportOut); err != nil {
		t.Fatalf("missing report output: %v", err)
	}
}
