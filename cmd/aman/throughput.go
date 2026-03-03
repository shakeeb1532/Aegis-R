package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"runtime"
	"sort"
	"time"

	"aman/internal/core"
	"aman/internal/env"
	"aman/internal/logic"
	"aman/internal/ops"
	"aman/internal/sim"
	"aman/internal/state"
	"aman/internal/validate"
)

type throughputReport struct {
	DurationSeconds float64 `json:"duration_seconds"`
	Iterations      int     `json:"iterations"`
	EventsPerBatch  int     `json:"events_per_batch"`
	EventsTotal     int     `json:"events_total"`
	AvgLatencyMs    float64 `json:"avg_latency_ms"`
	P50LatencyMs    float64 `json:"p50_latency_ms"`
	P90LatencyMs    float64 `json:"p90_latency_ms"`
	P99LatencyMs    float64 `json:"p99_latency_ms"`
	GCCount         uint32  `json:"gc_count"`
	GCPauseTotalMs  float64 `json:"gc_pause_total_ms"`
	GCPauseAvgMs    float64 `json:"gc_pause_avg_ms"`
}

func handleThroughputBench(args []string) {
	fs := flag.NewFlagSet("system throughput-bench", flag.ExitOnError)
	eventsCount := fs.Int("events", 10000, "events per batch")
	duration := fs.Duration("duration", 60*time.Second, "benchmark duration")
	rulesPath := fs.String("rules", "data/rules.json", "rules json")
	rulesExtra := fs.String("rules-extra", "", "optional extra rules json")
	envPath := fs.String("env", "data/env.json", "environment json")
	outPath := fs.String("out", "", "output file (optional)")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *eventsCount <= 0 {
		fatal(errors.New("events must be > 0"))
	}
	if *duration <= 0 {
		fatal(errors.New("duration must be > 0"))
	}

	rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
	if err != nil {
		fatal(err)
	}
	if err := validate.Rules(rules); err != nil {
		fatal(validate.Must(err))
	}
	environment, err := env.Load(*envPath)
	if err != nil {
		fatal(err)
	}
	if err := validate.Environment(environment); err != nil {
		fatal(validate.Must(err))
	}
	cfg, err := ops.LoadConfig("data/ops.json")
	if err != nil {
		fatal(err)
	}
	events := sim.Synthetic(42, *eventsCount)

	runtime.GC()
	var msStart runtime.MemStats
	runtime.ReadMemStats(&msStart)

	start := time.Now()
	deadline := start.Add(*duration)
	latencies := make([]time.Duration, 0, 1024)
	iterations := 0
	for time.Now().Before(deadline) {
		iterStart := time.Now()
		st := state.New()
		_ = core.AssessWithMetrics(events, rules, environment, st, nil, cfg.StrictMode)
		latencies = append(latencies, time.Since(iterStart))
		iterations++
	}

	var msEnd runtime.MemStats
	runtime.ReadMemStats(&msEnd)

	report := buildThroughputReport(latencies, iterations, *eventsCount, msStart, msEnd, time.Since(start))
	if *outPath == "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		outln(string(data))
		return
	}
	if !ops.IsSafePath(*outPath) {
		fatal(os.ErrInvalid)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*outPath, data, 0600); err != nil {
		fatal(err)
	}
	outln("Throughput report written: " + *outPath)
}

func buildThroughputReport(latencies []time.Duration, iterations int, eventsPerBatch int, msStart, msEnd runtime.MemStats, elapsed time.Duration) throughputReport {
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(float64(len(latencies)-1) * p)
		return float64(latencies[idx].Milliseconds())
	}
	totalLatency := time.Duration(0)
	for _, l := range latencies {
		totalLatency += l
	}
	avg := 0.0
	if len(latencies) > 0 {
		avg = float64(totalLatency.Milliseconds()) / float64(len(latencies))
	}
	gcCount := msEnd.NumGC - msStart.NumGC
	gcPause := msEnd.PauseTotalNs - msStart.PauseTotalNs
	gcPauseMs := float64(gcPause) / 1e6
	gcPauseAvg := 0.0
	if gcCount > 0 {
		gcPauseAvg = gcPauseMs / float64(gcCount)
	}
	return throughputReport{
		DurationSeconds: elapsed.Seconds(),
		Iterations:      iterations,
		EventsPerBatch:  eventsPerBatch,
		EventsTotal:     iterations * eventsPerBatch,
		AvgLatencyMs:    avg,
		P50LatencyMs:    pct(0.50),
		P90LatencyMs:    pct(0.90),
		P99LatencyMs:    pct(0.99),
		GCCount:         gcCount,
		GCPauseTotalMs:  gcPauseMs,
		GCPauseAvgMs:    gcPauseAvg,
	}
}
