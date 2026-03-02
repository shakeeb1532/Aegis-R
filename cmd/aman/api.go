package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"aman/internal/ops"
	"aman/internal/uiapi"
)

func handleServeAPI(args []string) {
	fs := flag.NewFlagSet("serve-api", flag.ExitOnError)
	addr := fs.String("addr", ":8081", "listen address")
	reportPath := fs.String("report", "data/report.json", "report json path")
	auditPath := fs.String("audit", "data/audit.log", "audit log path")
	approvalsPath := fs.String("approvals", "data/approvals.log", "approvals log path")
	feedbackPath := fs.String("feedback-out", "data/feedback.jsonl", "feedback jsonl output")
	constraintsPath := fs.String("constraints", "data/constraints.json", "tuning constraints json")
	requireKey := fs.Bool("require-key", true, "require API key (AMAN_UI_API_KEY)")
	pilotKpisOut := fs.String("pilot-kpis-out", "", "write pilot KPI snapshots to jsonl")
	pilotKpisInterval := fs.Duration("pilot-kpis-interval", 10*time.Minute, "snapshot interval")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	apiKey := os.Getenv("AMAN_UI_API_KEY")
	if *requireKey && apiKey == "" {
		fmt.Fprintln(os.Stderr, "AMAN_UI_API_KEY is required when --require-key is enabled")
		os.Exit(1)
	}

	srv := uiapi.NewServer(uiapi.ServerOptions{
		ReportPath:      *reportPath,
		AuditPath:       *auditPath,
		ApprovalsPath:   *approvalsPath,
		FeedbackPath:    *feedbackPath,
		ConstraintsPath: *constraintsPath,
		RequireKey:      *requireKey,
		APIKey:          apiKey,
	})

	if *pilotKpisOut != "" {
		if !ops.IsSafePath(*pilotKpisOut) {
			fmt.Fprintln(os.Stderr, "pilot-kpis-out path is not safe")
			os.Exit(1)
		}
		if err := os.MkdirAll(filepath.Dir(*pilotKpisOut), 0755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		go startPilotKpiWriter(*reportPath, *pilotKpisOut, *pilotKpisInterval)
	}

	log.Printf("UI API listening on %s", *addr)
	if err := http.ListenAndServe(*addr, srv.Routes()); err != nil {
		log.Fatalf("serve-api: %v", err)
	}
}

type pilotSnapshot struct {
	SnapshotAt string                  `json:"snapshot_at"`
	ReportPath string                  `json:"report_path"`
	Data       uiapi.PilotKpisResponse `json:"data"`
}

func startPilotKpiWriter(reportPath, outPath string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		writePilotSnapshot(reportPath, outPath)
		<-ticker.C
	}
}

func writePilotSnapshot(reportPath, outPath string) {
	kpis, err := uiapi.ComputePilotKpis(reportPath)
	if err != nil {
		log.Printf("pilot-kpis: %v", err)
		return
	}
	record := pilotSnapshot{
		SnapshotAt: time.Now().UTC().Format(time.RFC3339),
		ReportPath: reportPath,
		Data:       kpis,
	}
	data, err := json.Marshal(record)
	if err != nil {
		log.Printf("pilot-kpis: %v", err)
		return
	}
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("pilot-kpis: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		log.Printf("pilot-kpis: %v", err)
		return
	}
}
