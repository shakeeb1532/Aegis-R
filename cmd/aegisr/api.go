package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"aegisr/internal/uiapi"
)

func handleServeAPI(args []string) {
	fs := flag.NewFlagSet("serve-api", flag.ExitOnError)
	addr := fs.String("addr", ":8081", "listen address")
	reportPath := fs.String("report", "data/report.json", "report json path")
	auditPath := fs.String("audit", "data/audit.log", "audit log path")
	approvalsPath := fs.String("approvals", "data/approvals.log", "approvals log path")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	srv := uiapi.NewServer(*reportPath, *auditPath, *approvalsPath)
	log.Printf("UI API listening on %s", *addr)
	if err := http.ListenAndServe(*addr, srv.Routes()); err != nil {
		log.Fatalf("serve-api: %v", err)
	}
}
