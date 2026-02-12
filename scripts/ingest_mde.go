package main

import (
	"encoding/json"
	"fmt"
	"os"

	"aman/internal/integration"
	"aman/internal/ops"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: ingest_mde <file> <kind>")
		os.Exit(2)
	}
	path := os.Args[1]
	kind := os.Args[2]
	if !ops.IsSafePath(path) {
		fmt.Fprintln(os.Stderr, "invalid path")
		os.Exit(2)
	}
	// #nosec G304 - path validated via IsSafePath
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	events, err := integration.IngestEvents(raw, integration.IngestOptions{Schema: integration.SchemaMDE, Kind: kind})
	if err != nil {
		panic(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(events)
}
