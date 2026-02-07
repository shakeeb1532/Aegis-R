package main

import (
  "encoding/json"
  "fmt"
  "os"

  "aegisr/internal/integration"
)

func main() {
  if len(os.Args) < 3 {
    fmt.Fprintln(os.Stderr, "usage: ingest_mde <file> <kind>")
    os.Exit(2)
  }
  path := os.Args[1]
  kind := os.Args[2]
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
