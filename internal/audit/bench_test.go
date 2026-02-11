//go:build cgo

package audit

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"aegisr/internal/compress"
)

func sampleArtifact() Artifact {
	return Artifact{
		ID:        "artifact-1",
		CreatedAt: time.Now().UTC(),
		Summary:   "Causal feasibility evaluated",
		Findings:  []string{"TA0001 feasible", "TA0004 incomplete"},
		Reasoning: []string{"Reason line 1", "Reason line 2"},
		Metadata: map[string]string{
			"rules_source": "data/rules.json",
			"env_source":   "data/env.json",
		},
	}
}

func BenchmarkAppendLogPlain(b *testing.B) {
	path := "/tmp/aegis_audit_plain.log"
	_ = os.Remove(path)
	art := sampleArtifact()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := AppendLog(path, art); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAppendLogLZ4(b *testing.B) {
	path := "/tmp/aegis_audit_lz4.log.lz4"
	_ = os.Remove(path)
	art := sampleArtifact()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := AppendLog(path, art); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuditCompressionRatio(b *testing.B) {
	art := sampleArtifact()
	plain, err := json.Marshal(art)
	if err != nil {
		b.Fatal(err)
	}
	compressed, err := compress.Compress(plain)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(len(compressed))/float64(len(plain)), "ratio")
	b.ReportMetric(float64(len(plain))/float64(len(compressed)), "x")
	b.SetBytes(int64(len(plain)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = plain[0]
		_ = compressed[0]
	}
}
