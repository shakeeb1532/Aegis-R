package logic

import "time"

const (
	confidenceFloor           = 0.10
	confidenceCeiling         = 0.95
	confidenceCoverageW       = 0.65
	confidenceRecencyW        = 0.20
	confidenceCorroborW       = 0.10
	confidenceHighSignalBoost = 0.08
	confidenceRecencySpan     = 7 * 24 * time.Hour
	confidenceNoTSRecency     = 0.30
)

type ReasonerConfig struct {
	Now              func() time.Time
	CausalMaxSetSize int
	OrderingJitter   time.Duration
}

func DefaultReasonerConfig() ReasonerConfig {
	return ReasonerConfig{
		Now:              func() time.Time { return time.Now().UTC() },
		CausalMaxSetSize: 2,
		OrderingJitter:   90 * time.Second,
	}
}

func sanitizeReasonerConfig(cfg ReasonerConfig) ReasonerConfig {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.CausalMaxSetSize < 1 {
		cfg.CausalMaxSetSize = 1
	}
	if cfg.CausalMaxSetSize > 3 {
		cfg.CausalMaxSetSize = 3
	}
	if cfg.OrderingJitter < 0 {
		cfg.OrderingJitter = 0
	}
	return cfg
}
