package logic

import "time"

const (
	confidenceFeasibleHeuristic   = 0.85
	confidenceIncompleteHeuristic = 0.55
	confidenceLowHeuristic        = 0.40

	confidenceFloor       = 0.10
	confidenceCeiling     = 0.95
	confidenceCoverageW   = 0.65
	confidenceRecencyW    = 0.20
	confidenceCorroborW   = 0.10
	confidenceRecencySpan = 7 * 24 * time.Hour
	confidenceNoTSRecency = 0.30
)

type ReasonerConfig struct {
	Now                                    func() time.Time
	AllowProcessCreationAsCredentialAccess bool
	CausalMaxSetSize                       int
}

func DefaultReasonerConfig() ReasonerConfig {
	return ReasonerConfig{
		Now:                                    func() time.Time { return time.Now().UTC() },
		AllowProcessCreationAsCredentialAccess: false,
		CausalMaxSetSize:                       2,
	}
}
