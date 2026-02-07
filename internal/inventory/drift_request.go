package inventory

import "time"

type DriftRequest struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Summary   string    `json:"summary"`
	DriftPath string    `json:"drift_path"`
	Counts    DriftCounts `json:"counts"`
}

type DriftCounts struct {
	AddedHosts      int `json:"added_hosts"`
	RemovedHosts    int `json:"removed_hosts"`
	AddedIdentities int `json:"added_identities"`
	RemovedIdentites int `json:"removed_identities"`
	AddedTrusts     int `json:"added_trusts"`
	RemovedTrusts   int `json:"removed_trusts"`
}

func NewDriftRequest(driftPath string, rep DriftReport) DriftRequest {
	return DriftRequest{
		ID:        "drift-" + time.Now().UTC().Format("20060102T150405Z"),
		CreatedAt: time.Now().UTC(),
		Summary:   "Environment drift detected",
		DriftPath: driftPath,
		Counts: DriftCounts{
			AddedHosts:      len(rep.AddedHosts),
			RemovedHosts:    len(rep.RemovedHosts),
			AddedIdentities: len(rep.AddedIdentities),
			RemovedIdentites: len(rep.RemovedIdentites),
			AddedTrusts:     len(rep.AddedTrusts),
			RemovedTrusts:   len(rep.RemovedTrusts),
		},
	}
}
