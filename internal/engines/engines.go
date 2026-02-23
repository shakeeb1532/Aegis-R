package engines

type EngineSpec struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Purpose      string `json:"purpose"`
	RepoURL      string `json:"repo_url"`
	Integration  string `json:"integration"`
	Status       string `json:"status"`
	Notes        string `json:"notes,omitempty"`
	DocReference string `json:"doc_reference,omitempty"`
}

func Builtins() []EngineSpec {
	return []EngineSpec{
		{
			ID:          "blackbox-data",
			Name:        "Blackbox Data Engine",
			Purpose:     "High-efficiency storage and retrieval for large event/audit payloads.",
			RepoURL:     "https://github.com/shakeeb1532/blackbox-data",
			Integration: "Planned (external module)",
			Status:      "Not bundled",
			Notes:       "Keep as a separate engine; integrate via adapter once stable.",
			DocReference: "docs/engines.md",
		},
		{
			ID:          "time-travel-forensics",
			Name:        "Time Travel Forensics Engine",
			Purpose:     "Replay and diff historical states for incident forensics.",
			RepoURL:     "https://github.com/shakeeb1532/TimeTravel-Forensics",
			Integration: "Planned (external module)",
			Status:      "Not bundled",
			Notes:       "Keep as a separate engine; integrate via adapter once stable.",
			DocReference: "docs/engines.md",
		},
	}
}
