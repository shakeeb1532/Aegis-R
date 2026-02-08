package progression

import (
	"time"

	"aegisr/internal/state"
)

// ApplyDecay reduces confidence for older events and prunes outside the window.
func ApplyDecay(events []ProgressEventLike, now time.Time, window time.Duration) []ProgressEventLike {
	out := []ProgressEventLike{}
	for _, e := range events {
		age := now.Sub(e.GetTime())
		if window > 0 && age > window {
			continue
		}
		decay := 1.0
		if age > 0 {
			decay = 1.0 / (1.0 + age.Hours()/24.0)
		}
		e.SetConfidence(e.GetConfidence() * decay)
		out = append(out, e)
	}
	return out
}

// ApplyPositionDecay adjusts the current position confidence based on recency.
func ApplyPositionDecay(st *state.AttackState, now time.Time, window time.Duration) {
	if st == nil {
		return
	}
	if st.Position.UpdatedAt.IsZero() {
		return
	}
	age := now.Sub(st.Position.UpdatedAt)
	if window > 0 && age > window {
		st.Position.Confidence = 0
		return
	}
	decay := 1.0
	if age > 0 {
		decay = 1.0 / (1.0 + age.Hours()/24.0)
	}
	st.Position.Confidence = st.Position.Confidence * decay
}

// ProgressEventLike abstracts state.ProgressEvent for decay without import cycles.
type ProgressEventLike interface {
	GetTime() time.Time
	GetConfidence() float64
	SetConfidence(v float64)
}
