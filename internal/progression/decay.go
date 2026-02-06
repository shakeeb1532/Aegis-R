package progression

import "time"

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

// ProgressEventLike abstracts state.ProgressEvent for decay without import cycles.
type ProgressEventLike interface {
	GetTime() time.Time
	GetConfidence() float64
	SetConfidence(v float64)
}
