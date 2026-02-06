package ops

import "sync/atomic"

type Metrics struct {
	EventsIn     uint64
	RulesChecked uint64
	FindingsOut  uint64
}

func (m *Metrics) IncEvents(n int) {
	if n <= 0 {
		return
	}
	atomic.AddUint64(&m.EventsIn, uint64(n))
}

func (m *Metrics) IncRules(n int) {
	if n <= 0 {
		return
	}
	atomic.AddUint64(&m.RulesChecked, uint64(n))
}

func (m *Metrics) IncFindings(n int) {
	if n <= 0 {
		return
	}
	atomic.AddUint64(&m.FindingsOut, uint64(n))
}

func (m *Metrics) Snapshot() Metrics {
	return Metrics{
		EventsIn:     atomic.LoadUint64(&m.EventsIn),
		RulesChecked: atomic.LoadUint64(&m.RulesChecked),
		FindingsOut:  atomic.LoadUint64(&m.FindingsOut),
	}
}
