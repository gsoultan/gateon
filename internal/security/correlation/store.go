package correlation

import "sync"

// DefaultIncidentStore is the process-wide store of recent correlated incidents.
// The threat pipeline's OnIncident callback records into it and the REST API
// reads snapshots from it, mirroring the package-level broadcaster pattern used
// for raw threats. It is sized for a useful operator window without unbounded
// growth; older incidents are evicted as new ones arrive.
var DefaultIncidentStore = NewIncidentStore(512)

// IncidentStore is a thread-safe, bounded, newest-first ring of correlated
// incidents. It keeps only the most recent maxLen incidents in memory (incidents
// are also logged and optionally shipped to a SIEM, which is the durable record);
// this store exists so the gateway can surface them in its own UI/API without an
// external SIEM.
type IncidentStore struct {
	mu     sync.RWMutex
	buf    []Incident
	maxLen int
	total  uint64 // lifetime count of recorded incidents
}

// NewIncidentStore returns a store retaining up to maxLen recent incidents.
// A non-positive maxLen is floored to 1.
func NewIncidentStore(maxLen int) *IncidentStore {
	if maxLen < 1 {
		maxLen = 1
	}
	return &IncidentStore{maxLen: maxLen}
}

// Add records an incident at the front (newest-first), evicting the oldest when
// the buffer is full.
func (s *IncidentStore) Add(inc Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	// Prepend newest-first.
	s.buf = append(s.buf, Incident{})
	copy(s.buf[1:], s.buf)
	s.buf[0] = inc
	if len(s.buf) > s.maxLen {
		s.buf = s.buf[:s.maxLen]
	}
}

// List returns up to limit most-recent incidents (newest first). A non-positive
// limit returns all retained incidents. The returned slice is a copy.
func (s *IncidentStore) List(limit int) []Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.buf)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Incident, n)
	copy(out, s.buf[:n])
	return out
}

// Len returns the number of incidents currently retained.
func (s *IncidentStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.buf)
}

// TotalSeen returns the lifetime count of incidents recorded (including evicted).
func (s *IncidentStore) TotalSeen() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.total
}
