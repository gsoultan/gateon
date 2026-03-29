package telemetry

import (
	"sync"
	"time"
)

// CircuitState represents the possible states of a circuit breaker.
type CircuitState string

const (
	CircuitClosed   CircuitState = "CLOSED"
	CircuitOpen     CircuitState = "OPEN"
	CircuitHalfOpen CircuitState = "HALF-OPEN"
)

// CircuitBreakerEvent represents a state transition for a circuit breaker.
type CircuitBreakerEvent struct {
	Target    string       `json:"target"`
	State     CircuitState `json:"state"`
	Reason    string       `json:"reason"`
	Timestamp time.Time    `json:"timestamp"`
}

var (
	cbEvents   []CircuitBreakerEvent
	cbEventsMu sync.RWMutex
)

// RecordCircuitBreakerEvent logs a circuit breaker state transition.
// It maintains a ring buffer of the last 100 events.
func RecordCircuitBreakerEvent(target string, state CircuitState, reason string) {
	cbEventsMu.Lock()
	defer cbEventsMu.Unlock()
	cbEvents = append(cbEvents, CircuitBreakerEvent{
		Target:    target,
		State:     state,
		Reason:    reason,
		Timestamp: time.Now(),
	})
	if len(cbEvents) > 100 {
		cbEvents = cbEvents[len(cbEvents)-100:]
	}
}

// GetCircuitBreakerEvents returns all recorded circuit breaker events.
func GetCircuitBreakerEvents() []CircuitBreakerEvent {
	cbEventsMu.RLock()
	defer cbEventsMu.RUnlock()
	return append([]CircuitBreakerEvent(nil), cbEvents...)
}
