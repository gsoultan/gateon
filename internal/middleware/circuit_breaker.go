package middleware

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// CircuitBreakerConfig configures the circuit breaker middleware.
type CircuitBreakerConfig struct {
	ErrorThreshold float64       // Error rate threshold (0.0 to 1.0) to open the circuit
	MinRequests    int64         // Minimum requests in a window before the breaker can open
	WindowSize     time.Duration // Time window for error rate calculation
	SleepWindow    time.Duration // Time to stay in OPEN state before trying HALF-OPEN
	RouteID        string
}

type circuitBreakerState struct {
	mu        sync.RWMutex
	state     telemetry.CircuitState
	lastState time.Time
	requests  atomic.Int64
	errors    atomic.Int64
	lastReset time.Time
}

var (
	cbStates = make(map[string]*circuitBreakerState)
	cbMu     sync.Mutex
)

func getCBState(routeID string) *circuitBreakerState {
	cbMu.Lock()
	defer cbMu.Unlock()
	if s, ok := cbStates[routeID]; ok {
		return s
	}
	s := &circuitBreakerState{
		state:     telemetry.CircuitClosed,
		lastReset: time.Now(),
	}
	cbStates[routeID] = s
	return s
}

// CircuitBreaker returns a middleware that implements the circuit breaker pattern.
func CircuitBreaker(cfg CircuitBreakerConfig) Middleware {
	if cfg.WindowSize == 0 {
		cfg.WindowSize = 10 * time.Second
	}
	if cfg.SleepWindow == 0 {
		cfg.SleepWindow = 30 * time.Second
	}
	if cfg.ErrorThreshold == 0 {
		cfg.ErrorThreshold = 0.5
	}

	state := getCBState(cfg.RouteID)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state.mu.RLock()
			currState := state.state
			lastChange := state.lastState
			state.mu.RUnlock()

			if currState == telemetry.CircuitOpen {
				if time.Since(lastChange) > cfg.SleepWindow {
					// Transition to HALF-OPEN
					state.mu.Lock()
					if state.state == telemetry.CircuitOpen {
						state.state = telemetry.CircuitHalfOpen
						state.lastState = time.Now()
						telemetry.RecordCircuitBreakerEvent(cfg.RouteID, telemetry.CircuitHalfOpen, "sleep window expired")
					}
					state.mu.Unlock()
				} else {
					w.Header().Set("Retry-After", "30")
					httputil.WriteJSONError(w, http.StatusServiceUnavailable, "service unavailable (circuit open)", "")
					return
				}
			}

			// Capture status
			sw, ok := w.(*StatusResponseWriter)
			var pooled bool
			if !ok {
				sw = GetStatusResponseWriter(w)
				w = sw
				pooled = true
			}
			if pooled {
				defer PutStatusResponseWriter(sw)
			}

			state.requests.Add(1)
			next.ServeHTTP(sw, r)

			if sw.Status >= 500 {
				state.errors.Add(1)
			}

			// Check if we should trip the breaker
			state.checkBreaker(cfg)
		})
	}
}

func (s *circuitBreakerState) checkBreaker(cfg CircuitBreakerConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if now.Sub(s.lastReset) > cfg.WindowSize {
		// Reset window counters
		requests := s.requests.Swap(0)
		errors := s.errors.Swap(0)

		if s.state == telemetry.CircuitClosed && requests >= cfg.MinRequests {
			rate := float64(errors) / float64(requests)
			if rate >= cfg.ErrorThreshold {
				s.state = telemetry.CircuitOpen
				s.lastState = now
				telemetry.RecordCircuitBreakerEvent(cfg.RouteID, telemetry.CircuitOpen, "error rate exceeded threshold")
			}
		} else if s.state == telemetry.CircuitHalfOpen {
			if errors > 0 {
				s.state = telemetry.CircuitOpen
				s.lastState = now
				telemetry.RecordCircuitBreakerEvent(cfg.RouteID, telemetry.CircuitOpen, "error in half-open state")
			} else {
				s.state = telemetry.CircuitClosed
				s.lastState = now
				telemetry.RecordCircuitBreakerEvent(cfg.RouteID, telemetry.CircuitClosed, "recovered in half-open state")
			}
		}
		s.lastReset = now
	}
}
