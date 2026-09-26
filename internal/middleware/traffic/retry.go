// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// RetryConfig defines the configuration for the retry middleware.
type RetryConfig struct {
	Attempts        int
	InitialInterval time.Duration
}

const (
	// retryMaxBody is the largest request body kept for replay. A larger one is
	// sent once: holding it would put an attacker-sized buffer on every request.
	retryMaxBody = 64 << 10
	// defaultRetryInterval is the first backoff when none is configured.
	defaultRetryInterval = 100 * time.Millisecond
	// maxRetryInterval caps the doubling backoff.
	maxRetryInterval = 2 * time.Second
)

// Retry re-sends a request whose attempt failed at the gateway -- the backend
// refused or reset the connection, or timed out, which the proxy answers 502,
// 503 or 504 -- up to Attempts times, backing off from InitialInterval.
//
// It used to forward every request once and stop, while the dashboard offered
// the middleware and the README advertised automatic retries.
//
// Only what is safe to send twice and possible to replay is retried: an
// idempotent method whose body, if any, fits retryMaxBody, and never an
// upgrade. The outcome is decided when an attempt writes its status: a
// retryable failure is discarded, anything else is passed through as it is
// written, so a successful response -- a stream included -- is never held.
func Retry(cfg RetryConfig) kind.Middleware {
	interval := cfg.InitialInterval
	if interval <= 0 {
		interval = defaultRetryInterval
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, replayable := retryableRequest(r, cfg.Attempts)
			if !replayable {
				next.ServeHTTP(w, r)
				return
			}
			serveWithRetries(next, w, r, retryPlan{attempts: cfg.Attempts, interval: interval, body: body})
		})
	}
}

type retryPlan struct {
	attempts int
	interval time.Duration
	body     []byte
}

func serveWithRetries(next http.Handler, w http.ResponseWriter, r *http.Request, p retryPlan) {
	wait := p.interval
	for attempt := 1; ; attempt++ {
		r.Body = io.NopCloser(bytes.NewReader(p.body))
		if attempt == p.attempts {
			next.ServeHTTP(w, r)
			return
		}
		aw := &attemptWriter{w: w, header: make(http.Header)}
		next.ServeHTTP(aw, r)
		if !aw.discarded {
			aw.commit(http.StatusOK)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, maxRetryInterval)
	}
}

// retryableRequest reports whether r may be retried and returns its body for
// replay. A body too large to keep is restored for the single attempt.
func retryableRequest(r *http.Request, attempts int) ([]byte, bool) {
	if attempts < 2 || !idempotent(r.Method) || r.Header.Get("Upgrade") != "" {
		return nil, false
	}
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, retryMaxBody+1))
	if err != nil || len(buf) > retryMaxBody {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
		return nil, false
	}
	_ = r.Body.Close()
	return buf, true
}

func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete, http.MethodTrace:
		return true
	}
	return false
}

func retryableStatus(code int) bool {
	return code == http.StatusBadGateway || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}

// attemptWriter decides an attempt's fate at its status line: a retryable
// failure is swallowed whole, anything else is committed to the client and
// streamed from then on.
type attemptWriter struct {
	w         http.ResponseWriter
	header    http.Header
	committed bool
	discarded bool
}

func (a *attemptWriter) Header() http.Header {
	if a.committed {
		return a.w.Header()
	}
	return a.header
}

func (a *attemptWriter) WriteHeader(code int) {
	if a.committed || a.discarded {
		return
	}
	if retryableStatus(code) {
		a.discarded = true
		return
	}
	a.commit(code)
}

func (a *attemptWriter) commit(code int) {
	if a.committed || a.discarded {
		return
	}
	a.committed = true
	dst := a.w.Header()
	for k, v := range a.header {
		dst[k] = v
	}
	a.w.WriteHeader(code)
}

func (a *attemptWriter) Write(b []byte) (int, error) {
	if a.discarded {
		return len(b), nil
	}
	a.commit(http.StatusOK)
	return a.w.Write(b)
}

// Flush forwards once the attempt is committed; a discarded attempt has
// nothing on the wire to flush.
func (a *attemptWriter) Flush() {
	if !a.committed {
		return
	}
	if f, ok := a.w.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the client's writer.
func (a *attemptWriter) Unwrap() http.ResponseWriter { return a.w }
