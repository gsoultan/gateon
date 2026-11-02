// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"sync"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Every open /v1/diagnostics/watch stream computed its own GetDiagnostics on
// its own five-second ticker: three database reads and a dependency check
// per stream per tick, with nothing shared between two operators watching
// the same page. sharedDiagnostics computes it once per period for every
// stream: a stream whose tick finds a result younger than sharedDiagnosticsFor
// sends that, and streams that tick while it is being computed wait for the
// one computation rather than starting their own.
//
// The one-shot GET is not served from it: an operator who has just acted
// reads the state as it is now.
const sharedDiagnosticsFor = 4 * time.Second

type diagnosticsFunc func(context.Context, *gateonv1.GetDiagnosticsRequest) (*gateonv1.GetDiagnosticsResponse, error)

type sharedDiagnostics struct {
	compute diagnosticsFunc
	mu      sync.Mutex
	at      time.Time
	res     *gateonv1.GetDiagnosticsResponse
	// inflight is closed when the computation under way ends.
	inflight chan struct{}
}

func newSharedDiagnostics(compute diagnosticsFunc) *sharedDiagnostics {
	return &sharedDiagnostics{compute: compute}
}

// get returns a result no older than sharedDiagnosticsFor, computing one when
// needed. The result is shared between streams and is only ever read.
func (s *sharedDiagnostics) get(ctx context.Context) (*gateonv1.GetDiagnosticsResponse, error) {
	for {
		s.mu.Lock()
		if s.res != nil && time.Since(s.at) < sharedDiagnosticsFor {
			res := s.res
			s.mu.Unlock()
			return res, nil
		}
		if wait := s.inflight; wait != nil {
			s.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		s.inflight = done
		s.mu.Unlock()

		// Computed under a context of its own: the stream that started it may
		// end before it does, and the others waiting on it still want it.
		cctx, cancel := context.WithTimeout(context.Background(), sharedDiagnosticsFor)
		res, err := s.compute(cctx, &gateonv1.GetDiagnosticsRequest{})
		cancel()

		s.mu.Lock()
		if err == nil {
			s.res, s.at = res, time.Now()
		}
		s.inflight = nil
		close(done)
		s.mu.Unlock()
		return res, err
	}
}
