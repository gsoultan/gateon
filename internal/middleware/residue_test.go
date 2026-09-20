// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ADR-0002 moved the traffic, transform and security middlewares out of this
// package along with their tests, and what stayed behind is the part nobody had
// written tests for -- the factory's own surface, the chain plumbing, and the
// response-writer wrapper. Coverage fell from 63.1% to 58.0% because the tested
// code left, which is the ratchet pointing at a real gap rather than at the
// refactor.

// TestFactoryIsGRPCRoute pins a trust boundary. The route type decides whether
// the WAF's gRPC transport relaxations apply, and it must come from gateon's
// own route configuration -- a client that could name its own transport could
// ask for the relaxations. The comparison is deliberately forgiving about case
// and whitespace because the value comes from config written by hand.
func TestFactoryIsGRPCRoute(t *testing.T) {
	cases := map[string]bool{
		"grpc":    true,
		"gRPC":    true,
		"GRPC":    true,
		" grpc ":  true,
		"http":    false,
		"":        false,
		"grpcweb": false, // a different transport, not a sloppy spelling of this one
	}

	for routeType, want := range cases {
		t.Run("type="+routeType, func(t *testing.T) {
			f := NewFactory(nil, nil, nil, nil, ".")
			f.SetRouteType(routeType)
			if got := f.IsGRPCRoute(); got != want {
				t.Errorf("IsGRPCRoute() with routeType %q = %v, want %v", routeType, got, want)
			}
		})
	}
}

// TestFactoryValidateRejectsWhatCreateRejects is the property that makes
// Validate worth having: the dashboard calls it to check a middleware before
// saving it, so anything Create would refuse at request time has to be refused
// here, at configuration time. If the two ever disagree, an operator saves a
// configuration that the gateway then declines to build -- and finds out when
// the route stops working.
func TestFactoryValidateRejectsWhatCreateRejects(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())

	cases := []struct {
		name string
		mw   *gateonv1.Middleware
	}{
		{"unknown type", &gateonv1.Middleware{Type: "no-such-middleware"}},
		{"empty type", &gateonv1.Middleware{Type: ""}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vErr := f.Validate(tc.mw)
			_, cErr := f.Create(tc.mw, "")

			if (vErr == nil) != (cErr == nil) {
				t.Fatalf("Validate and Create disagree: Validate=%v, Create=%v. "+
					"An operator would save a configuration the gateway then "+
					"refuses to build", vErr, cErr)
			}
			if vErr == nil {
				t.Errorf("Validate accepted %+v; an unrecognised middleware type "+
					"saved into a route silently does nothing", tc.mw)
			}
		})
	}
}

// TestFactoryValidateAcceptsAWorkingMiddleware is the other half: a Validate
// that refused everything would satisfy the test above and be useless.
func TestFactoryValidateAcceptsAWorkingMiddleware(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	mw := &gateonv1.Middleware{
		Type:   "headers",
		Config: map[string]string{"set_response_X-Test": "1"},
	}
	if err := f.Validate(mw); err != nil {
		t.Errorf("Validate rejected a well-formed headers middleware: %v", err)
	}
}

// hijackRecorder is an httptest.ResponseRecorder that also implements the three
// optional interfaces, so a wrapper that forwards them can be told apart from
// one that merely claims to.
type hijackRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
	flushed  bool
	pushed   string
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, errors.New("hijacked")
}
func (h *hijackRecorder) Flush() { h.flushed = true }
func (h *hijackRecorder) Push(target string, _ *http.PushOptions) error {
	h.pushed = target
	return nil
}

// TestBodyRecorderForwardsOptionalInterfaces covers the wrapper the debug
// middleware puts in front of a response.
//
// Hijack is the one that has bitten this codebase before: a wrapper that does
// not forward it breaks every WebSocket upgrade on the route it sits on, which
// is what caused the "hijack failed" 500 on the Synology route. Flush breaks
// server-sent events the same way, silently -- the stream simply never arrives.
func TestBodyRecorderForwardsOptionalInterfaces(t *testing.T) {
	inner := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	rec := &bodyRecorder{ResponseWriter: inner, body: new(bytes.Buffer), maxSize: 8}

	if _, _, err := rec.Hijack(); err == nil || err.Error() != "hijacked" {
		t.Errorf("Hijack() = %v, want the inner writer's error; a wrapper that "+
			"does not forward Hijack breaks every WebSocket upgrade behind it", err)
	}
	if !inner.hijacked {
		t.Error("Hijack did not reach the inner ResponseWriter")
	}

	rec.Flush()
	if !inner.flushed {
		t.Error("Flush did not reach the inner ResponseWriter; server-sent " +
			"events behind this wrapper would never arrive")
	}

	if err := rec.Push("/style.css", nil); err != nil {
		t.Errorf("Push() = %v, want nil", err)
	}
	if inner.pushed != "/style.css" {
		t.Errorf("Push forwarded %q, want %q", inner.pushed, "/style.css")
	}
}

// TestBodyRecorderReportsUnsupportedRatherThanPanicking covers the other
// branch: an inner writer that implements none of the three. Returning
// ErrNotSupported is what lets net/http fall back; a panic here would take down
// the request goroutine.
func TestBodyRecorderReportsUnsupportedRatherThanPanicking(t *testing.T) {
	rec := &bodyRecorder{ResponseWriter: httptest.NewRecorder(), body: new(bytes.Buffer), maxSize: 8}

	if _, _, err := rec.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Errorf("Hijack() on a plain writer = %v, want http.ErrNotSupported", err)
	}
	if err := rec.Push("/x", nil); !errors.Is(err, http.ErrNotSupported) {
		t.Errorf("Push() on a plain writer = %v, want http.ErrNotSupported", err)
	}
	rec.Flush() // must not panic
}

// TestBodyRecorderCapsWhatItKeepsButNotWhatItSends is the bound on this
// wrapper. It exists to show a response body in the debugger, so it keeps a
// prefix -- but the client must still receive every byte the origin sent, and
// the buffer must not grow with the response.
func TestBodyRecorderCapsWhatItKeepsButNotWhatItSends(t *testing.T) {
	inner := httptest.NewRecorder()
	rec := &bodyRecorder{ResponseWriter: inner, body: new(bytes.Buffer), maxSize: 4}

	payload := []byte("0123456789")
	n, err := rec.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}

	if got := inner.Body.String(); got != string(payload) {
		t.Errorf("client received %q, want the whole payload %q; the recorder "+
			"must not truncate what it forwards", got, payload)
	}
	if got := rec.body.String(); got != "0123" {
		t.Errorf("recorder kept %q, want %q capped at maxSize", got, "0123")
	}

	// A second write past the cap keeps nothing more but still forwards.
	_, _ = rec.Write([]byte("abc"))
	if got := rec.body.String(); got != "0123" {
		t.Errorf("recorder grew to %q past its cap; the buffer would scale with "+
			"the response size", got)
	}
	if got := inner.Body.String(); got != "0123456789abc" {
		t.Errorf("client received %q, want every forwarded byte", got)
	}
}
