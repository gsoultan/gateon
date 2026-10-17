// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A management stream was authorized once, when it opened. The log WebSocket
// and the event streams then ran until the client left or the stream lifetime
// cap ended them -- up to twelve hours, past the eight-hour token -- so a
// sign-out, a disabled account or a demotion left every open stream reading
// the system log and the live security events (ADR 0077). Each now re-runs
// the request's own check on a clock, and ends when it no longer holds.

// streamBound bounds every wait in these tests; nothing here waits for it
// unless the stream failed to end.
const streamBound = 5 * time.Second

// streamFixture is a management plane with one signed-in operator: a real
// auth.Manager, the handlers behind PasetoAuth as the base handler puts them,
// and a re-check clock the test drives.
type streamFixture struct {
	mgr   *auth.Manager
	user  *gateonv1.User
	token string
	ticks chan time.Time
	url   string
}

func newStreamFixture(t *testing.T) *streamFixture {
	t.Helper()
	mgr, err := auth.NewManager(filepath.Join(t.TempDir(), "auth.db"),
		"0123456789abcdef0123456789abcdef", logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.UpsertUser(&gateonv1.User{Username: "ops", Password: "correct-horse", Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	token, user, err := mgr.Authenticate("ops", "correct-horse", "127.0.0.1")
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	f := &streamFixture{mgr: mgr, user: user, token: token, ticks: make(chan time.Time)}
	d := &Deps{AuthManager: mgr, streamTicks: func() (<-chan time.Time, func()) { return f.ticks, func() {} }}
	mux := http.NewServeMux()
	registerDiagnosticHandlers(mux, nil, d)
	RegisterWatchHandler(mux, d)
	srv := httptest.NewServer(middleware.PasetoAuth(mgr, middleware.AuthBaseConfig{})(mux))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// tick advances the re-check clock once and reports whether a stream was
// there to take it.
func (f *streamFixture) tick() bool {
	select {
	case f.ticks <- time.Now():
		return true
	case <-time.After(streamBound):
		return false
	}
}

// openEvents opens the /v1/watch event stream with the session token, and
// returns once its re-check clock has taken a tick -- the stream is open and
// being watched -- with a channel closed when the stream has ended. The
// response head is not waited for: the stream sends it with its first event.
func (f *streamFixture) openEvents(t *testing.T) <-chan struct{} {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.url+"/v1/watch", nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}()
	if !f.tick() {
		t.Fatal("the event stream of a signed-in user never started re-checking it")
	}
	return ended
}

// ends reports whether ended closes within streamBound.
func ends(ended <-chan struct{}) bool {
	select {
	case <-ended:
		return true
	case <-time.After(streamBound):
		return false
	}
}

// revocations are the three ways an operator ends a session.
var revocations = map[string]func(*streamFixture) error{
	"signed out": func(f *streamFixture) error { return f.mgr.EndSessions(f.user.Id) },
	"disabled":   func(f *streamFixture) error { return f.mgr.SetUserDisabled(f.user.Id, true) },
	"demoted": func(f *streamFixture) error {
		return f.mgr.UpsertUser(&gateonv1.User{Id: f.user.Id, Username: "ops", Role: auth.RoleViewer})
	},
}

func TestAnEventStreamEndsWhenItsSessionIsRevoked(t *testing.T) {
	for name, revoke := range revocations {
		t.Run(name, func(t *testing.T) {
			f := newStreamFixture(t)
			events := f.openEvents(t)
			if err := revoke(f); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			f.tick()
			if !ends(events) {
				t.Fatalf("/v1/watch was still streaming one re-check after its user was %s", name)
			}
		})
	}
}

func TestTheLogStreamEndsWhenItsSessionIsRevoked(t *testing.T) {
	for name, revoke := range revocations {
		t.Run(name, func(t *testing.T) {
			f := newStreamFixture(t)
			wsURL := "ws" + strings.TrimPrefix(f.url, "http") + "/v1/logs?auth=" + f.token
			conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				t.Fatalf("open /v1/logs: %v", err)
			}
			_ = resp.Body.Close()
			t.Cleanup(func() { _ = conn.Close() })
			if !f.tick() {
				t.Fatal("the log stream of a signed-in user never started re-checking it")
			}
			if err := revoke(f); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			f.tick()
			if !wsEnds(conn) {
				t.Fatalf("/v1/logs was still streaming one re-check after its user was %s", name)
			}
		})
	}
}

// wsEnds reports whether the server ends conn within streamBound: every read
// fails once it has, and log lines may arrive until then. A read that fails
// by running out of time means it had not.
func wsEnds(conn *websocket.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(streamBound))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			var ne net.Error
			return !errors.As(err, &ne) || !ne.Timeout()
		}
	}
}

// TestAValidSessionsEventStreamContinues: re-checks that find the session
// still good leave the stream open. A tick is taken only once the one before
// it has been checked, so each was answered and the stream was still there.
func TestAValidSessionsEventStreamContinues(t *testing.T) {
	f := newStreamFixture(t)
	events := f.openEvents(t)
	for i := range 3 {
		if !f.tick() {
			t.Fatalf("the stream of a valid session was gone by re-check %d", i+2)
		}
	}
	select {
	case <-events:
		t.Fatal("the stream of a valid session ended")
	default:
	}
}

// TestAStreamEndsWhenItsTokenExpires: a stream ends when the token that
// opened it expires, not at the next re-check and not at the lifetime cap.
// The verifier here accepts the token whatever its expiry, so only the
// expiry itself can end the stream.
func TestAStreamEndsWhenItsTokenExpires(t *testing.T) {
	claims := &auth.Claims{Role: auth.RoleAdmin, Expiration: time.Now().Add(-time.Second)}
	req := httptest.NewRequest(http.MethodGet, "/v1/watch", nil)
	req.Header.Set("Authorization", "Bearer expiring")
	req = req.WithContext(middleware.InjectContext(req.Context(), claims))
	ticks := make(chan time.Time)
	d := &Deps{
		AuthManager: testTokenVerifier{token: "expiring", claims: claims},
		streamTicks: func() (<-chan time.Time, func()) { return ticks, func() {} },
	}
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	d.streamGuard(req, diagnosticsRead).watch(ctx, cancel)
	select {
	case <-ctx.Done():
	case <-time.After(streamBound):
		t.Fatal("a stream whose token had expired was still open with no re-check due")
	}
}

// TestTheLogStreamEndsAtItsLifetimeCap: the log WebSocket is hijacked, so the
// listener's stream lifetime cap does not reach it; it carries its own.
func TestTheLogStreamEndsAtItsLifetimeCap(t *testing.T) {
	f := newStreamFixture(t)
	d := &Deps{AuthManager: f.mgr, streamTicks: func() (<-chan time.Time, func()) { return f.ticks, func() {} }}
	logs := &logStream{deps: d, upgrader: logsUpgrader(nil), lifetime: time.Nanosecond}
	srv := httptest.NewServer(middleware.PasetoAuth(f.mgr, middleware.AuthBaseConfig{})(http.HandlerFunc(logs.serve)))
	t.Cleanup(srv.Close)
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/?auth="+f.token, nil)
	if err != nil {
		t.Fatalf("open the log stream: %v", err)
	}
	_ = resp.Body.Close()
	t.Cleanup(func() { _ = conn.Close() })
	if !wsEnds(conn) {
		t.Fatal("the log stream outlived its lifetime cap")
	}
}

// TestTheLogHandshakeHasATimeout: gorilla clears the connection's deadlines
// at the upgrade, so the handshake is bounded by the upgrader itself.
func TestTheLogHandshakeHasATimeout(t *testing.T) {
	if up := logsUpgrader(nil); up.HandshakeTimeout <= 0 {
		t.Fatal("the log WebSocket's handshake has no timeout")
	}
}
