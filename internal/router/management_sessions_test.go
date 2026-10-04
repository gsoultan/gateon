// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// sessionVerifier accepts one token as a management session.
type sessionVerifier struct{ session string }

func (v sessionVerifier) VerifyToken(token string) (any, error) {
	if token == v.session {
		return struct{}{}, nil
	}
	return nil, errors.New("not a session")
}

// sessionAwareFinal stands in for the proxy handler: the route's final handler
// that knows the management plane's session check (ADR 0051).
type sessionAwareFinal struct{ v middleware.TokenVerifier }

func (sessionAwareFinal) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func (s sessionAwareFinal) ManagementSessions() middleware.TokenVerifier { return s.v }

// The route chain hands the final handler's session check to the middlewares
// that send credentials to another server, so forward auth withholds a
// management session even when one reaches it -- the third line behind the
// data-plane entry strip and the proxy strip. Without the hand-off, forward
// auth cannot recognise a session bearer and sends it to its auth server.
func TestTheRouteChainGivesForwardAuthTheManagementSessionCheck(t *testing.T) {
	const session = "v4.local.MGMT-SESSION"
	var mu sync.Mutex
	var seen []string
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Values("Authorization")...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer auth.Close()

	store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{
		"fa": {Id: "fa", Type: "forwardauth", Config: map[string]string{"address": auth.URL + "/check"}},
	}}
	rt := &gateonv1.Route{Id: "r", ServiceId: "svc", Rule: "PathPrefix(`/`)", Middlewares: []string{"fa"}}
	h := ApplyRouteMiddlewares(sessionAwareFinal{v: sessionVerifier{session: session}}, rt, nil, store, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "http://app.example/", nil)
	req.Header.Set("Authorization", "Bearer "+session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 && rec.Code != http.StatusOK {
		t.Fatalf("control: the request never reached forward auth (status %d), so this test would prove nothing", rec.Code)
	}
	for _, v := range seen {
		if strings.Contains(v, session) {
			t.Fatalf("forward auth sent the management session to its auth server: Authorization %q", v)
		}
	}
}
