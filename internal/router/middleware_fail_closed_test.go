// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// stubMiddlewareStore serves one middleware config by name.
type stubMiddlewareStore struct {
	mws map[string]*gateonv1.Middleware
}

func (s *stubMiddlewareStore) Get(_ context.Context, id string) (*gateonv1.Middleware, bool) {
	mw, ok := s.mws[id]
	return mw, ok
}

func (s *stubMiddlewareStore) List(context.Context) []*gateonv1.Middleware { return nil }
func (s *stubMiddlewareStore) ListPaginated(context.Context, int32, int32, string) ([]*gateonv1.Middleware, int32) {
	return nil, 0
}
func (s *stubMiddlewareStore) All(context.Context) map[string]*gateonv1.Middleware { return s.mws }
func (s *stubMiddlewareStore) Update(context.Context, *gateonv1.Middleware) error {
	return nil
}
func (s *stubMiddlewareStore) Delete(context.Context, string) error { return nil }

// TestRouteRefusesWhenASecurityMiddlewareCannotBeBuilt is the regression guard
// for a route quietly serving without a control it was configured to have.
//
// The build loop used to `continue` on a Create error with nothing logged, and
// route chains are cached until invalidated -- so an `auth` middleware missing
// its secret, or an `oidc` one whose IdP discovery failed at startup, left the
// route serving unauthenticated while the dashboard still listed the
// middleware as attached. A transient failure was baked in permanently.
func TestRouteRefusesWhenASecurityMiddlewareCannotBeBuilt(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // 418 == reached the origin
	})

	// "auth" with no configuration at all: Factory.Create returns an error.
	store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{
		"broken-auth": {Id: "broken-auth", Name: "broken-auth", Type: "auth"},
	}}
	rt := &gateonv1.Route{Id: "r1", Name: "r1", Middlewares: []string{"broken-auth"}}

	h := ApplyRouteMiddlewares(backend, rt, nil, store, nil, nil, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/private", nil))

	if rec.Code == http.StatusTeapot {
		t.Error("the request reached the origin on a route whose auth middleware " +
			"failed to build; the route serves unauthenticated and the chain is " +
			"cached, so the failure persists")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// TestRouteRefusesWhenASecurityMiddlewareIsMissing covers the other silent
// branch: the route names a middleware that is not in the store at all, which
// is what a rename or a delete leaves behind.
func TestRouteRefusesWhenASecurityMiddlewareIsMissing(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{}}
	rt := &gateonv1.Route{Id: "r1", Name: "r1", Middlewares: []string{"deleted-auth"}}

	h := ApplyRouteMiddlewares(backend, rt, nil, store, nil, nil, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/private", nil))

	if rec.Code == http.StatusTeapot {
		t.Error("a route naming a middleware that does not exist served the " +
			"origin anyway; deleting a middleware silently unprotects every " +
			"route that referenced it")
	}
}

// TestRouteStillServesWhenACosmeticMiddlewareFails keeps the distinction
// honest. Failing closed on everything would turn a broken header rewrite into
// an outage, which is not a trade worth making.
func TestRouteStillServesWhenACosmeticMiddlewareFails(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	// "retry" with a config that cannot parse.
	store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{
		"bad-retry": {
			Id: "bad-retry", Name: "bad-retry", Type: "retry",
			Config: map[string]string{"attempts": "not-a-number"},
		},
	}}
	rt := &gateonv1.Route{Id: "r1", Name: "r1", Middlewares: []string{"bad-retry"}}

	h := ApplyRouteMiddlewares(backend, rt, nil, store, nil, nil, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))

	if rec.Code == http.StatusServiceUnavailable {
		t.Error("a cosmetic middleware failing to build took the route out of " +
			"service; only security middlewares should do that")
	}
}

// TestEveryMiddlewareTypeIsClassified keeps the two lists honest against the
// factory. A type in neither list defaults to security and so takes a route
// out of service when it fails to build -- safe, but a surprise if nobody
// decided it. A type in both is a contradiction.
//
// The factory's switch is the source of truth; this reads it rather than
// restating it, so adding a case there without classifying it fails here.
func TestEveryMiddlewareTypeIsClassified(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "middleware", "factory.go"))
	if err != nil {
		t.Fatalf("read factory: %v", err)
	}

	cases := regexp.MustCompile(`(?m)^\tcase "([a-z_]+)"`).FindAllStringSubmatch(string(src), -1)
	if len(cases) < 20 {
		t.Fatalf("found only %d middleware cases; the pattern no longer matches "+
			"the factory and this test is not checking anything", len(cases))
	}

	for _, m := range cases {
		name := m[1]
		_, sec := securityMiddlewareTypes[name]
		_, cos := cosmeticMiddlewareTypes[name]
		switch {
		case sec && cos:
			t.Errorf("%q is in both lists; it cannot be both", name)
		case !sec && !cos:
			t.Errorf("%q is in neither list, so it defaults to failing closed. "+
				"That may be right, but decide it explicitly", name)
		}
	}
}
