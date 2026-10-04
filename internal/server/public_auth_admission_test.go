// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/auth/admission"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// publicAuthBudget is the per-client budget these tests run under: every
// profile's default (TestPublicAuthBudgetIsTheProfileDefault).
const publicAuthBudget = 10

// managementStack serves the management plane as run.go builds it -- the base
// handler in front of the REST API, Connect and gRPC, over one real auth
// manager at the production bcrypt cost -- with each request's client address
// and entrypoint written into its request state the way the entrypoint
// middleware does, the address taken from testClientAddr.
type managementStack struct {
	url    string
	client *http.Client
	grpcc  gateonv1.ApiServiceClient
}

func newManagementStack(t *testing.T) *managementStack {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	t.Setenv("GATEON_PROFILE", "standard")
	dir := t.TempDir()
	mgr, err := auth.NewManager(filepath.Join(dir, "auth.db"), "12345678901234567890123456789012", logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.UpsertUser(&gateonv1.User{Username: "admin", Password: anonAdminPassword, Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	svc := &api.ApiService{Auth: mgr, Globals: config.NewGlobalRegistry(filepath.Join(dir, "global.json"))}
	mux := http.NewServeMux()
	mux.Handle(apiConnectHandler(svc))
	handlers.RegisterRESTHandlers(mux, svc, &handlers.Deps{AuthManager: mgr})
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(NewGRPCRBACInterceptor()))
	gateonv1.RegisterApiServiceServer(grpcServer, svc)
	t.Cleanup(grpcServer.Stop)
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	deps := setupTestDeps(mgr)
	deps.ProxyHandler = dispatch
	// The budget the standard profile gives, on a clock that does not move: a
	// request under the race detector takes long enough for the real one to earn
	// a token back mid-test.
	deps.PublicAuth = admission.NewSources(publicAuthBudget)
	frozen := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	deps.PublicAuth.SetClock(func() time.Time { return frozen })
	base := CreateBaseHandler(http.NotFoundHandler(), deps, nil, mux)
	entry := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs := &request.RequestState{EntryPointID: "management", ClientRemoteAddr: r.Header.Get(testClientAddr)}
		base.ServeHTTP(w, r.WithContext(request.WithState(r.Context(), rs)))
	})
	srv := httptest.NewUnstartedServer(entry)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	conn, err := grpc.NewClient(strings.TrimPrefix(srv.URL, "https://"),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &managementStack{url: srv.URL, client: srv.Client(), grpcc: gateonv1.NewApiServiceClient(conn)}
}

// post sends body to path from addr and returns the status and Retry-After.
func (s *managementStack) post(t *testing.T, path, addr, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.url+path, strings.NewReader(body))
	if err != nil {
		t.Error(err)
		return 0, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(testClientAddr, addr)
	resp, err := s.client.Do(req)
	if err != nil {
		t.Error(err)
		return 0, ""
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Retry-After")
}

// flood sends n requests to path from addr at once and returns how many were
// answered 429, how many were not, and how many 429s had no Retry-After.
func (s *managementStack) flood(t *testing.T, path, addr string, n int) (limited, served, noRetry int) {
	t.Helper()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			body := `{"username":"nobody-` + strconv.Itoa(i) + `","password":"a-guess-at-it"}`
			code, retry := s.post(t, path, addr, body)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case code == http.StatusTooManyRequests && retry == "":
				limited++
				noRetry++
			case code == http.StatusTooManyRequests:
				limited++
			default:
				served++
			}
		})
	}
	wg.Wait()
	return limited, served, noRetry
}

// TestOneClientCannotFloodThePublicAuthEndpoints is MGMT-N3: POST
// /v1/auth/2fa/enroll took the sign-in's password step -- a bcrypt at the
// production cost, unknown names included -- with no budget at all, and from
// one address answered 18,252 times in 75 s, never 429. Every public endpoint
// that can reach a password check now spends from one per-client budget, over
// REST and Connect alike: a burst of three times the budget from one address
// gets at most the budget served and the rest 429 with Retry-After.
func TestOneClientCannotFloodThePublicAuthEndpoints(t *testing.T) {
	s := newManagementStack(t)
	paths := []string{
		"/v1/auth/2fa/enroll",
		"/v1/login",
		"/gateon.v1.ApiService/Login",
		"/v1/auth/2fa/verify",
		"/v1/setup",
		"/v1/setup/test-db",
		"/gateon.v1.ApiService/Setup",
		// It checks the setup token (ADR 0057): unbudgeted, it was a way to
		// guess one that skipped Setup's budget.
		"/gateon.v1.ApiService/IsSetupRequired",
	}
	for i, path := range paths {
		// An address per path: the budget is the client's, shared by all of them.
		addr := "203.0.113." + strconv.Itoa(10+i)
		limited, served, noRetry := s.flood(t, path, addr, 3*publicAuthBudget)
		if served > publicAuthBudget || limited < 2*publicAuthBudget {
			t.Errorf("%s: %d of %d concurrent requests from one address were served and %d refused 429; "+
				"want at most %d served", path, served, 3*publicAuthBudget, limited, publicAuthBudget)
		}
		if noRetry > 0 {
			t.Errorf("%s: %d refusals without a Retry-After", path, noRetry)
		}
	}
}

// TestTheBudgetIsOnePerClientAcrossEndpointsAndTransports: spending it on one
// endpoint leaves nothing for another, the same /64 is the same client, and
// gRPC is refused as ResourceExhausted like REST and Connect.
func TestTheBudgetIsOnePerClientAcrossEndpointsAndTransports(t *testing.T) {
	s := newManagementStack(t)
	const client = "2001:db8:5:6::1"
	for range publicAuthBudget {
		s.post(t, "/v1/auth/2fa/enroll", client, `{"username":"nobody","password":"a-guess-at-it"}`)
	}
	if code, _ := s.post(t, "/v1/login", "2001:db8:5:6::99", `{"username":"admin","password":"x"}`); code != http.StatusTooManyRequests {
		t.Errorf("REST login from the same /64 after its budget went on enroll: %d, want 429", code)
	}
	if code, _ := s.post(t, "/gateon.v1.ApiService/Login", client, `{"username":"admin","password":"x"}`); code != http.StatusTooManyRequests {
		t.Errorf("Connect Login after the budget went on enroll: %d, want 429", code)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), strings.ToLower(testClientAddr), client)
	_, err := s.grpcc.Login(ctx, &gateonv1.LoginRequest{Username: "admin", Password: "x"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("gRPC Login after the budget went on enroll: %v, want ResourceExhausted", err)
	}
}

// TestGRPCLoginFloodFromOneClientIsRefused: the native gRPC Login, which
// reaches the same password step, is refused past the budget too.
func TestGRPCLoginFloodFromOneClientIsRefused(t *testing.T) {
	s := newManagementStack(t)
	ctx := metadata.AppendToOutgoingContext(context.Background(), strings.ToLower(testClientAddr), "203.0.113.77")
	var exhausted, other int
	for i := range 3 * publicAuthBudget {
		_, err := s.grpcc.Login(ctx, &gateonv1.LoginRequest{Username: "nobody-" + strconv.Itoa(i), Password: "a-guess-at-it"})
		if status.Code(err) == codes.ResourceExhausted {
			exhausted++
		} else {
			other++
		}
	}
	if other > publicAuthBudget || exhausted < 2*publicAuthBudget {
		t.Errorf("gRPC: %d answered with something other than ResourceExhausted, %d ResourceExhausted, of %d from one client; want at most %d",
			other, exhausted, 3*publicAuthBudget, publicAuthBudget)
	}
}

// TestTheOwnerSignsInWhileOneAddressFloods: an address that has spent its
// budget, and keeps sending, costs nobody else theirs -- the owner signs in
// from their own address over REST and gRPC.
func TestTheOwnerSignsInWhileOneAddressFloods(t *testing.T) {
	s := newManagementStack(t)
	const attacker, owner = "203.0.113.9", "198.51.100.7"
	s.flood(t, "/v1/auth/2fa/enroll", attacker, 3*publicAuthBudget)
	s.flood(t, "/v1/login", attacker, 3*publicAuthBudget)
	if code, _ := s.post(t, "/v1/login", owner,
		`{"username":"admin","password":"`+anonAdminPassword+`"}`); code != http.StatusOK {
		t.Errorf("the owner's REST sign-in during the flood: %d, want 200", code)
	}
	if err := grpcLogin(s.grpcc, owner, anonAdminPassword); err != nil {
		t.Errorf("the owner's gRPC sign-in during the flood: %v", err)
	}
}

// TestPublicAuthBudgetIsTheProfileDefault pins what the tests above assume,
// and that a base handler given no budget still has one: nil is the
// profile's budget, never none.
func TestPublicAuthBudgetIsTheProfileDefault(t *testing.T) {
	for _, tier := range []config.Tier{config.TierMinimal, config.TierStandard, config.TierEnterprise} {
		if got := config.DefaultsFor(tier).AuthAttemptsPerMinute; got != publicAuthBudget {
			t.Errorf("%s: AuthAttemptsPerMinute %d, these tests assume %d", tier, got, publicAuthBudget)
		}
	}
	t.Setenv("GATEON_PROFILE", "standard")
	t.Setenv(admission.AttemptsPerMinuteEnv, "")
	handler := CreateBaseHandler(http.NotFoundHandler(), setupTestDeps(auth.NewHolder(nil)), nil, http.NewServeMux())
	var limited int
	for range 3 * publicAuthBudget {
		r := managementRequest(http.MethodPost, "/v1/auth/2fa/enroll")
		r = r.WithContext(request.WithState(r.Context(), &request.RequestState{
			EntryPointID: "management", ClientRemoteAddr: "203.0.113.5",
		}))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, r)
		if rr.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited < 2*publicAuthBudget-1 {
		t.Errorf("a base handler built with no PublicAuth refused %d of %d from one client; want the default budget enforced",
			limited, 3*publicAuthBudget)
	}
}

// TestAFullGateIsAnswered429OverEveryTransport: clients each well within
// their budget, together more than the gate's one slot, sign in at once. The
// ones the gate turns away are told to retry -- 429 with Retry-After over
// REST, ResourceExhausted over gRPC -- and none is answered as a failure (5xx,
// Unknown) or as a wrong password, because nothing was checked.
func TestAFullGateIsAnswered429OverEveryTransport(t *testing.T) {
	t.Setenv(admission.HashConcurrencyEnv, "1")
	s := newManagementStack(t)
	const clients = 24
	var mu sync.Mutex
	rest, grpcBusy := map[int]int{}, map[codes.Code]int{}
	var noRetry int
	var wg sync.WaitGroup
	for i := range clients {
		wg.Go(func() {
			code, retry := s.post(t, "/v1/auth/2fa/enroll", "198.51.100."+strconv.Itoa(i+1),
				`{"username":"nobody","password":"a-guess-at-it"}`)
			ctx := metadata.AppendToOutgoingContext(context.Background(), strings.ToLower(testClientAddr),
				"192.0.2."+strconv.Itoa(i+1))
			_, err := s.grpcc.Login(ctx, &gateonv1.LoginRequest{Username: "nobody", Password: "a-guess-at-it"})
			mu.Lock()
			defer mu.Unlock()
			rest[code]++
			grpcBusy[status.Code(err)]++
			if code == http.StatusTooManyRequests && retry != "1" {
				noRetry++
			}
		})
	}
	wg.Wait()
	t.Logf("REST %v, gRPC %v", rest, grpcBusy)
	if rest[http.StatusTooManyRequests] == 0 || rest[http.StatusTooManyRequests]+rest[http.StatusUnauthorized] != clients {
		t.Errorf("REST enroll at once from %d clients, gate of 1: %v; want only 401 and 429, some 429", clients, rest)
	}
	if noRetry > 0 {
		t.Errorf("%d busy refusals without Retry-After: 1", noRetry)
	}
	if grpcBusy[codes.ResourceExhausted] == 0 || grpcBusy[codes.ResourceExhausted]+grpcBusy[codes.Unknown] != clients {
		// A wrong password is Unknown over gRPC: ApiService returns it unconverted.
		t.Errorf("gRPC Login at once from %d clients, gate of 1: %v; want ResourceExhausted for some", clients, grpcBusy)
	}
}
