// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fakeProvider records what it was asked to resolve.
type fakeProvider struct {
	gotTarget string
	err       error
}

func (f *fakeProvider) Resolve(_ context.Context, target string) ([]*gateonv1.Target, error) {
	f.gotTarget = target
	if f.err != nil {
		return nil, f.err
	}
	return []*gateonv1.Target{{Url: "http://10.0.0.1:80", Weight: 1, Protocol: "http"}}, nil
}

func TestNewResolverRegistersEveryDocumentedScheme(t *testing.T) {
	t.Parallel()

	r := NewResolver()
	for _, scheme := range []string{"dns", "consul", "etcd", "mdns", "eureka", "zk"} {
		if _, ok := r.providers[scheme]; !ok {
			t.Errorf("scheme %q has no provider, so any route configured with it "+
				"fails at resolve time rather than at config time", scheme)
		}
	}
}

func TestResolveDispatchesOnScheme(t *testing.T) {
	t.Parallel()

	fake := &fakeProvider{}
	r := &Resolver{providers: map[string]Provider{"dns": fake}}

	got, err := r.Resolve(context.Background(), "dns:api.svc.local")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d targets, want 1", len(got))
	}
	if fake.gotTarget != "api.svc.local" {
		t.Errorf("provider received target %q, want %q", fake.gotTarget, "api.svc.local")
	}
}

// TestResolveKeepsColonsInTheTarget matters for any scheme whose target is
// itself host:port -- splitting on every colon would truncate it.
func TestResolveKeepsColonsInTheTarget(t *testing.T) {
	t.Parallel()

	fake := &fakeProvider{}
	r := &Resolver{providers: map[string]Provider{"etcd": fake}}

	if _, err := r.Resolve(context.Background(), "etcd:host:2379/services/api"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "host:2379/services/api"; fake.gotTarget != want {
		t.Errorf("provider received %q, want %q", fake.gotTarget, want)
	}
}

func TestResolveRejectsMalformedURLs(t *testing.T) {
	t.Parallel()

	r := NewResolver()
	for _, tc := range []struct {
		name, url, wantSubstr string
	}{
		{"no scheme separator", "justahostname", "invalid discovery URL"},
		{"empty string", "", "invalid discovery URL"},
		{"unknown scheme", "nosuchscheme:target", "unsupported discovery scheme"},
		{"empty scheme", ":target", "unsupported discovery scheme"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := r.Resolve(context.Background(), tc.url)
			if err == nil {
				t.Fatalf("Resolve(%q) returned no error", tc.url)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("Resolve(%q) error = %q, want it to mention %q",
					tc.url, err, tc.wantSubstr)
			}
		})
	}
}

func TestResolvePropagatesProviderErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("backend registry unreachable")
	r := &Resolver{providers: map[string]Provider{"consul": &fakeProvider{err: sentinel}}}

	_, err := r.Resolve(context.Background(), "consul:api")
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want it to wrap %v; a discovery failure that is "+
			"swallowed looks like a service with no backends", err, sentinel)
	}
}
