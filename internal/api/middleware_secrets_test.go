// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security/secretmask"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The Connect and gRPC transports serve these same methods, and the RBAC table
// grants a viewer read on ResourceMiddlewares for the ListMiddlewares procedure.
//
// Authorization in this codebase was once enforced on the REST routes only while
// Connect and gRPC served the same methods unguarded. A redaction that covered
// one transport would be that defect again, so it is tested on this side rather
// than assumed to follow from the handler.

type fakeMwStore struct {
	config.MiddlewareStore
	mws []*gateonv1.Middleware
}

func (f *fakeMwStore) List(context.Context) []*gateonv1.Middleware { return f.mws }
func (f *fakeMwStore) Get(_ context.Context, id string) (*gateonv1.Middleware, bool) {
	for _, m := range f.mws {
		if m.Id == id {
			return m, true
		}
	}
	return nil, false
}
func (f *fakeMwStore) Update(_ context.Context, mw *gateonv1.Middleware) error {
	for i, m := range f.mws {
		if m.Id == mw.Id {
			f.mws[i] = mw
			return nil
		}
	}
	f.mws = append(f.mws, mw)
	return nil
}

func ctxAs(role string) context.Context {
	return context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: "u-1", Username: "u", Role: role})
}

// TestListMiddlewaresMasksSecretsOverConnect is the transport-parity test.
func TestListMiddlewaresMasksSecretsOverConnect(t *testing.T) {
	const signingKey = "SUPER-SECRET-SIGNING-KEY"
	store := &fakeMwStore{mws: []*gateonv1.Middleware{{
		Id: "jwt-1", Type: "jwt",
		Config: map[string]string{"secret": signingKey, "issuer": "https://idp"},
	}}}
	s := &ApiService{Middlewares: store}

	res, err := s.ListMiddlewares(ctxAs(auth.RoleViewer), &gateonv1.ListMiddlewaresRequest{})
	if err != nil {
		t.Fatalf("ListMiddlewares: %v", err)
	}
	if got := res.Middlewares[0].Config["secret"]; got == signingKey {
		t.Error("a viewer read the signing key over the Connect transport. The REST " +
			"handler masks it; this procedure is in the RBAC table as readable by " +
			"viewers and returns the stored config unchanged, so the mask is one " +
			"transport wide.")
	}
	if got := res.Middlewares[0].Config["issuer"]; got != "https://idp" {
		t.Errorf("issuer = %q, want it readable; masking covers credentials, not the "+
			"whole config", got)
	}

	// And the live configuration is untouched.
	if store.mws[0].Config["secret"] != signingKey {
		t.Fatal("the read rewrote the stored secret; every request through this " +
			"route would now fail to authenticate")
	}
}

// TestListMiddlewaresShowsSecretsToAnOperator keeps export working.
func TestListMiddlewaresShowsSecretsToAnOperator(t *testing.T) {
	const signingKey = "SUPER-SECRET-SIGNING-KEY"
	s := &ApiService{Middlewares: &fakeMwStore{mws: []*gateonv1.Middleware{{
		Id: "jwt-1", Config: map[string]string{"secret": signingKey},
	}}}}

	res, err := s.ListMiddlewares(ctxAs(auth.RoleOperator), &gateonv1.ListMiddlewaresRequest{})
	if err != nil {
		t.Fatalf("ListMiddlewares: %v", err)
	}
	if res.Middlewares[0].Config["secret"] != signingKey {
		t.Error("an operator, who can overwrite this secret, could not read it; " +
			"config export round-trips through here")
	}
}

// TestUpdateMiddlewareDoesNotOverwriteASecretWithThePlaceholder is what stops
// the mask from breaking saves.
//
// A caller who was shown a placeholder sends it back on any save that did not
// touch the credential. Written literally, an unrelated rename would replace the
// signing key with a string published in the source.
func TestUpdateMiddlewareDoesNotOverwriteASecretWithThePlaceholder(t *testing.T) {
	const signingKey = "SUPER-SECRET-SIGNING-KEY"
	store := &fakeMwStore{mws: []*gateonv1.Middleware{{
		Id: "jwt-1", Name: "old-name",
		Config: map[string]string{"secret": signingKey},
	}}}
	s := &ApiService{Middlewares: store}

	_, err := s.UpdateMiddleware(context.Background(), &gateonv1.UpdateMiddlewareRequest{
		Middleware: &gateonv1.Middleware{
			Id: "jwt-1", Name: "new-name",
			Config: map[string]string{"secret": secretmask.Placeholder},
		},
	})
	if err != nil {
		t.Fatalf("UpdateMiddleware: %v", err)
	}

	got, _ := store.Get(context.Background(), "jwt-1")
	if got.Config["secret"] != signingKey {
		t.Errorf("after a rename the secret is %q, want the original preserved. "+
			"Masking a value on the way out means recognising it on the way back, "+
			"or every edit destroys the credential.", got.Config["secret"])
	}
	if got.Name != "new-name" {
		t.Errorf("name = %q, want the edit applied", got.Name)
	}
}

// TestUpdateMiddlewareStillRotatesASecret is the control.
func TestUpdateMiddlewareStillRotatesASecret(t *testing.T) {
	store := &fakeMwStore{mws: []*gateonv1.Middleware{{
		Id: "jwt-1", Config: map[string]string{"secret": "old-key"},
	}}}
	s := &ApiService{Middlewares: store}

	if _, err := s.UpdateMiddleware(context.Background(), &gateonv1.UpdateMiddlewareRequest{
		Middleware: &gateonv1.Middleware{
			Id: "jwt-1", Config: map[string]string{"secret": "rotated-key"},
		},
	}); err != nil {
		t.Fatalf("UpdateMiddleware: %v", err)
	}

	got, _ := store.Get(context.Background(), "jwt-1")
	if got.Config["secret"] != "rotated-key" {
		t.Errorf("secret = %q, want the rotation applied; preserving the placeholder "+
			"must not mean refusing real changes", got.Config["secret"])
	}
}
