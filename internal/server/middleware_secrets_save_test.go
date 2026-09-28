// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// placeholder is what the API shows for a stored secret. Spelled out rather
// than imported, so a test cannot pass by agreeing with a changed constant.
const placeholder = "__gateon_redacted__"

// shown is the middleware as an operator reads it over REST.
func (a *mwAPI) shown(t *testing.T, id string) *gateonv1.Middleware {
	t.Helper()
	_, mws := a.listREST(t)
	for _, m := range mws {
		if m.GetId() == id {
			return m
		}
	}
	t.Fatalf("GET /v1/middlewares has no %s", id)
	return nil
}

func (a *mwAPI) stored(t *testing.T, id string) map[string]string {
	t.Helper()
	m, ok := a.reg.Get(context.Background(), id)
	if !ok {
		t.Fatalf("nothing stored as %s", id)
	}
	c, ok := proto.Clone(m).(*gateonv1.Middleware)
	if !ok {
		t.Fatal("clone")
	}
	return c.GetConfig()
}

func (a *mwAPI) put(t *testing.T, m *gateonv1.Middleware) (int, string) {
	t.Helper()
	wire, err := protojson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	code, out := a.do(t, http.MethodPut, "/v1/middlewares", wire)
	return code, string(out)
}

func requireRefused(t *testing.T, what string, code int, body string, mentions ...string) {
	t.Helper()
	if code != http.StatusBadRequest {
		t.Fatalf("%s was answered %d %s; it must be refused", what, code, body)
	}
	for _, m := range mentions {
		if !strings.Contains(body, m) {
			t.Errorf("%s was refused without naming %q: %s", what, m, body)
		}
	}
}

// markerFor finds the key an API key with this tenant label is shown as.
func markerFor(t *testing.T, cfg map[string]string, label string) string {
	t.Helper()
	for k, v := range cfg {
		if v == label && strings.HasPrefix(k, "key_"+placeholder+"_") {
			return k
		}
	}
	t.Fatalf("no masked API key is labelled %q in %v", label, cfg)
	return ""
}

// apiKeyFor is the stored API key with this tenant label.
func apiKeyFor(t *testing.T, cfg map[string]string, label string) string {
	t.Helper()
	for k, v := range cfg {
		if v == label && strings.HasPrefix(k, "key_") {
			return k
		}
	}
	t.Fatalf("no stored API key is labelled %q", label)
	return ""
}

// TestMiddlewareSaveKeepsListSecretsByIdentity: a basic-auth user keeps its
// password by name and an API key keeps its key by fingerprint, however the
// list is reordered, relabelled or cut down, and an element no stored one
// matches is refused by name rather than handed a neighbour's secret.
func TestMiddlewareSaveKeepsListSecretsByIdentity(t *testing.T) {
	t.Run("basic-auth users reordered and one deleted", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		before := usersOf(a.stored(t, "auth-basic-users")["users"])
		m := a.shown(t, "auth-basic-users")
		m.Config["users"] = "carol:" + placeholder + ",alice:" + placeholder
		if code, body := a.put(t, m); code != http.StatusOK {
			t.Fatalf("PUT: %d %s", code, body)
		}
		want := "carol:" + before["carol"] + ",alice:" + before["alice"]
		if got := a.stored(t, "auth-basic-users")["users"]; got != want {
			t.Errorf("users stored as %q, want %q: each kept password belongs to its own user", got, want)
		}
	})
	t.Run("a renamed basic-auth user is refused, named", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		live, file := a.snapshot(t)
		m := a.shown(t, "auth-basic-users")
		m.Config["users"] = "alicia:" + placeholder + ",bob:" + placeholder
		code, body := a.put(t, m)
		requireRefused(t, "a user renamed with the placeholder as its password", code, body, `alicia`)
		a.requireUnchanged(t, "a refused rename", live, file)
	})
	t.Run("API keys relabelled and one deleted", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		before := a.stored(t, "auth-apikey")
		keyA, keyC := apiKeyFor(t, before, "tenant-a"), apiKeyFor(t, before, "tenant-c")
		m := a.shown(t, "auth-apikey")
		delete(m.Config, markerFor(t, m.Config, "tenant-b"))
		m.Config[markerFor(t, m.Config, "tenant-a")] = "tenant-a-renamed"
		if code, body := a.put(t, m); code != http.StatusOK {
			t.Fatalf("PUT: %d %s", code, body)
		}
		got := a.stored(t, "auth-apikey")
		want := map[string]string{"type": "apikey", "header": "X-API-Key", keyA: "tenant-a-renamed", keyC: "tenant-c"}
		if !equalMaps(got, want) {
			t.Errorf("stored %v, want %v: a relabelled key keeps its key, a deleted one is gone", got, want)
		}
	})
	t.Run("an API key no stored one matches is refused, named", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		live, file := a.snapshot(t)
		m := a.shown(t, "auth-apikey")
		m.Config["key_"+placeholder+"_0123456789abcdef"] = "tenant-new"
		code, body := a.put(t, m)
		requireRefused(t, "an API key marker that matches no stored key", code, body, "tenant-new")
		a.requireUnchanged(t, "a refused unknown API key", live, file)
	})
}

// TestMiddlewareSaveRefusesAKeptSecretForAMovedDestination: a kept secret goes
// where it went before. Without this, write-only is one request from read-back:
// point the introspection endpoint or the OpenID provider at a server you run,
// keep the placeholder, and let the gateway deliver the client secret.
func TestMiddlewareSaveRefusesAKeptSecretForAMovedDestination(t *testing.T) {
	for _, c := range []struct{ id, key, moved string }{
		{"auth-oauth2", "introspection_url", "https://collector.example.test/introspect"},
		{"oidc-login", "issuer", "https://collector.example.test"},
	} {
		t.Run(c.id, func(t *testing.T) {
			a, _ := newMwAPI(t, auth.RoleOperator)
			live, file := a.snapshot(t)
			m := a.shown(t, c.id)
			m.Config[c.key] = c.moved
			code, body := a.put(t, m)
			requireRefused(t, "keeping "+c.id+"'s client secret while moving "+c.key, code, body, c.key)
			a.requireUnchanged(t, "a refused move", live, file)

			m.Config["client_secret"] = "a-new-secret-entered-for-the-new-destination"
			if code, body := a.put(t, m); code != http.StatusOK {
				t.Fatalf("moving %s with a new secret: %d %s; only a kept secret is bound", c.key, code, body)
			}
		})
	}
}

// TestMiddlewareSaveRefusesAPlaceholderItCannotKeep: the placeholder keeps a
// stored secret of this middleware, used as it was entered, and nothing else.
func TestMiddlewareSaveRefusesAPlaceholderItCannotKeep(t *testing.T) {
	cases := []struct {
		name, mentions string
		edit           func(m *gateonv1.Middleware)
	}{
		{"a new middleware", "no stored middleware has this id", func(m *gateonv1.Middleware) { m.Id = "auth-jwt-copy" }},
		{"a changed kind of authentication", "another kind of middleware",
			func(m *gateonv1.Middleware) { m.Config["type"] = "paseto" }},
		{"a changed type", "another kind of middleware", func(m *gateonv1.Middleware) { m.Type = "hmac" }},
		{"a field that holds no secret", "holds none", func(m *gateonv1.Middleware) { m.Config["issuer"] = placeholder }},
		{"a secret with nothing stored", "none is stored",
			func(m *gateonv1.Middleware) { m.Config["client_secret"] = placeholder }},
		{"a value that merely contains it", "is not it",
			func(m *gateonv1.Middleware) { m.Config["secret"] = placeholder + "-and-more" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _ := newMwAPI(t, auth.RoleOperator)
			live, file := a.snapshot(t)
			m := a.shown(t, "auth-jwt")
			c.edit(m)
			code, body := a.put(t, m)
			requireRefused(t, c.name, code, body, c.mentions)
			a.requireUnchanged(t, "a refused placeholder", live, file)
		})
	}
}

// TestMiddlewareSaveClearsAnOptionalSecretAndRefusesToClearARequiredOne: ""
// clears. A secret the middleware cannot run without is refused by the build
// check every save makes -- not kept: for a middleware "" is never an omitted
// field (the dashboard sends every key, and an absent key is removed), and it
// is how an operator hands a secret over to its GATEON_*_SECRET fallback.
func TestMiddlewareSaveClearsAnOptionalSecretAndRefusesToClearARequiredOne(t *testing.T) {
	t.Setenv("GATEON_HMAC_SECRET", "")
	a, _ := newMwAPI(t, auth.RoleOperator)
	m := a.shown(t, "deception")
	m.Config["canary_token"] = ""
	if code, body := a.put(t, m); code != http.StatusOK {
		t.Fatalf("clearing the canary token: %d %s", code, body)
	}
	if got, ok := a.stored(t, "deception")["canary_token"]; !ok || got != "" {
		t.Errorf("canary_token stored as %q (present %v) after clearing it, want \"\"", got, ok)
	}
	// Cleared beside secrets the same save keeps: "" is not the placeholder.
	before := a.stored(t, "headers")
	m = a.shown(t, "headers")
	m.Config["set_response_X-Session-Token"] = ""
	if code, body := a.put(t, m); code != http.StatusOK {
		t.Fatalf("clearing one header credential and keeping the rest: %d %s", code, body)
	}
	after := a.stored(t, "headers")
	if after["set_response_X-Session-Token"] != "" || after["set_request_Authorization"] != before["set_request_Authorization"] {
		t.Errorf("headers stored as %v; want X-Session-Token cleared and Authorization kept", after)
	}

	live, file := a.snapshot(t)
	m = a.shown(t, "hmac")
	m.Config["secret"] = ""
	code, body := a.put(t, m)
	requireRefused(t, "clearing the only HMAC secret", code, body, "secret")
	a.requireUnchanged(t, "a refused clear", live, file)
}

// TestConfigImportRefusesAPlaceholderItCannotKeep: an import keeps a stored
// secret only for the middleware with the same id, type and destination, and
// names every one it cannot keep -- in the preview, before anything is
// written, and in the import.
func TestConfigImportRefusesAPlaceholderItCannotKeep(t *testing.T) {
	a, _ := newMwAPI(t, auth.RoleAdmin)
	live, file := a.snapshot(t)
	oauth := a.shown(t, "auth-oauth2")
	oauth.Config["introspection_url"] = "https://collector.example.test/introspect"
	payload := map[string]any{"middlewares": []*gateonv1.Middleware{
		{Id: "brand-new", Name: "brand-new", Type: "hmac", Config: map[string]string{"secret": placeholder}},
		oauth,
	}}
	body := marshalImport(t, payload)

	code, out := a.do(t, http.MethodPost, "/v1/config/import?dry_run=true", body)
	if code != http.StatusOK || !bytes.Contains(out, []byte("brand-new")) || !bytes.Contains(out, []byte(`"refused"`)) {
		t.Fatalf("the preview did not name the placeholder it would refuse: %d %s", code, out)
	}
	code, out = a.do(t, http.MethodPost, "/v1/config/import", body)
	for _, want := range []string{"middleware brand-new", "middleware auth-oauth2", "introspection_url"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("the import did not name %q: %d %s", want, code, out)
		}
	}
	a.requireUnchanged(t, "an import of placeholders it cannot keep", live, file)
}

// TestConfigImportPreviewAndValidateEchoNoSecret: the preview and the validate
// preflight answer about a payload without repeating the secrets in it. The
// preview used to echo every middleware it was sent, new secrets included.
func TestConfigImportPreviewAndValidateEchoNoSecret(t *testing.T) {
	a, _ := newMwAPI(t, auth.RoleAdmin)
	const fresh = "S3CR3T-entered-in-this-import-0f9e8d7c"
	payload := map[string]any{"middlewares": []*gateonv1.Middleware{
		{Id: "hmac", Name: "hmac", Type: "hmac", Config: map[string]string{"secret": fresh}},
		{Id: "brand-new-basic", Name: "b", Type: "auth", Config: map[string]string{"type": "basic",
			"users": "alice:" + fresh}},
	}}
	body := marshalImport(t, payload)
	for _, path := range []string{"/v1/config/import?dry_run=true", "/v1/config/validate"} {
		code, out := a.do(t, http.MethodPost, path, body)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, code, out)
		}
		if bytes.Contains(out, []byte(fresh)) {
			t.Errorf("%s echoed a secret it was sent: %s", path, out)
		}
	}
}

func marshalImport(t *testing.T, payload map[string]any) []byte {
	t.Helper()
	raw := map[string]json.RawMessage{}
	for k, v := range payload {
		list, ok := v.([]*gateonv1.Middleware)
		if !ok {
			t.Fatalf("payload %s", k)
		}
		items := make([]json.RawMessage, 0, len(list))
		for _, m := range list {
			b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			items = append(items, b)
		}
		b, err := json.Marshal(items)
		if err != nil {
			t.Fatal(err)
		}
		raw[k] = b
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func usersOf(v string) map[string]string {
	out := map[string]string{}
	for part := range strings.SplitSeq(v, ",") {
		name, pw, _ := strings.Cut(part, ":")
		out[name] = pw
	}
	return out
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
