// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const refVar = "GATEON_TEST_REF_SECRET_8812"

func registryWithReference(t *testing.T) (*GlobalRegistry, string) {
	t.Helper()
	t.Setenv(refVar, "resolved-secret-value")
	path := filepath.Join(t.TempDir(), "global.json")
	body := `{"auth": {"enabled": true, "paseto_secret": "$env:` + refVar + `"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := NewGlobalRegistry(path)
	if reg.LoadErr() != nil {
		t.Fatalf("load: %v", reg.LoadErr())
	}
	return reg, path
}

func onDisk(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestUpdateEchoingTheResolvedSecretKeepsTheReference sends back the live
// config -- resolved value in place of the reference, as a client that read it
// does and as KeepOmittedSections copies it -- and requires the file to keep
// the reference.
func TestUpdateEchoingTheResolvedSecretKeepsTheReference(t *testing.T) {
	reg, path := registryWithReference(t)
	echo := proto.Clone(reg.Get(t.Context())).(*gateonv1.GlobalConfig)
	if err := reg.Update(t.Context(), echo); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := onDisk(t, path); !strings.Contains(got, "$env:"+refVar) || strings.Contains(got, "resolved-secret-value") {
		t.Fatalf("after an unchanged save global.json holds:\n%s", got)
	}
	if got := reg.Get(t.Context()).GetAuth().GetPasetoSecret(); got != "resolved-secret-value" {
		t.Fatalf("live secret is %q, want the resolved value", got)
	}
}

// TestUpdateResolvesAReferenceItIsGiven sends the reference itself. It used
// to become the live secret verbatim until the next restart.
func TestUpdateResolvesAReferenceItIsGiven(t *testing.T) {
	reg, path := registryWithReference(t)
	conf := proto.Clone(reg.Get(t.Context())).(*gateonv1.GlobalConfig)
	conf.Auth.PasetoSecret = "$env:" + refVar
	if err := reg.Update(t.Context(), conf); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := reg.Get(t.Context()).GetAuth().GetPasetoSecret(); got != "resolved-secret-value" {
		t.Fatalf("live secret is %q, want the resolved value", got)
	}
	if got := onDisk(t, path); !strings.Contains(got, "$env:"+refVar) {
		t.Fatalf("global.json lost the reference:\n%s", got)
	}
}

// TestUpdateRefusesAReferenceItCannotResolve keeps an update naming an unset
// variable from being stored, live or on disk.
func TestUpdateRefusesAReferenceItCannotResolve(t *testing.T) {
	reg, path := registryWithReference(t)
	before := onDisk(t, path)
	conf := proto.Clone(reg.Get(t.Context())).(*gateonv1.GlobalConfig)
	conf.Auth.PasetoSecret = "$env:GATEON_TEST_UNSET_REF_8812"
	if err := reg.Update(t.Context(), conf); err == nil {
		t.Fatal("an update naming an unset variable was accepted")
	}
	if got := reg.Get(t.Context()).GetAuth().GetPasetoSecret(); got != "resolved-secret-value" {
		t.Fatalf("the refused update changed the live secret to %q", got)
	}
	if onDisk(t, path) != before {
		t.Fatal("the refused update rewrote global.json")
	}
}

// TestWriterViewShowsTheReference is what GET /v1/global and GetGlobalConfig
// hand a caller who may write the config.
func TestWriterViewShowsTheReference(t *testing.T) {
	reg, _ := registryWithReference(t)
	live := reg.Get(t.Context())
	view := WithSecretReferences(reg, live)
	if got := view.GetAuth().GetPasetoSecret(); got != "$env:"+refVar {
		t.Fatalf("writer view holds %q, want the reference", got)
	}
	if live.GetAuth().GetPasetoSecret() != "resolved-secret-value" {
		t.Fatal("building the writer view modified the live config")
	}
}
