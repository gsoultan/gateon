// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/config/storedsecret"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestUpdateRefusesToStoreThePlaceholder is the store's own guard. The API
// restores a kept secret before saving, but setup, GitOps sync, the diagnostic
// fixes and ClamAV installation write the registry directly; whichever path
// carries the placeholder in, it must not become the session key.
func TestUpdateRefusesToStoreThePlaceholder(t *testing.T) {
	reg, path := registryWithReference(t)
	before := onDisk(t, path)
	live := proto.Clone(reg.Get(t.Context())).(*gateonv1.GlobalConfig)

	conf := proto.Clone(live).(*gateonv1.GlobalConfig)
	conf.Auth.PasetoSecret = storedsecret.Sentinel
	err := reg.Update(t.Context(), conf)
	if !errors.Is(err, storedsecret.ErrPlaceholderStored) {
		t.Fatalf("Update = %v; want ErrPlaceholderStored", err)
	}
	if onDisk(t, path) != before {
		t.Fatal("the refused update rewrote global.json")
	}
	if !proto.Equal(reg.Get(t.Context()), live) {
		t.Fatal("the refused update changed the live config")
	}
}

// TestLoadNamesListElementsThatHaveNoID: a dispatcher written without an id
// gets one on load, the same on every load, so the dashboard can keep its
// stored webhook when it saves the settings back.
func TestLoadNamesListElementsThatHaveNoID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global.json")
	body := `{"alerting": {"dispatchers": [{"name": "ops", "type": "slack", "webhook_url": "https://hooks.example/x"}]}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	first := NewGlobalRegistry(path).Get(t.Context()).GetAlerting().GetDispatchers()[0].GetId()
	second := NewGlobalRegistry(path).Get(t.Context()).GetAlerting().GetDispatchers()[0].GetId()
	if first == "" || first != second {
		t.Fatalf("ids on two loads: %q and %q; want one non-empty id", first, second)
	}
}
