// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestUpdateTLSOptionGivesANewOptionAnID: the RPC wrote the option to the store
// as sent, and a new one is sent without an id -- the dashboard's form sends
// exactly that. Over gRPC, which serves every RPC, each new option therefore
// landed under "", overwriting the last, and none could be deleted, since
// DeleteTLSOption refuses an empty id. REST saves through the domain service,
// which assigns one.
func TestUpdateTLSOptionGivesANewOptionAnID(t *testing.T) {
	ctx := context.Background()
	store := config.NewTLSOptionRegistry(filepath.Join(t.TempDir(), "tls_options.json"))
	svc := &ApiService{TLSOptions: store}

	for _, name := range []string{"modern", "legacy"} {
		resp, err := svc.UpdateTLSOption(ctx, &gateonv1.UpdateTLSOptionRequest{TlsOption: &gateonv1.TLSOption{Name: name}})
		if err != nil || !resp.GetSuccess() {
			t.Fatalf("UpdateTLSOption(%q): resp=%v err=%v", name, resp, err)
		}
	}
	opts := store.List(ctx)
	if len(opts) != 2 {
		t.Fatalf("the store holds %d options after two new ones were saved, want 2: %v", len(opts), opts)
	}
	for _, o := range opts {
		if o.GetId() == "" {
			t.Fatalf("option %q was stored without an id", o.GetName())
		}
		if resp, err := svc.DeleteTLSOption(ctx, &gateonv1.DeleteTLSOptionRequest{Id: o.GetId()}); err != nil || !resp.GetSuccess() {
			t.Errorf("DeleteTLSOption(%q): resp=%v err=%v", o.GetId(), resp, err)
		}
	}
	if left := store.List(ctx); len(left) != 0 {
		t.Errorf("%d options left after deleting both: %v", len(left), left)
	}
}
