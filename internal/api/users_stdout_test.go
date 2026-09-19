// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestListUsersWritesNothingToStdout: a leftover fmt.Printf("DEBUG: ...")
// wrote every ListUsers request -- including the operator-typed search
// string -- straight to the process's stdout, bypassing the logger's level,
// format and redaction. Stdout in a container is the log pipeline.
func TestListUsersWritesNothingToStdout(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	svc := &ApiService{Auth: auth.NewHolder(nil)}
	if _, err := svc.ListUsers(context.Background(), &gateonv1.ListUsersRequest{Search: "typed-by-operator"}); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}

	os.Stdout = orig
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("ListUsers wrote to stdout: %q", out)
	}
}
