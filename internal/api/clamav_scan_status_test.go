// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"testing"

	"github.com/gsoultan/gateon/internal/security"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestScanStatusHasNoLastScanBeforeTheFirst: the status carried Go's zero
// time, "0001-01-01T00:00:00Z", for a gateway that had never scanned, and the
// Security page printed it as "Last scan: Jan 1, 00:00".
func TestScanStatusHasNoLastScanBeforeTheFirst(t *testing.T) {
	s := &ApiService{ClamAVManager: security.NewClamAVManager(&gateonv1.ClamavConfig{})}
	res, err := s.GetClamavScanStatus(t.Context(), &gateonv1.GetClamavScanStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.GetStatus().GetLastScan(); got != "" {
		t.Fatalf("lastScan before any scan = %q, want empty", got)
	}
}
