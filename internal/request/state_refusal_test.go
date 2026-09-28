// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http/httptest"
	"testing"
)

// MarkRefused writes to the request's own state, which the metrics middleware
// reads after the handler returns; a request with no state is left unmarked,
// so its refusal counts as it did before the mark existed.
func TestMarkRefusedWritesTheRequestsState(t *testing.T) {
	rs := &RequestState{}
	req := httptest.NewRequest("POST", "/graphql", nil)
	req = req.WithContext(WithState(req.Context(), rs))

	MarkRefused(req, RefusalToken)
	if rs.Refused != RefusalToken || rs.Refused.String() != "token" {
		t.Errorf("after MarkRefused the state reads %d (%q), want the token refusal", rs.Refused, rs.Refused.String())
	}

	bare := httptest.NewRequest("POST", "/graphql", nil)
	MarkRefused(bare, RefusalToken) // must not panic
	if GetRequestState(bare) != nil {
		t.Error("MarkRefused created state for a request that had none")
	}
	if RefusalNone.String() != "" {
		t.Errorf("no refusal names itself %q; a trace would record it", RefusalNone.String())
	}
}
