// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package route

import (
	"errors"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ValidateStreamMode accepts the three values the router reads and refuses any
// other number, which the router would read as auto while the store kept it
// (ADR 0064).
func TestValidateStreamMode(t *testing.T) {
	for _, m := range []gateonv1.Route_StreamMode{
		gateonv1.Route_STREAM_MODE_AUTO, gateonv1.Route_STREAM_MODE_ALWAYS, gateonv1.Route_STREAM_MODE_NEVER,
	} {
		if err := ValidateStreamMode(&gateonv1.Route{StreamMode: m}); err != nil {
			t.Errorf("%v refused: %v", m, err)
		}
	}
	for _, n := range []int32{3, -1, 99} {
		err := ValidateStreamMode(&gateonv1.Route{StreamMode: gateonv1.Route_StreamMode(n)})
		if !errors.Is(err, ErrInvalidStreamMode) {
			t.Errorf("stream_mode %d: got %v, want ErrInvalidStreamMode", n, err)
		}
	}
}
