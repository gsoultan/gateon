// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import "testing"

// withBrotliEncoderSlots gives the process-wide brotli gate n slots for one test.
func withBrotliEncoderSlots(t *testing.T, n string) {
	t.Helper()
	t.Setenv(brotliEncodersEnv, n)
	brotliEncoders = encoderGate{}
	t.Cleanup(func() { brotliEncoders = encoderGate{} })
}
