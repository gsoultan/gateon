// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import "testing"

// withSchemaDecodeSlots gives the process-wide schema decode gate n slots for
// one test.
func withSchemaDecodeSlots(t *testing.T, n string) {
	t.Helper()
	t.Setenv(schemaLargeBodyEnv, n)
	schemaDecodes = schemaDecodeGate{}
	t.Cleanup(func() { schemaDecodes = schemaDecodeGate{} })
}
