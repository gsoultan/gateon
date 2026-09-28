// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestMain runs this package's tests at bcrypt's lowest cost. They check only
// hashes they made themselves; at the production cost the package took four
// minutes under the race detector here and outran CI's ten-minute timeout.
func TestMain(m *testing.M) {
	bcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}

// TestStoredHashesUseTheProductionCost pins the cost the gateway stores
// passwords and recovery codes at; the lower cost is the tests' alone.
func TestStoredHashesUseTheProductionCost(t *testing.T) {
	if productionBcryptCost < bcrypt.DefaultCost {
		t.Fatalf("passwords and recovery codes are hashed at cost %d, below bcrypt's default %d",
			productionBcryptCost, bcrypt.DefaultCost)
	}
}
