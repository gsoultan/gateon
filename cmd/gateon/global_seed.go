// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
)

// globalConfigSeedEnv names a global.json to start from when the one the
// gateway keeps (GLOBAL_CONFIG_FILE) does not exist yet (ADR 0049).
//
// The container image and the Helm chart kept global.json at
// /etc/gateon/global.json, which the image did not have and the chart mounted
// read-only from a Secret. First-run setup writes global.json, so it failed
// there ("read-only file system"), and so did every later save of global
// settings. They now keep it on the data volume, and what an operator mounts
// at /etc/gateon/global.json -- the chart's externalDatabase and redis
// settings, say -- is this seed: copied once, onto a volume that has none,
// and not read again.
const globalConfigSeedEnv = "GATEON_GLOBAL_CONFIG_SEED"

// seedGlobalConfig copies the seed named by GATEON_GLOBAL_CONFIG_SEED to
// target when target does not exist and the seed does. It reports whether it
// copied. A seed that exists and cannot be copied is an error: starting on the
// built-in defaults instead would drop the settings the operator mounted.
func seedGlobalConfig(target string) (bool, error) {
	seed := strings.TrimSpace(os.Getenv(globalConfigSeedEnv))
	if seed == "" || filepath.Clean(seed) == filepath.Clean(target) {
		return false, nil
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		return false, nil // there already is one, or it cannot be told; the registry reports that
	}
	b, err := os.ReadFile(seed) // #nosec G304 G703 -- a path the operator names in the environment
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read the global config seed %s: %w", seed, err)
	}
	if err := writeFileAtomic(target, b); err != nil {
		return false, fmt.Errorf("copy the global config seed %s to %s: %w", seed, target, err)
	}
	return true, nil
}

// writeFileAtomic writes b to path, 0600, through a temporary file renamed
// into place, so a crash leaves either no file or the whole one.
func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".seed.tmp"
	// #nosec G703 -- GLOBAL_CONFIG_FILE, a path the operator names in the environment
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// applyGlobalConfigSeed seeds target, logging what it did; a seed that cannot
// be copied stops the gateway.
func applyGlobalConfigSeed(target string) {
	copied, err := seedGlobalConfig(target)
	if err != nil {
		logger.Fatal("refusing to start on built-in defaults: the global config seed could not be copied",
			"error", err)
	}
	if copied {
		logger.L.LogInfo("global config seeded; later changes to the seed are not read",
			"seed", os.Getenv(globalConfigSeedEnv), "path", target)
	}
}
