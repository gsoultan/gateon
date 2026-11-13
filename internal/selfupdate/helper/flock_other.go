// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !unix

package helper

import (
	"errors"
	"os"
)

// lockExclusive refuses: the helper replaces the binary of a systemd
// service, and there is none here to replace.
func lockExclusive(*os.File) error {
	return errors.New("the upgrade helper runs on Linux only")
}
