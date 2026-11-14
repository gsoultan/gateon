// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// GatewayUnit is the unit the helper restarts.
const GatewayUnit = "gateon.service"

// The bounds on one systemctl call. A restart is the long one: it waits for
// the gateway to drain before starting it again.
const (
	restartTimeout = 4 * time.Minute
	showTimeout    = 10 * time.Second
)

// Systemd controls the gateway through systemctl.
type Systemd struct {
	Unit string
}

func (s Systemd) systemctl(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// #nosec G204 -- systemctl with arguments this package wrote; nothing here comes from the gateway.
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Restart restarts the gateway and waits for the new process to be started.
// reset-failed first: it clears the restart counter Restarts reads, and a
// start limit an earlier failure left behind.
func (s Systemd) Restart(ctx context.Context) error {
	_, _ = s.systemctl(ctx, showTimeout, "reset-failed", s.Unit)
	_, err := s.systemctl(ctx, restartTimeout, "restart", s.Unit)
	return err
}

// Restarts reads the unit's automatic restart counter.
func (s Systemd) Restarts(ctx context.Context) int {
	out, err := s.systemctl(ctx, showTimeout, "show", "--property=NRestarts", "--value", s.Unit)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0
	}
	return n
}
