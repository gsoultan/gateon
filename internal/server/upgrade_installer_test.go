// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"testing"

	"github.com/gsoultan/gateon/internal/selfupdate"
	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestTheGatewaysInstallerRefusesWhereNothingCouldInstall: the installer the
// gateway is started with, on a machine with no upgrade helper and no
// release offered, says why it cannot install and starts nothing. A test
// process is such a machine, whatever started it.
func TestTheGatewaysInstallerRefusesWhereNothingCouldInstall(t *testing.T) {
	cfg := func() *gateonv1.UpdateConfig { return &gateonv1.UpdateConfig{} }
	dirs := upgrade.Dirs{Data: t.TempDir(), State: t.TempDir()}
	in := newUpgradeInstaller("1.8.2", dirs, selfupdate.New("1.8.2", cfg), cfg)

	view := in.View()
	if view.Blocker == upgrade.BlockerNone {
		t.Fatal("a gateway with no helper beside it offers to install")
	}
	if view.Current != nil || len(view.History) != 0 {
		t.Fatalf("an install is reported that never happened: %+v", view)
	}
	if err := in.Install("1.8.3", "ada", false); !errors.Is(err, upgrade.ErrBlocked) {
		t.Fatalf("Install: %v, want a refusal naming the blocker", err)
	}
}
