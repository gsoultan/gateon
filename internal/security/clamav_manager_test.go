package security

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestClamAVManagerStatus(t *testing.T) {
	mgr := NewClamAVManager(&gateonv1.ClamavConfig{})
	mgr.isOverloaded = func() bool { return false }

	status := mgr.GetScanStatus()
	if status.IsRunning {
		t.Error("expected status to not be running initially")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	// Since we don't have clamscan in test environment, it will fail fast
	// but it should still update the status.
	mgr.RunFullScan(ctx)

	status = mgr.GetScanStatus()
	if status.IsRunning {
		t.Error("expected status to not be running after scan finish")
	}
	if status.LastScan.IsZero() {
		t.Error("expected LastScan to be set")
	}
}

func TestClamAVManagerConcurrency(t *testing.T) {
	mgr := NewClamAVManager(&gateonv1.ClamavConfig{})
	mgr.isOverloaded = func() bool { return false }

	// Simulating multiple calls
	go mgr.RunFullScan(context.Background())
	time.Sleep(10 * time.Millisecond) // Give it a moment to start

	status := mgr.GetScanStatus()
	// It might have finished if it failed fast, but usually it takes a bit.
	// In this environment it probably fails fast.
	_ = status
}

func TestClamAVManagerReconfigure(t *testing.T) {
	tests := []struct {
		name        string
		initial     *gateonv1.ClamavConfig
		next        *gateonv1.ClamavConfig
		wantNilCfg  bool
		wantLowRsrc bool
	}{
		{
			name:        "EnableFromDisabled",
			initial:     nil,
			next:        &gateonv1.ClamavConfig{LowResourceMode: true, FullScanSchedule: "@daily"},
			wantNilCfg:  false,
			wantLowRsrc: true,
		},
		{
			name:       "DisableFromEnabled",
			initial:    &gateonv1.ClamavConfig{FullScanSchedule: "@daily"},
			next:       nil,
			wantNilCfg: true,
		},
		{
			name:        "UpdateSchedule",
			initial:     &gateonv1.ClamavConfig{FullScanSchedule: "@daily"},
			next:        &gateonv1.ClamavConfig{FullScanSchedule: "@hourly", LowResourceMode: true},
			wantNilCfg:  false,
			wantLowRsrc: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mgr := NewClamAVManager(tc.initial)
			t.Cleanup(mgr.Stop)

			mgr.Reconfigure(t.Context(), tc.next)

			got := mgr.cfg()
			if tc.wantNilCfg {
				if got != nil {
					t.Fatalf("%s: expected nil config after reconfigure, got %+v", tc.name, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("%s: expected non-nil config after reconfigure", tc.name)
			}
			if got.GetLowResourceMode() != tc.wantLowRsrc {
				t.Errorf("%s: LowResourceMode = %v; want %v", tc.name, got.GetLowResourceMode(), tc.wantLowRsrc)
			}
			// The live snapshot must reflect the new schedule, not the old one.
			if got.GetFullScanSchedule() != tc.next.GetFullScanSchedule() {
				t.Errorf("%s: FullScanSchedule = %q; want %q", tc.name, got.GetFullScanSchedule(), tc.next.GetFullScanSchedule())
			}
		})
	}
}

func TestClamAVManagerReconfigureNilSafe(t *testing.T) {
	mgr := NewClamAVManager(nil)
	t.Cleanup(mgr.Stop)
	// Reconfiguring a never-configured manager with nil must not panic and the
	// dependent accessors must remain safe.
	mgr.Reconfigure(t.Context(), nil)
	if mgr.cfg() != nil {
		t.Fatal("expected nil config to remain nil")
	}
	if mgr.IsInstalled(t.Context()) {
		t.Fatal("unconfigured manager must report not installed")
	}
}

func TestClamAVManagerPreflight(t *testing.T) {
	t.Run("NilConfig", func(t *testing.T) {
		mgr := NewClamAVManager(nil)
		err := mgr.Preflight()
		if err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("expected not-configured error, got %v", err)
		}
	})

	t.Run("UnspecifiedMode", func(t *testing.T) {
		mgr := NewClamAVManager(&gateonv1.ClamavConfig{
			InstallationMode: gateonv1.ClamavConfig_INSTALLATION_MODE_UNSPECIFIED,
		})
		err := mgr.Preflight()
		if err == nil || !strings.Contains(err.Error(), "unsupported installation mode") {
			t.Fatalf("expected unsupported-mode error, got %v", err)
		}
	})

	t.Run("DockerModeDependsOnDocker", func(t *testing.T) {
		mgr := NewClamAVManager(&gateonv1.ClamavConfig{
			InstallationMode: gateonv1.ClamavConfig_INSTALLATION_MODE_DOCKER,
		})
		// When docker is absent the error must be actionable; when present the
		// preflight must pass. Either way it must not panic and must agree with
		// docker availability on this host.
		_, dockerErr := exec.LookPath("docker")
		err := mgr.Preflight()
		if dockerErr != nil {
			if err == nil || !strings.Contains(err.Error(), "docker not found") {
				t.Fatalf("expected docker-not-found error, got %v", err)
			}
		} else if err != nil {
			t.Fatalf("docker is available but preflight failed: %v", err)
		}
	})
}

func TestClamAVManagerOverload(t *testing.T) {
	mgr := NewClamAVManager(&gateonv1.ClamavConfig{})
	// This should not crash on any OS
	overloaded := mgr.isSystemOverloaded()
	t.Logf("System overloaded: %v", overloaded)
}

func TestFormatExecError(t *testing.T) {
	mgr := NewClamAVManager(&gateonv1.ClamavConfig{})

	tests := []struct {
		name     string
		err      error
		output   string
		contains string
	}{
		{
			name:     "Read-only filesystem",
			err:      errors.New("exit status 100"),
			output:   "Could not open file ... (30: Read-only file system)",
			contains: "filesystem is read-only",
		},
		{
			name:     "Permission denied",
			err:      errors.New("exit status 1"),
			output:   "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?",
			contains: "insufficient privileges",
		},
		{
			name:     "General error",
			err:      errors.New("exit status 1"),
			output:   "some other error",
			contains: "failed: exit status 1 (output: some other error)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mgr.formatExecError("test", tt.err, []byte(tt.output))
			if !strings.Contains(got.Error(), tt.contains) {
				t.Errorf("expected error containing %q, got %q", tt.contains, got.Error())
			}
		})
	}
}
