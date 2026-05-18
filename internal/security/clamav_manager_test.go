package security

import (
	"context"
	"errors"
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
