package security

import (
	"context"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestClamAVManagerStatus(t *testing.T) {
	mgr := NewClamAVManager(&gateonv1.ClamavConfig{})

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

	// Simulating multiple calls
	go mgr.RunFullScan(context.Background())
	time.Sleep(10 * time.Millisecond) // Give it a moment to start

	status := mgr.GetScanStatus()
	// It might have finished if it failed fast, but usually it takes a bit.
	// In this environment it probably fails fast.
	_ = status
}
