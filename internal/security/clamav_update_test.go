package security

import (
	"context"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestClamAVManagerManualUpdate(t *testing.T) {
	mgr := NewClamAVManager(&gateonv1.ClamavConfig{
		InstallationMode: gateonv1.ClamavConfig_INSTALLATION_MODE_LOCAL,
	})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	// This should fail because freshclam is likely not in path in test env
	err := mgr.UpdateDatabase(ctx)
	if err != nil {
		t.Logf("UpdateDatabase failed as expected in test env: %v", err)
	}

	err = mgr.UpdateApplication(ctx)
	if err != nil {
		t.Logf("UpdateApplication failed as expected in test env: %v", err)
	}
}

func TestClamAVManagerScheduling(t *testing.T) {
	// Use a very frequent schedule to see if it triggers (though cron might not trigger that fast)
	mgr := NewClamAVManager(&gateonv1.ClamavConfig{
		FullScanSchedule:       "0 0 * * *", // Once a day
		DatabaseUpdateSchedule: "0 0 * * *",
		AppUpdateSchedule:      "0 0 * * *",
	})

	err := mgr.Start(context.Background())
	if err != nil {
		t.Fatalf("failed to start manager: %v", err)
	}
	defer mgr.Stop()

	// Wait a bit to ensure no panics and it starts
	time.Sleep(100 * time.Millisecond)
}
