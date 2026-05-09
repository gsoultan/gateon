package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var originalChecksum string

func init() {
	// In a real production scenario, the original checksum would be embedded at build time
	// or stored in a signed file. For this implementation, we calculate it once at start.
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	originalChecksum, _ = calculateChecksum(exePath)
	logger.L.LogInfo("Initial system integrity checksum calculated", "checksum", originalChecksum)
}

// IntegrityDetector monitors the Gateon binary for unauthorized modifications.
type IntegrityDetector struct{}

func (d *IntegrityDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	if originalChecksum == "" {
		return nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return nil
	}

	currentChecksum, err := calculateChecksum(exePath)
	if err != nil {
		return nil
	}

	if currentChecksum != originalChecksum {
		return []*gateonv1.Anomaly{
			{
				Type:           "system_integrity_violation",
				Severity:       "critical",
				Description:    "Gateon binary checksum mismatch! Potential unauthorized modification detected.",
				Timestamp:      time.Now().Format(time.RFC3339),
				Source:         "local_system",
				Recommendation: "Immediately isolate the server and investigate for potential compromise. Restore from a known good backup.",
			},
		}
	}

	return nil
}

func calculateChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
