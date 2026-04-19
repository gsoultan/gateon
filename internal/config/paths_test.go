package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some files for testing
	dataDir := filepath.Join(tmpDir, "var_lib_gateon")
	_ = os.MkdirAll(filepath.Join(dataDir, "certs"), 0755)
	certFileInDataDir := filepath.Join(dataDir, "certs/data.crt")
	_ = os.WriteFile(certFileInDataDir, []byte("data"), 0644)

	configDir := filepath.Join(tmpDir, "etc_gateon")
	_ = os.MkdirAll(filepath.Join(configDir, "certs"), 0755)
	certFileInConfigDir := filepath.Join(configDir, "certs/config.crt")
	_ = os.WriteFile(certFileInConfigDir, []byte("config"), 0644)

	// Set env vars
	os.Setenv("GATEON_DATA_DIR", dataDir)
	os.Setenv("GATEON_CONFIG_DIR", configDir)
	defer os.Unsetenv("GATEON_DATA_DIR")
	defer os.Unsetenv("GATEON_CONFIG_DIR")

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "absolute path remains unchanged",
			input:    "/abs/path",
			expected: "/abs/path",
		},
		{
			name:     "empty path remains empty",
			input:    "",
			expected: "",
		},
		{
			name:     "found in data dir",
			input:    "certs/data.crt",
			expected: certFileInDataDir,
		},
		{
			name:     "found in config dir",
			input:    "certs/config.crt",
			expected: certFileInConfigDir,
		},
		{
			name:     "not found returns original",
			input:    "certs/missing.crt",
			expected: "certs/missing.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolvePath(tt.input)
			// Clean paths to compare fairly on Windows/Linux
			got = filepath.Clean(got)
			expected := filepath.Clean(tt.expected)
			if got != expected {
				t.Errorf("ResolvePath(%q) = %q, expected %q", tt.input, got, expected)
			}
		})
	}
}
