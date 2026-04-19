package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// DataDir returns the base directory for state data (e.g. uploaded certs, sqlite db).
func DataDir() string {
	if dir := os.Getenv("GATEON_DATA_DIR"); dir != "" {
		return dir
	}
	if dir := os.Getenv("GATEON_STATE_DIR"); dir != "" {
		return dir
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/var/lib/gateon"); err == nil {
			return "/var/lib/gateon"
		}
	}
	return "."
}

// ConfigDir returns the base directory for configuration files.
func ConfigDir() string {
	if dir := os.Getenv("GATEON_CONFIG_DIR"); dir != "" {
		return dir
	}
	if globalFile := os.Getenv("GLOBAL_CONFIG_FILE"); globalFile != "" {
		return filepath.Dir(globalFile)
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/etc/gateon"); err == nil {
			return "/etc/gateon"
		}
	}
	return "."
}

// ResolvePath tries to find a file in common search locations if the path is relative.
func ResolvePath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}

	// 1. Try relative to CWD
	if _, err := os.Stat(path); err == nil {
		return path
	}

	// 2. Try relative to DataDir
	dataDirPath := filepath.Join(DataDir(), path)
	if _, err := os.Stat(dataDirPath); err == nil {
		return dataDirPath
	}

	// 3. Try relative to ConfigDir
	configDirPath := filepath.Join(ConfigDir(), path)
	if _, err := os.Stat(configDirPath); err == nil {
		return configDirPath
	}

	return path
}
