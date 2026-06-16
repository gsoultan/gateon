package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	// Paths relative to project root (or internal/ui when run via go generate)
	src := filepath.Join("ui", "dist")
	dst := filepath.Join("internal", "ui", "dist")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		src = filepath.Join("..", "..", "ui", "dist")
		dst = "dist"
	}

	fmt.Printf("Syncing assets from %s to %s...\n", src, dst)
	// Clean destination directory first to remove stale assets (hashes changed),
	// but preserve the tracked .gitkeep file so the working tree stays clean
	// (otherwise tools like GoReleaser fail on a "dirty" git state in CI).
	if err := cleanDir(dst); err != nil {
		fmt.Printf("Error cleaning destination: %v\n", err)
		os.Exit(1)
	}
	if err := copyDir(src, dst); err != nil {
		fmt.Printf("Error syncing assets: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Assets synced successfully.")
}

// gitKeep is the tracked placeholder that must survive a sync so the working
// tree does not end up in a dirty state.
const gitKeep = ".gitkeep"

// cleanDir removes stale build artifacts from dst while preserving the tracked
// .gitkeep file. The destination directory itself is (re)created if missing.
func cleanDir(dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == gitKeep {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dst, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		targetPath := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}

		return copyFile(path, targetPath)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return out.Close()
}
