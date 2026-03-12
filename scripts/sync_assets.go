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
	err := copyDir(src, dst)
	if err != nil {
		fmt.Printf("Error syncing assets: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Assets synced successfully.")
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
