//go:generate bun install --cwd ../../ui
//go:generate bun run --cwd ../../ui build
//go:generate go run ../../scripts/sync_assets.go
package ui

import (
	"embed"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distEmbed embed.FS

// Handler returns an http.Handler that serves the embedded UI.
func Handler() http.Handler {
	return StaticHandler(distEmbed, "dist")
}

// StaticHandler returns an http.Handler that serves assets from a provided filesystem.
func StaticHandler(content fs.FS, subDir string) http.Handler {
	dist, err := fs.Sub(content, subDir)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "UI assets not found", http.StatusInternalServerError)
		})
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if cleanPath == "" {
			cleanPath = "index.html"
		}

		f, err := dist.Open(cleanPath)
		if err != nil {
			// If the file is not found:
			// 1. If it's an asset (js, css, images, etc.), return 404.
			// 2. Otherwise, serve index.html for SPA routing.
			if isAsset(cleanPath) {
				// For assets, return a 404 with a MIME type that matches the extension.
				// If we return text/plain with nosniff for a .js file, browsers will
				// report a MIME mismatch error instead of a clear 404.
				ext := path.Ext(cleanPath)
				contentType := "text/plain; charset=utf-8"
				if ext != "" {
					contentType = mime.TypeByExtension(ext)
					if contentType == "" {
						contentType = "application/octet-stream"
					}
				}
				w.Header().Set("Content-Type", contentType)
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, "Asset not found: %s\n", cleanPath)
				return
			}
			r.URL.Path = "/"
		} else {
			f.Close()
		}
		fileServer.ServeHTTP(w, r)
	})
}

func isAsset(p string) bool {
	p = strings.ToLower(p)
	if strings.HasPrefix(p, "assets/") || strings.HasPrefix(p, "static/") || strings.HasPrefix(p, "favicon") {
		return true
	}
	ext := path.Ext(p)
	switch ext {
	case ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".json", ".wasm", ".map":
		return true
	}
	return false
}
