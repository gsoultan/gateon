//go:generate bun install --cwd ../../ui
//go:generate bun run --cwd ../../ui build
//go:generate go run ../../scripts/sync_assets.go
package ui

import (
	"embed"
	"io/fs"
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
		f, err := dist.Open(strings.TrimPrefix(path.Clean(r.URL.Path), "/"))
		if err != nil {
			r.URL.Path = "/"
		} else {
			f.Close()
		}
		fileServer.ServeHTTP(w, r)
	})
}
