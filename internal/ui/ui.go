// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:generate bun install --cwd ../../ui
//go:generate bun run --cwd ../../ui build
//go:generate go run ../../scripts/sync_assets.go
package ui

import (
	"bytes"
	"embed"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
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

	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(dist, "index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		nonce := kind.GetNonce(r)
		if nonce != "" {
			data = bytes.ReplaceAll(data, []byte("NONCE_PLACEHOLDER"), []byte(nonce))
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		_, _ = w.Write(data)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if cleanPath == "" || cleanPath == "index.html" {
			serveIndex(w, r)
			return
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
				// Not the path: it is the requester's to choose, and the
				// Content-Type above follows its extension, so an echoed
				// "/assets/....html" was markup served as HTML on the
				// dashboard's own origin.
				_, _ = w.Write([]byte("Asset not found\n"))
				return
			}
			serveIndex(w, r)
			return
		} else {
			_ = f.Close()
		}
		if servePrecompressed(w, r, dist, cleanPath) {
			return
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

// precompressedVariants are the encodings the dashboard build writes beside
// each asset, best first.
var precompressedVariants = [...]struct{ encoding, suffix string }{
	{"br", ".br"},
	{"gzip", ".gz"},
}

// servePrecompressed answers with the variant the build already compressed,
// when the client accepts one, and reports whether it did.
//
// Without it the management chain's compress middleware brotli-encoded every
// asset on the fly, for unauthenticated clients, at about 11 MiB of live heap
// per encoder: 200 concurrent requests for the largest bundle held 2.2 GiB
// (ADR 0074). The variant carries its own Content-Encoding, which the compress
// middleware takes as already encoded and passes through untouched.
//
// index.html never reaches here: it is rewritten per request with the CSP
// nonce, so its precompressed copy is not what is served.
func servePrecompressed(w http.ResponseWriter, r *http.Request, dist fs.FS, name string) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	accept := r.Header.Get("Accept-Encoding")
	varies := false
	for _, v := range precompressedVariants {
		f, err := dist.Open(name + v.suffix)
		if err != nil {
			continue
		}
		varies = true
		if !acceptsEncoding(accept, v.encoding) {
			_ = f.Close()
			continue
		}
		served := serveVariant(w, r, f, name, v.encoding)
		_ = f.Close()
		if served {
			return true
		}
	}
	if varies {
		// The plain answer differs by Accept-Encoding too, or a shared cache
		// could hand it the br one.
		w.Header().Add("Vary", "Accept-Encoding")
	}
	return false
}

// serveVariant writes f as name encoded with encoding. It reports false, having
// written nothing, when f cannot be served from (not seekable, no stat).
func serveVariant(w http.ResponseWriter, r *http.Request, f fs.File, name, encoding string) bool {
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return false
	}
	h := w.Header()
	if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
		h.Set("Content-Type", ct)
	}
	h.Set("Content-Encoding", encoding)
	h.Add("Vary", "Accept-Encoding")
	// ServeContent leaves Content-Length off an encoded answer. The variant is
	// served whole, so its length is the file's; a range of the encoded bytes
	// is not worth what it would take to get right, and the whole answer is
	// what a client gets for a Range it cannot have.
	h.Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	if r.Header.Get("Range") != "" {
		r = r.Clone(r.Context())
		r.Header.Del("Range")
	}
	http.ServeContent(w, r, name, info.ModTime(), rs)
	return true
}

// acceptsEncoding reports whether an Accept-Encoding header admits coding: it
// is named, or "*" is, without q=0.
func acceptsEncoding(header, coding string) bool {
	star := false
	for part := range strings.SplitSeq(header, ",") {
		name, params, _ := strings.Cut(part, ";")
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case coding:
			return !zeroQuality(params)
		case "*":
			star = !zeroQuality(params)
		}
	}
	return star
}

// zeroQuality reports whether a coding's parameters carry q=0, which refuses it.
func zeroQuality(params string) bool {
	for p := range strings.SplitSeq(params, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
			q, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return err == nil && q == 0
		}
	}
	return false
}
