// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// chunkRecorder keeps every slice it is handed, not a copy, so a test can see
// whether a writer passed the caller's memory through or made its own.
type chunkRecorder struct {
	header http.Header
	chunks [][]byte
	failAt int // fail the nth Write, counting from 1; 0 never fails
}

func (r *chunkRecorder) Header() http.Header { return r.header }
func (r *chunkRecorder) WriteHeader(int)     {}

func (r *chunkRecorder) Write(p []byte) (int, error) {
	if len(r.chunks)+1 == r.failAt {
		return 0, errors.New("connection reset")
	}
	r.chunks = append(r.chunks, p)
	return len(p), nil
}

type injectingWriter struct {
	wrap   func(http.ResponseWriter) http.ResponseWriter
	marker string
}

func injectingWriters() map[string]injectingWriter {
	return map[string]injectingWriter{
		"deception": {
			wrap: func(w http.ResponseWriter) http.ResponseWriter {
				return &deceptionResponseWriter{ResponseWriter: w, cfg: DeceptionConfig{InvisibleLinkPaths: []string{"/trap"}}}
			},
			marker: `href="/trap"`,
		},
		"honeypot breadcrumb": {
			wrap: func(w http.ResponseWriter) http.ResponseWriter {
				return &breadcrumbWriter{ResponseWriter: w, request: httptest.NewRequest(http.MethodGet, "/", nil)}
			},
			marker: "/_gateon_trap_",
		},
	}
}

func htmlRecorder(failAt int) *chunkRecorder {
	return &chunkRecorder{header: http.Header{"Content-Type": {"text/html; charset=utf-8"}}, failAt: failAt}
}

// Both writers put markup in front of the page's closing body tag. They built
// the result in a new buffer and wrote that -- a copy of the page chunk, up to
// the proxy's 32 KiB, on every HTML response they touched. The page now goes
// out around the markup, so what reaches the next writer is the caller's own
// memory.
func TestInjectionWritesThePageAroundTheMarkupWithoutCopyingIt(t *testing.T) {
	page := []byte("<html><body><p>hello</p></body></html>")
	idx := bytes.LastIndex(page, []byte("</body>"))
	for name, iw := range injectingWriters() {
		t.Run(name, func(t *testing.T) {
			rec := htmlRecorder(0)
			n, err := iw.wrap(rec).Write(page)
			if err != nil || n != len(page) {
				t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(page))
			}
			got := string(bytes.Join(rec.chunks, nil))
			if !strings.HasPrefix(got, string(page[:idx])) || !strings.HasSuffix(got, string(page[idx:])) ||
				!strings.Contains(got, iw.marker) {
				t.Fatalf("wrote %q; want the page intact with %s before </body>", got, iw.marker)
			}
			first, last := rec.chunks[0], rec.chunks[len(rec.chunks)-1]
			if &first[0] != &page[0] || &last[0] != &page[idx] {
				t.Error("the page reached the next writer as a copy, not in place")
			}
		})
	}
}

// A write that fails partway reports how much of the page it wrote, as
// io.Writer requires: the deception writer said none, the breadcrumb writer
// said all of it.
func TestInjectionReportsHowMuchOfThePageAFailedWriteWrote(t *testing.T) {
	page := []byte("<html><body><p>hello</p></body></html>")
	idx := bytes.LastIndex(page, []byte("</body>"))
	for name, iw := range injectingWriters() {
		t.Run(name, func(t *testing.T) {
			n, err := iw.wrap(htmlRecorder(2)).Write(page) // the page's first half lands, the markup does not
			if err == nil || n != idx {
				t.Errorf("Write = %d, %v; want %d and the error", n, err, idx)
			}
		})
	}
}

// discardHTML is the cheapest writer that still looks like an HTML response.
type discardHTML struct{ header http.Header }

func (d discardHTML) Header() http.Header                   { return d.header }
func (discardHTML) WriteHeader(int)                         {}
func (discardHTML) Write(p []byte) (int, error)             { return len(p), nil }
func (discardHTML) WriteString(s string) (n int, err error) { return len(s), nil }

// BenchmarkDeceptionInjection writes one proxy-sized HTML chunk through the
// deception writer, the way httputil.ReverseProxy hands it over.
func BenchmarkDeceptionInjection(b *testing.B) {
	page := []byte(strings.Repeat("<p>lorem ipsum dolor sit amet</p>\n", 32*1024/34) + "</body></html>")
	dst := discardHTML{header: http.Header{"Content-Type": {"text/html"}}}
	cfg := DeceptionConfig{InvisibleLinkPaths: []string{"/wp-admin-backup", "/.env.old"}}
	b.ReportAllocs()
	b.SetBytes(int64(len(page)))
	for b.Loop() {
		w := &deceptionResponseWriter{ResponseWriter: dst, cfg: cfg}
		if _, err := w.Write(page); err != nil {
			b.Fatal(err)
		}
	}
}
