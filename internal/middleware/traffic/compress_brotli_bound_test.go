// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/andybalholm/brotli"
)

// A brotli encoder at the library's default quality and window held about
// 11 MiB live once it had seen more than 64 KiB, against about 1 MiB for gzip,
// and the compress middleware preferred br whenever a client offered it. 200
// concurrent br requests for the dashboard's largest asset held 2.2 GiB in
// this package's own measurement. Root cause: every encoder was built at the
// default quality and window, and nothing bounded how many ran at once.

// compressibleText is input shaped like a script bundle: words from a small
// vocabulary, so the encoder finds matches and fills its window and tables.
func compressibleText(n int) []byte {
	words := strings.Fields("const function return import export default props state value " +
		"render useEffect useState className children onClick theme color size")
	r := rand.New(rand.NewPCG(1, 2))
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(words[r.IntN(len(words))])
		b.WriteByte(' ')
	}
	return []byte(b.String()[:n])
}

func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// maxBrotliEncoderBytes is the live heap one pooled encoder may hold after a
// large input. The chosen settings measure about 2.6 MiB; the defaults 11 MiB.
const maxBrotliEncoderBytes = 4 << 20

func TestAPooledBrotliEncoderHoldsABoundedAmountOfMemory(t *testing.T) {
	input := compressibleText(1 << 20)
	const n = 8
	base := liveHeap()
	writers := make([]*brotli.Writer, n)
	for i := range writers {
		writers[i] = brotliWriterPool.Get().(*brotli.Writer)
		writers[i].Reset(io.Discard)
		if _, err := writers[i].Write(input); err != nil {
			t.Fatal(err)
		}
	}
	held := liveHeap() - base
	for _, w := range writers {
		_ = w.Close()
	}
	if per := held / n; per > maxBrotliEncoderBytes {
		t.Fatalf("one brotli encoder holds %.1f MiB after a 1 MiB input; want at most %.1f MiB",
			float64(per)/(1<<20), float64(maxBrotliEncoderBytes)/(1<<20))
	}
}

// blockedCompressions starts n requests whose handler writes a body large
// enough to be compressed and then waits on release, so each one holds its
// encoder until the test lets go. It returns once every handler has written.
func blockedCompressions(t *testing.T, h http.Handler, n int, release <-chan struct{}) *sync.WaitGroup {
	t.Helper()
	var wrote, done sync.WaitGroup
	wrote.Add(n)
	done.Add(n)
	for range n {
		go func() {
			defer done.Done()
			req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
			req.Header.Set("Accept-Encoding", "br")
			h.ServeHTTP(&signalOnWrite{ResponseRecorder: httptest.NewRecorder(), wrote: &wrote}, req)
		}()
	}
	wrote.Wait()
	return &done
}

// signalOnWrite reports the first body write that reaches the client, which
// is after the compressor has been chosen and its slot taken.
type signalOnWrite struct {
	*httptest.ResponseRecorder
	wrote *sync.WaitGroup
	once  sync.Once
}

func (s *signalOnWrite) Write(b []byte) (int, error) {
	s.once.Do(s.wrote.Done)
	return s.ResponseRecorder.Write(b)
}

func TestBrotliFallsBackWhenEveryEncoderSlotIsTaken(t *testing.T) {
	withBrotliEncoderSlots(t, "2")
	body := compressibleText(64 << 10)
	release := make(chan struct{})
	h := Compress()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = w.Write(body)
	}))
	holding := Compress()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = w.Write(body)
		w.(http.Flusher).Flush()
		<-release
	}))
	done := blockedCompressions(t, holding, 2, release)

	get := func(acceptEncoding string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
		req.Header.Set("Accept-Encoding", acceptEncoding)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if got := get("gzip, br").Header().Get("Content-Encoding"); got != "gzip" {
		t.Errorf("with every brotli slot taken, a client offering gzip got %q; want gzip", got)
	}
	if got := get("br").Header().Get("Content-Encoding"); got != "" {
		t.Errorf("with every brotli slot taken, a br-only client got %q; want identity", got)
	}

	close(release)
	done.Wait()
	if got := get("gzip, br").Header().Get("Content-Encoding"); got != "br" {
		t.Errorf("once the slots were given back a client offering br got %q; want br", got)
	}
}
