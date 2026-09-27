// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// benchTraces builds traces shaped like real ones: random IDs, source
// addresses and latencies, a handful of routes and user agents, and the
// headers a browser sends -- the parts that do not repeat are what decide the
// compression ratio, so they must not be constant here.
func benchTraces(n int, at time.Time) [][]byte {
	rng := rand.New(rand.NewPCG(1, 2))
	paths := []string{"/api/orders", "/api/orders/%d", "/api/users/%d/profile", "/static/app.%x.js", "/healthz", "/api/search?q=%x"}
	agents := []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
		"curl/8.7.1", "okhttp/4.12.0",
	}
	statuses := []string{"200", "200", "200", "200", "201", "204", "304", "404", "500"}
	out := make([][]byte, n)
	for i := range out {
		p := paths[rng.IntN(len(paths))]
		if rng.IntN(2) == 0 {
			p = fmt.Sprintf(p, rng.Uint32())
		}
		ip := fmt.Sprintf("%d.%d.%d.%d", rng.IntN(223)+1, rng.IntN(256), rng.IntN(256), rng.IntN(256))
		tr := telemetry.TraceRecord{
			ID:              fmt.Sprintf("%016x%016x", rng.Uint64(), rng.Uint64()),
			OperationName:   "GET " + p,
			ServiceName:     "orders-svc",
			RouteID:         "route-orders",
			DurationMs:      rng.Float64() * 250,
			Timestamp:       at.Add(time.Duration(i) * time.Millisecond * 90),
			Status:          statuses[rng.IntN(len(statuses))],
			Path:            p,
			SourceIP:        ip,
			CountryCode:     "NL",
			UserAgent:       agents[rng.IntN(len(agents))],
			Method:          "GET",
			RequestURI:      "shop.example.com" + p,
			JA4:             fmt.Sprintf("t13d1516h2_%012x_%012x", rng.Uint64()&0xffffffffffff, rng.Uint64()&0xffffffffffff),
			RequestHeaders:  fmt.Sprintf("Accept: */*\nAccept-Encoding: gzip, br\nCookie: [REDACTED]\nX-Request-Id: %x\n", rng.Uint64()),
			ResponseHeaders: fmt.Sprintf("Content-Type: application/json\nContent-Length: %d\nEtag: \"%x\"\n", rng.IntN(20000), rng.Uint64()),
			Reputation:      float64(rng.IntN(100)),
			ServiceDelay:    rng.Float64() * 200,
		}
		b, _ := json.Marshal(&tr)
		out[i] = b
	}
	return out
}

// BenchmarkWriteSegment measures what exporting an hour costs besides reading
// it from the store: framing and zstd. It reports the NDJSON throughput and
// how small the file comes out.
func BenchmarkWriteSegment(b *testing.B) {
	seg := SegmentAt(time.Date(2026, 9, 26, 14, 0, 0, 0, time.UTC))
	traces := benchTraces(20_000, seg.Start())
	raw := 0
	for _, t := range traces {
		raw += len(t) + 1
	}
	b.SetBytes(int64(raw))
	root := b.TempDir()
	var size int64
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		w, err := newSegmentWriter(root, testNode, seg)
		if err != nil {
			b.Fatal(err)
		}
		for i, t := range traces {
			w.fromStore(false)
			if err := w.add(t, seg.Start().Add(time.Duration(i)).UnixNano()); err != nil {
				b.Fatal(err)
			}
		}
		if _, _, err := w.commit(); err != nil {
			b.Fatal(err)
		}
		info, err := os.Stat(seg.path(root, testNode))
		if err != nil {
			b.Fatal(err)
		}
		size = info.Size()
	}
	b.ReportMetric(float64(raw)/float64(size), "ratio")
	b.ReportMetric(float64(raw)/20_000, "bytes/trace")
}
