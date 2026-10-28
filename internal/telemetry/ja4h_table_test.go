// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

// referenceJA4H is a JA4H written out longhand from the request, so the
// interned table is checked against the layout rather than against the code
// that fills it.
func referenceJA4H(r *http.Request) string {
	method := strings.ToLower(r.Method) + "00"
	if len(r.Method) == 1 {
		method = strings.ToLower(r.Method) + "0"
	}
	version := "11"
	switch {
	case r.ProtoMajor == 2:
		version = "20"
	case r.ProtoMajor == 3:
		version = "30"
	case r.ProtoMajor == 1 && r.ProtoMinor == 0:
		version = "10"
	}
	cookie, referer := "n", "n"
	if r.Header.Get("Cookie") != "" {
		cookie = "c"
	}
	if r.Header.Get("Referer") != "" {
		referer = "r"
	}
	var names []string
	for _, n := range []string{"Accept-Language", "User-Agent"} {
		if r.Header.Get(n) != "" {
			names = append(names, n)
		}
	}
	alpn := "00"
	if r.TLS != nil {
		if p := r.TLS.NegotiatedProtocol; len(p) >= 2 {
			alpn = p[:1] + p[len(p)-1:]
		} else if len(p) == 1 {
			alpn = p + "0"
		}
	}
	return method[:2] + version + cookie + referer + "0" + string(rune('0'+len(names))) + alpn + "_" + referenceHeaderHash(names...)
}

// ja4hTableRequests is a request for every slot of ja4hPlusTable: each
// method, version, cookie and referer presence, tracked-header set and ALPN
// the table holds.
func ja4hTableRequests() []*http.Request {
	var out []*http.Request
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
	versions := [][2]int{{1, 1}, {2, 0}, {3, 0}, {1, 0}}
	alpns := []*tls.ConnectionState{nil, {NegotiatedProtocol: "h2"}, {NegotiatedProtocol: "http/1.1"}, {NegotiatedProtocol: "h3"}}
	for _, m := range methods {
		for _, v := range versions {
			for flags := range 1 << 4 {
				for _, a := range alpns {
					r := req(m, nil)
					r.ProtoMajor, r.ProtoMinor = v[0], v[1]
					r.TLS = a
					for bit, name := range []string{"Cookie", "Referer", "Accept-Language", "User-Agent"} {
						if flags&(1<<bit) != 0 {
							r.Header.Set(name, "v")
						}
					}
					out = append(out, r)
				}
			}
		}
	}
	return out
}

// Every request the table holds gets its own JA4H back, from a slot no other
// JA4H shares, and the table's whole value space is that many slots: the index
// is a function of exactly what the string is.
func TestJA4HPlusTableIsExact(t *testing.T) {
	reqs := ja4hTableRequests()
	if len(reqs) != ja4hTableSize {
		t.Fatalf("%d requests for %d slots", len(reqs), ja4hTableSize)
	}
	bySlot := make(map[int]string, len(reqs))
	for _, r := range reqs {
		want := "_" + referenceJA4H(r)
		for range 2 { // the miss that fills the slot, then the hit
			if got := GenerateJA4HPlus(r); got != want {
				t.Fatalf("%s %d.%d %v: JA4H+ %q, want %q", r.Method, r.ProtoMajor, r.ProtoMinor, r.Header, got, want)
			}
		}
		if got := GenerateJA4H(r); got != want[1:] {
			t.Fatalf("JA4H %q, want %q", got, want[1:])
		}
		slot := ja4hPartsOf(r).tableSlot()
		if slot < 0 {
			t.Fatalf("%q is not in the table", want)
		}
		if prev, ok := bySlot[slot]; ok && prev != want {
			t.Fatalf("slot %d holds both %q and %q", slot, prev, want)
		}
		bySlot[slot] = want
	}
	if len(bySlot) != ja4hTableSize {
		t.Fatalf("%d distinct slots used, want %d", len(bySlot), ja4hTableSize)
	}
}

// A browser's request, once its JA4H has been seen, costs nothing to
// fingerprint. This allocated once a request before the table.
func TestJA4HPlusOfASeenShapeDoesNotAllocate(t *testing.T) {
	r := req(http.MethodGet, map[string]string{"User-Agent": "Mozilla/5.0", "Accept-Language": "en", "Cookie": "a=b"})
	r.ProtoMajor, r.ProtoMinor = 2, 0
	r.TLS = &tls.ConnectionState{NegotiatedProtocol: "h2"}
	_ = GenerateJA4HPlus(r)
	if n := testing.AllocsPerRun(100, func() { _ = GenerateJA4HPlus(r) }); n != 0 {
		t.Fatalf("GenerateJA4HPlus allocated %v times, want 0", n)
	}
}

// What the table does not hold -- a method or ALPN a client is free to choose
// -- is built per request, correctly, and never stored, so no request can grow
// or poison the table.
func TestJA4HPlusOutsideTheTable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		tls    *tls.ConnectionState
	}{
		{"WebDAV method", "PROPFIND", nil},
		{"one-letter method", "M", nil},
		{"lower-case custom method", "mkcol", nil},
		{"unlisted ALPN", http.MethodGet, &tls.ConnectionState{NegotiatedProtocol: "acme-tls/1"}},
		{"one-byte ALPN", http.MethodGet, &tls.ConnectionState{NegotiatedProtocol: "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := req(tc.method, map[string]string{"User-Agent": "x"})
			r.TLS = tc.tls
			if slot := ja4hPartsOf(r).tableSlot(); slot >= 0 {
				t.Fatalf("slot %d for a shape outside the table", slot)
			}
			if got, want := GenerateJA4HPlus(r), "_"+referenceJA4H(r); got != want {
				t.Fatalf("JA4H+ %q, want %q", got, want)
			}
		})
	}
}
