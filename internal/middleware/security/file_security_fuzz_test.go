// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

const fuzzBoundary = "fuzzb"

// fuzzUpload builds a multipart body with one file part under the fixed fuzz
// boundary, so the seeds are real uploads rather than arbitrary bytes.
func fuzzUpload(f *testing.F, name string, content []byte) []byte {
	f.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.SetBoundary(fuzzBoundary); err != nil {
		f.Fatal(err)
	}
	p, err := w.CreateFormFile("file", name)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := p.Write(content); err != nil {
		f.Fatal(err)
	}
	if err := w.Close(); err != nil {
		f.Fatal(err)
	}
	return body.Bytes()
}

// FuzzFileSecurityMultipart drives the upload scanner with an arbitrary body
// and an arbitrary boundary. The multipart reader, the disposition parser and
// the magic-byte detectors all take bytes the client wrote; the seeds cover
// the parser-differential shapes the bypass tests were written against -- a
// body cut before its closing boundary, a disposition that repeats filename=,
// a PNG head with an ELF behind it -- and the fuzzer mutates from there.
//
// The invariant is the one the scanner exists for: a request is forwarded with
// the exact bytes it arrived with, or it is refused. A forward with a changed
// body is restoreBody failing; a response that is neither is a part reaching
// the origin that no check looked at.
func FuzzFileSecurityMultipart(f *testing.F) {
	clean := fuzzUpload(f, "notes.txt", []byte("hello, world"))
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 300)...)
	elfInPNG := append(append([]byte{}, png...), append([]byte("\x7fELF"), make([]byte, 64)...)...)

	f.Add(fuzzBoundary, clean)
	f.Add(fuzzBoundary, clean[:len(clean)-len("--"+fuzzBoundary+"--\r\n")]) // truncated before the close
	f.Add(fuzzBoundary, fuzzUpload(f, "image.png", elfInPNG))
	f.Add(fuzzBoundary, []byte("--"+fuzzBoundary+"\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.png\"; filename=\"b.exe\"\r\n\r\n"+string(png)+"\r\n--"+fuzzBoundary+"--\r\n"))
	f.Add(fuzzBoundary, []byte("--"+fuzzBoundary+"\r\n\r\n"))
	f.Add(fuzzBoundary, []byte(nil))
	f.Add("", clean)
	f.Add("bad boundary with spaces", clean)
	f.Add("\"quoted\"", clean)

	mw := FileSecurity(FileSecurityConfig{
		EnableSignatureScan: true,
		MaxFileSize:         256 << 10,
		MaxScanBytes:        1 << 20,
		MaxConcurrentScans:  1,
		RouteID:             "fuzz",
	})

	f.Fuzz(func(t *testing.T, boundary string, body []byte) {
		var reached bool
		var forwarded []byte
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			forwarded, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
		req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if reached && !bytes.Equal(forwarded, body) {
			t.Fatalf("forwarded body differs from what was sent (boundary %q)\n sent=%q\n got=%q", boundary, body, forwarded)
		}
		if !reached && rr.Code < 400 {
			t.Fatalf("request was neither forwarded nor refused (status %d, boundary %q, body %q)", rr.Code, boundary, body)
		}
	})
}

// FuzzMultipartBoundary covers the Content-Type parse on its own, since it is
// the one piece of the upload path that runs before any size bound applies.
func FuzzMultipartBoundary(f *testing.F) {
	for _, s := range []string{
		"multipart/form-data; boundary=abc",
		"multipart/form-data; boundary=",
		"multipart/form-data",
		"multipart/form-data; boundary=\"q\"; boundary=r",
		"multipart/mixed; charset=\"\xff\"",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ct string) {
		_, _ = multipartBoundary(ct)
	})
}
