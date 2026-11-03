// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
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
	for _, seed := range multipartStructuredSeeds() {
		f.Add(seed.boundary, seed.body)
	}

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

// multipartSeed is one structure-aware starting point for the upload fuzzer.
type multipartSeed struct {
	boundary string
	body     []byte
}

// multipartParts assembles a body from raw parts, each a header block and its
// content, so a seed can say exactly which bytes sit between the delimiters
// (a lower-cased header, a missing CR, a transfer encoding) instead of getting
// whatever mime/multipart's writer would emit. nl is the line ending.
func multipartParts(boundary, nl string, parts ...string) []byte {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--" + boundary + nl + p + nl)
	}
	b.WriteString("--" + boundary + "--" + nl)
	return []byte(b.String())
}

// multipartStructuredSeeds are the shapes a multipart parser and a backend
// most often read differently, written out whole. The first seed set covered
// a single part well; the corpus stopped growing on it because the fuzzer
// almost never invents a second part, a nested multipart, a transfer encoding
// or an RFC 2231 filename from bytes alone. Each of these is a real body that
// mutations can bend, and several carry an executable or a webshell somewhere
// the scanner has to look for it.
func multipartStructuredSeeds() []multipartSeed {
	const b = fuzzBoundary
	elf := "\x7fELF" + strings.Repeat("\x00", 64)
	png := "\x89PNG\r\n\x1a\n" + strings.Repeat("\x00", 64)
	disp := func(name, file string) string {
		return `Content-Disposition: form-data; name="` + name + `"; filename="` + file + `"`
	}
	long := strings.Repeat("x", 70) // the RFC 2046 maximum boundary length
	var empties []string
	for range 24 {
		empties = append(empties, "Content-Disposition: form-data; name=\"e\"\r\n")
	}
	return []multipartSeed{
		// A form field and a file, the shape every real upload form sends.
		{b, multipartParts(b, "\r\n",
			"Content-Disposition: form-data; name=\"title\"\r\n\r\nhello",
			disp("file", "a.png")+"\r\nContent-Type: image/png\r\n\r\n"+png)},
		// A field whose content is itself multipart/mixed, carrying a file
		// (RFC 2388 section 5.2; Apache commons-fileupload unpacks it).
		{b, multipartParts(b, "\r\n",
			"Content-Disposition: form-data; name=\"files\"\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n"+
				string(multipartParts("inner", "\r\n",
					"Content-Disposition: file; filename=\"a.exe\"\r\nContent-Type: application/octet-stream\r\n\r\n"+elf,
					"Content-Disposition: file; filename=\"b.png\"\r\nContent-Type: image/png\r\n\r\n"+png)))},
		// Transfer encodings: base64 hides the magic bytes from a reader that
		// does not decode it; Go's reader decodes quoted-printable itself.
		{b, multipartParts(b, "\r\n",
			disp("f", "a.png")+"\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\n"+
				base64.StdEncoding.EncodeToString([]byte(png+elf)))},
		{b, multipartParts(b, "\r\n",
			disp("f", "a.bin")+"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=7FELF=00=00=00=00")},
		// Bare LF line endings throughout.
		{b, multipartParts(b, "\n", disp("f", "a.exe")+"\n\n"+elf)},
		// Content that contains the delimiter without being one.
		{b, multipartParts(b, "\r\n", disp("f", "a.txt")+"\r\n\r\nx--"+b+"y\r\n--"+b+"-z\r\n -- "+b)},
		// A preamble before the first delimiter and an epilogue after the last.
		{b, append([]byte("preamble\r\n"), append(multipartParts(b, "\r\n", disp("f", "a.exe")+"\r\n\r\n"+elf), "epilogue"...)...)},
		// RFC 2231 / 5987 extended filename, alone and beside a plain one.
		{b, multipartParts(b, "\r\n", "Content-Disposition: form-data; name=\"f\"; filename*=UTF-8''evil%2Eexe\r\n\r\n"+elf)},
		{b, multipartParts(b, "\r\n", "Content-Disposition: form-data; name=\"f\"; filename=\"a.png\"; filename*=UTF-8''a.exe\r\n\r\n"+png+elf)},
		// Header case, spacing and quoting a lenient backend accepts.
		{b, multipartParts(b, "\r\n", "content-disposition:form-data;name=f;filename=a.exe\r\ncontent-type:application/x-msdownload\r\n\r\nMZ\x90\x00PE\x00\x00")},
		// Two Content-Disposition headers on one part.
		{b, multipartParts(b, "\r\n", disp("f", "a.png")+"\r\n"+disp("f", "a.exe")+"\r\n\r\n"+png+elf)},
		// A declared type that disagrees with both the name and the content.
		{b, multipartParts(b, "\r\n", disp("f", "a.jpg")+"\r\nContent-Type: image/jpeg\r\n\r\nPK\x03\x04"+strings.Repeat("\x00", 26))},
		// A webshell behind an image extension, for the signature engine.
		{b, multipartParts(b, "\r\n", disp("f", "a.php.jpg")+"\r\nContent-Type: image/jpeg\r\n\r\n\xff\xd8\xff\xe0<?php system($_GET['c']); ?>")},
		// Whitespace after a delimiter, which RFC 2046 allows.
		{b, []byte("--" + b + " \t \r\n" + disp("f", "a.exe") + "\r\n\r\n" + elf + "\r\n--" + b + "-- \r\n")},
		// Many empty parts, then the file.
		{b, multipartParts(b, "\r\n", append(empties, disp("f", "a.exe")+"\r\n\r\n"+elf)...)},
		// The longest boundary RFC 2046 allows.
		{long, multipartParts(long, "\r\n", disp("f", "a.exe")+"\r\n\r\n"+elf)},
	}
}

// TestMultipartStructuredSeedsParse keeps the seeds above honest: each is a
// body Go's multipart reader reads to its closing delimiter, with at least one
// part. A seed the reader refuses on its first line only ever exercises the
// malformed-body refusal, which the first seed set already covers, and the
// fuzzer would start from noise again without anyone noticing.
func TestMultipartStructuredSeedsParse(t *testing.T) {
	for i, seed := range multipartStructuredSeeds() {
		mr := multipart.NewReader(bytes.NewReader(seed.body), seed.boundary)
		parts := 0
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("seed %d: part %d: %v\n%q", i, parts, err, seed.body)
			}
			if _, err := io.Copy(io.Discard, p); err != nil {
				t.Fatalf("seed %d: reading part %d: %v", i, parts, err)
			}
			parts++
		}
		if parts == 0 {
			t.Fatalf("seed %d has no parts: %q", i, seed.body)
		}
	}
}
