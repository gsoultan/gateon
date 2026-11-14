// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bufio"
	"bytes"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// scriptedClamd is a scanner that reads one INSTREAM upload to its end and
// then answers with reply, or closes without a word when reply is empty.
func scriptedClamd(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go answerInstream(c, reply)
		}
	}()
	return "tcp://" + ln.Addr().String()
}

func answerInstream(c net.Conn, reply string) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	if _, err := r.ReadString('\n'); err != nil { // the command line
		return
	}
	for {
		var size [4]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return
		}
		n := int(size[0])<<24 | int(size[1])<<16 | int(size[2])<<8 | int(size[3])
		if n == 0 {
			break
		}
		if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
			return
		}
	}
	_, _ = io.WriteString(c, reply)
}

func uploadThrough(t *testing.T, cfg FileSecurityConfig) (status int, reachedBackend bool) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "report.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("quarterly numbers"))
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	FileSecurity(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reachedBackend = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	return rec.Code, reachedBackend
}

// TestOnlyAVerdictOfCleanIsClean: the scan read clamd's reply looking for
// FOUND and called everything else clean. clamd answers "ERROR" when it could
// not scan -- a stream past StreamMaxLength, a database that failed to load --
// and a connection that closes or a service that is not clamd answers nothing
// it recognises. Each of those forwarded the upload as scanned and clean on a
// route configured to refuse what it cannot scan. A file is clean when the
// scanner says OK, and only then.
func TestOnlyAVerdictOfCleanIsClean(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
	}{
		{"an error from clamd", "INSTREAM size limit exceeded. ERROR\n"},
		{"a scan error from clamd", "stream: Can't allocate memory ERROR\n"},
		{"no reply at all", ""},
		{"a reply that is not clamd's", "HTTP/1.1 400 Bad Request\n"},
		{"a verdict with something after it", "stream: OK but not really\n"},
		{"an unterminated verdict", "stream: OK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := FileSecurityConfig{EnableClamAV: true, ClamAVAddr: scriptedClamd(t, tc.reply), ScanTimeout: 5 * time.Second}
			status, reached := uploadThrough(t, cfg)
			if reached || status == http.StatusOK {
				t.Fatalf("status %d, reached backend = %v: an upload the scanner did not clear was forwarded", status, reached)
			}
		})
	}
}

// TestAScannerVerdictIsHonoured is the control: the same fixture forwards a
// file clamd clears and refuses one it names, so the refusals above are the
// reply being read and not a scanner that cannot be reached.
func TestAScannerVerdictIsHonoured(t *testing.T) {
	cfg := FileSecurityConfig{EnableClamAV: true, ClamAVAddr: scriptedClamd(t, "stream: OK\n"), ScanTimeout: 5 * time.Second}
	if status, reached := uploadThrough(t, cfg); !reached || status != http.StatusOK {
		t.Errorf("a clean file: status %d, reached backend = %v", status, reached)
	}
	cfg.ClamAVAddr = scriptedClamd(t, "stream: Win.Test.EICAR_HDB-1 FOUND\n")
	if status, reached := uploadThrough(t, cfg); reached || status != http.StatusForbidden {
		t.Errorf("an infected file: status %d, reached backend = %v", status, reached)
	}
}
