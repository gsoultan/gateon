// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package redact

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestURIMasksCredentialParametersAndKeepsTheRest(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"no query": {"/app/users/42", "/app/users/42"},
		"nothing to hide": {
			"/search?q=shoes&page=2", "/search?q=shoes&page=2",
		},
		"api key, token, access token, password": {
			"/v?api_key=K1&token=T1&access_token=A1&password=P1&page=2",
			"/v?api_key=[REDACTED]&token=[REDACTED]&access_token=[REDACTED]&password=[REDACTED]&page=2",
		},
		"oidc callback": {
			"app.example.com/cb?code=C1&state=S1&session_state=X",
			"app.example.com/cb?code=[REDACTED]&state=[REDACTED]&session_state=[REDACTED]",
		},
		"percent-encoded name": {"/x?api%5Fkey=K2&q=1", "/x?api%5Fkey=[REDACTED]&q=1"},
		"semicolon separator":  {"/x?q=1;secret=Z", "/x?q=1;secret=[REDACTED]"},
		"value shaped like a credential under an innocent name": {
			"/x?t=gateon_tok_abc&j=eyJhbGciOi.eyJzdWIi.sig&v=v4.local.xyz&q=ok",
			"/x?t=[REDACTED]&j=[REDACTED]&v=[REDACTED]&q=ok",
		},
		"name without value, empty value": {"/x?token&password=&q=1", "/x?token&password=&q=1"},
		"absolute referer": {
			"https://idp.example/authorize?client_id=c&client_secret=CS",
			"https://idp.example/authorize?client_id=c&client_secret=[REDACTED]",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := URI(tc.in); got != tc.want {
				t.Errorf("URI(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestURIAllocatesNothingWhenThereIsNothingToHide(t *testing.T) {
	for _, uri := range []string{"/plain/path", "/search?q=shoes&page=2&sort=asc"} {
		if n := testing.AllocsPerRun(100, func() { _ = URI(uri) }); n != 0 {
			t.Errorf("URI(%q) allocated %v times", uri, n)
		}
	}
}

func TestIsCredentialParam(t *testing.T) {
	for _, name := range []string{"password", "Passwd", "api_key", "apikey", "X-Api-Key", "access_token",
		"id_token", "client_secret", "code", "STATE", "pwd", "user[password]", "Authorization", "cookie", "sig"} {
		if !IsCredentialParam(name) {
			t.Errorf("IsCredentialParam(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"", "q", "page", "zipcode", "statement", "user", "email", "sort"} {
		if IsCredentialParam(name) {
			t.Errorf("IsCredentialParam(%q) = true, want false", name)
		}
	}
}

func TestIsCredentialHeader(t *testing.T) {
	for _, name := range []string{"Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Session-Token", "Private-Token"} {
		if !IsCredentialHeader(name) {
			t.Errorf("IsCredentialHeader(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"WWW-Authenticate", "Sec-WebSocket-Key", "Content-Type", "User-Agent", "X-Request-Id"} {
		if IsCredentialHeader(name) {
			t.Errorf("IsCredentialHeader(%q) = true, want false", name)
		}
	}
}

func TestIsURIHeader(t *testing.T) {
	for _, name := range []string{"Referer", "Location", "Content-Location", "X-Forwarded-Uri", "X-Original-URL"} {
		if !IsURIHeader(name) {
			t.Errorf("IsURIHeader(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"Host", "Origin", "Content-Type"} {
		if IsURIHeader(name) {
			t.Errorf("IsURIHeader(%q) = true, want false", name)
		}
	}
}

func TestTextMasksEveryCredentialShape(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte("alice:B4SIC"))
	cases := map[string]struct{ in, want string }{
		"form body": {
			"user=alice&password=P%40ss&remember=1",
			"user=alice&password=[REDACTED]&remember=1",
		},
		"json, every value type": {
			`{"user":"alice","password":"P1","pin":1234,"api_key":{"k":"v"},"tokens":["a","b"],"otp":null,"n":2}`,
			`{"user":"alice","password":"[REDACTED]","pin":"[REDACTED]","api_key":"[REDACTED]","tokens":"[REDACTED]","otp":null,"n":2}`,
		},
		"json with spaces and escapes": {
			`{ "secret" : "a\"b" , "name" : "x" }`,
			`{ "secret" : "[REDACTED]" , "name" : "x" }`,
		},
		"json cut inside a credential string": {
			`{"name":"x","password":"hunter`,
			`{"name":"x","password":"[REDACTED]`,
		},
		"json cut inside a credential object": {
			`{"credentials":{"user":"a","pass`,
			`{"credentials":"[REDACTED]"`,
		},
		"bearer and basic": {
			"Authorization: Bearer abcdefgh12345 and Basic " + basic + " end",
			"Authorization: Bearer [REDACTED] and Basic [REDACTED] end",
		},
		"bearer and basic in prose are left alone": {
			"the bearer of bad news has basic rights", "the bearer of bad news has basic rights",
		},
		"jwt anywhere": {
			"<p>eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl</p>",
			"<p>[REDACTED]</p>",
		},
		"gateway and paseto tokens keep their prefix": {
			"t gateon_tok_SECRET1 and v4.local.SECRET2.x",
			"t gateon_tok_[REDACTED] and v4.local.[REDACTED]",
		},
		"quoted pair value": {`token="abc def" q=1`, `token="[REDACTED]" q=1`},
		"multipart": {
			"--b\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n" +
				"--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nM1\r\n--b--\r\n",
			"--b\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n" +
				"--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n[REDACTED]\r\n--b--\r\n",
		},
		"html input named password is not a multipart part": {
			"<input name=\"password\">\n\nhello\n--x", "<input name=\"password\">\n\nhello\n--x",
		},
		"nothing to hide": {"plain text, q=1 & page=2", "plain text, q=1 & page=2"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Text(tc.in); got != tc.want {
				t.Errorf("Text(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBodyCapsAndRefusesWhatItCannotRead(t *testing.T) {
	if got := Body(""); got != "" {
		t.Errorf("Body(\"\") = %q", got)
	}
	if got := Body("password=x"); got != "password=[REDACTED]" {
		t.Errorf("Body redacts nothing: %q", got)
	}

	long := strings.Repeat("a", MaxBodyBytes+10)
	got := Body(long)
	if !strings.HasSuffix(got, truncatedNote) || len(got) != MaxBodyBytes+len(truncatedNote) {
		t.Errorf("a %d-byte body was kept as %d bytes", len(long), len(got))
	}

	for name, in := range map[string]string{
		"gzip":     "\x1f\x8b\x08\x00password=secret",
		"protobuf": "\x0a\x08password\x12\x06secret",
		"invalid":  "abc\xffpassword=secret",
	} {
		got := Body(in)
		if strings.Contains(got, "secret") || !strings.Contains(got, "non-text body not kept") {
			t.Errorf("%s body kept as %q", name, got)
		}
	}

	// A capture limit can cut a character in half; that is still text.
	if got := Body("password=x é"[:len("password=x é")-1]); got != "password=[REDACTED] " {
		t.Errorf("a body cut mid-character was not kept as text: %q", got)
	}
}

// The telemetry store asks both about every header of every trace it keeps,
// and canonical header names are mixed case.
func TestHeaderClassificationAllocatesNothing(t *testing.T) {
	for _, name := range []string{"Content-Type", "WWW-Authenticate", "X-Forwarded-Uri", "Accept-Language"} {
		n := testing.AllocsPerRun(100, func() {
			_ = IsCredentialHeader(name)
			_ = IsURIHeader(name)
			_ = IsCredentialParam(name)
		})
		if n != 0 {
			t.Errorf("classifying %q allocated %v times", name, n)
		}
	}
}

func TestTextAllocatesNothingWhenThereIsNothingToHide(t *testing.T) {
	s := `{"user":"alice","n":2} q=1&page=2 the bearer of news`
	if n := testing.AllocsPerRun(100, func() { _ = Text(s) }); n != 0 {
		t.Errorf("Text allocated %v times", n)
	}
}
