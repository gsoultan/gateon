// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// PHP-to-shell ("php2sell") is the family of request payloads that turn a PHP
// application into a command runner: stream wrappers that smuggle code
// (php://, data://, phar://, expect://, zip://, glob://), the code-evaluation
// sinks (eval, assert, create_function, preg_replace /e), the process-spawning
// APIs (shell_exec, passthru, proc_open, popen, pcntl_exec), object injection,
// and a dropped webshell. The detection lives in gwaf's core ruleset; this test
// pins that gateon's *default* WAF -- paranoia level 1, the minimal tier -- puts
// every one of them behind a 403, so a gwaf bump or a wiring change cannot drop
// the coverage silently. It is the regression guard for the php2sell pass.
func fireWAF(t *testing.T, pl int, method, url, contentType, body string) int {
	t.Helper()
	mw, err := WAF(WAFConfig{ParanoiaLevel: pl})
	if err != nil {
		t.Fatalf("create WAF pl=%d: %v", pl, err)
	}
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rr := httptest.NewRecorder()
	mw(okOrigin()).ServeHTTP(rr, req)
	return rr.Code
}

func TestPHP2ShellBlockedAtDefaultParanoia(t *testing.T) {
	cases := []struct {
		name, method, url, ct, body string
	}{
		// Stream wrappers: the value names a scheme PHP will fetch or execute.
		{"php-filter", http.MethodGet, "/?file=php://filter/convert.base64-encode/resource=index.php", "", ""},
		{"php-input", http.MethodGet, "/?p=php://input", "", ""},
		{"data-wrapper", http.MethodGet, "/?i=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOw==", "", ""},
		{"phar", http.MethodGet, "/?p=phar://malicious.phar/payload", "", ""},
		{"expect", http.MethodGet, "/?p=expect://id", "", ""},
		{"zip-wrapper", http.MethodGet, "/?p=zip://shell.zip%23payload.php", "", ""},
		{"glob-wrapper", http.MethodGet, "/?p=glob://*.php", "", ""},
		// Code-evaluation sinks.
		{"eval", http.MethodGet, "/?x=eval(base64_decode('aaa'))", "", ""},
		{"assert", http.MethodGet, "/?x=assert($_GET['c'])", "", ""},
		{"create_function", http.MethodGet, "/?x=create_function('','system($_GET[0]);')", "", ""},
		{"preg-replace-e", http.MethodGet, "/?x=preg_replace('/.*/e','system(chr(105))','')", "", ""},
		{"base64-eval-chain", http.MethodGet, "/?x=eval(gzinflate(base64_decode('AAAA')))", "", ""},
		// Process-spawning APIs that name one thing (gwaf's strong tier, High).
		{"shell_exec", http.MethodGet, "/?cmd=shell_exec('id')", "", ""},
		{"passthru", http.MethodGet, "/?cmd=passthru('id')", "", ""},
		{"proc_open", http.MethodGet, "/?cmd=proc_open('id',...)", "", ""},
		{"popen", http.MethodGet, "/?cmd=popen('id','r')", "", ""},
		{"pcntl_exec", http.MethodGet, "/?cmd=pcntl_exec('/bin/sh')", "", ""},
		{"system-nested-call", http.MethodGet, "/?cmd=system(base64_decode('aWQ='))", "", ""},
		{"call_user_func", http.MethodGet, "/?x=call_user_func('system','id')", "", ""},
		// Shell command substitution and the one injection form gwaf does report.
		{"dollar-paren-subst", http.MethodGet, "/?x=$(id)", "", ""},
		{"ifs-evasion", http.MethodGet, "/?cmd=cat${IFS}/etc/passwd", "", ""},
		// Object injection and a dropped webshell.
		{"php-object-injection", http.MethodGet, "/?data=O:8:%22stdClass%22:1:%7Bs:4:%22ping%22;s:9:%22phpinfo()%22;%7D", "", ""},
		{"webshell-eval-body", http.MethodPost, "/upload", "text/plain", "<?php system($_GET['c']); ?>"},
		{"webshell-multipart", http.MethodPost, "/upload", "multipart/form-data; boundary=X",
			"--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php system($_GET[0]); ?>\r\n--X--\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fireWAF(t, 1, tc.method, tc.url, tc.ct, tc.body); got != http.StatusForbidden {
				t.Fatalf("php2sell %q at default paranoia: got %d, want 403 -- the gateway stopped blocking a PHP-to-shell primitive", tc.name, got)
			}
		})
	}
}

// system('id') and exec('id') are the two process-spawning spellings gwaf keeps
// at Medium confidence, because "system(" appears in prose about this very
// attack and "exec" is also a SQL keyword and a shell builtin -- blocking them
// at High was measured as a false-positive source (gwaf
// TestMediumTierIsOptInAndReachable). gateon's paranoia level is the dial: the
// default (PL1 = High) lets them through, and an operator who raises it to PL2
// (Medium) gets them, accepting the prose false positives that come with. This
// pins that the dial actually reaches them, so the coverage is "opt-in", not
// "absent".
func TestPHP2ShellWeakTierReachableAtParanoia2(t *testing.T) {
	for _, name := range []string{"system", "exec"} {
		url := "/?cmd=" + name + "('id')"
		if got := fireWAF(t, 1, http.MethodGet, url, "", ""); got != http.StatusOK {
			t.Fatalf("%s('id') at PL1: got %d, want 200 -- the Medium tier must stay opt-in at the default", name, got)
		}
		if got := fireWAF(t, 2, http.MethodGet, url, "", ""); got != http.StatusForbidden {
			t.Fatalf("%s('id') at PL2: got %d, want 403 -- raising paranoia must reach the Medium tier", name, got)
		}
	}
}
