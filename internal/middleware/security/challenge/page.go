// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"html/template"
	"net/http"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// The two pages a browser can be shown -- the JS challenge and the
// proof-of-work fallback -- are one page with two ways of handing in the work,
// so that what a person sees, and what a screen reader reads, is the same
// whichever stopped them (ADR 0045).
const (
	// modeAnswer: answer a bot-management challenge at this URL, then ask
	// whether the pass cookie stuck, then reload.
	modeAnswer = "answer"
	// modePow: retry this URL with the proof-of-work headers, then reload.
	modePow = "pow"
)

// pageData is everything the page interpolates. None of it is text the client
// wrote: the nonce is fresh, the ID is digits, dots, dashes and hex, the
// method is one of challengeMethod's five, bits is a small integer and mode
// a constant. html/template escapes each for its context regardless.
type pageData struct {
	Nonce  string
	ID     string
	Method string
	Bits   int
	Mode   string
}

// writeChallengePage answers with the challenge page under a CSP that admits
// only its own script, and no-store so that no cache hands one client's
// challenge to another.
func writeChallengePage(w http.ResponseWriter, status int, data pageData) {
	data.Nonce = kind.GenerateNonce()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'nonce-"+data.Nonce+
		"'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	if err := challengePage.Execute(w, data); err != nil {
		logger.L.LogDebug("writing a challenge page failed", "error", err)
	}
}

var challengePage = template.Must(template.New("challenge").Parse(challengePageHTML))

// challengePageHTML is meant to be read by a screen reader as easily as it is
// skipped past by a sighted user: one heading, one live status line that says
// what is happening and, on failure, what to do, a <noscript> explanation, and
// a Try again button that is the only way to start over -- a failed check
// never reloads by itself. A sessionStorage marker (a timestamp, not a
// credential) stops the one loop a page cannot otherwise see: work that the
// gateway accepted and a reload that is challenged anyway, as when the
// browser refuses the cookie.
//
// SHA-256 is computed in script rather than with crypto.subtle, which exists
// only in a secure context: on a plain-HTTP site the page could never finish.
const challengePageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Checking your browser</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f4f4f4;color:#1a1a1a}
main{max-width:32rem;margin:1rem;padding:2rem;background:#fff;border-radius:8px;box-shadow:0 4px 6px rgba(0,0,0,.1);text-align:center;line-height:1.5}
button{font:inherit;padding:.5rem 1.25rem;margin-top:1rem;cursor:pointer}
button:focus-visible{outline:3px solid #1c7ed6;outline-offset:2px}
</style>
</head>
<body>
<main>
<h1>Checking your browser</h1>
<p id="gateon-challenge-status" role="status" aria-live="polite">This site asks your browser to do a short calculation before it continues. It usually takes a few seconds and needs nothing from you.</p>
<noscript><p>This check needs JavaScript. Turn on JavaScript for this site, then reload the page.</p></noscript>
<button id="gateon-challenge-retry" type="button" hidden>Try again</button>
</main>
<script nonce="{{.Nonce}}">
(function () {
  "use strict";
  var id = {{.ID}}, bits = {{.Bits}}, method = {{.Method}}, mode = {{.Mode}};
  var here = location.href.split("#")[0];
  var marker = "gateon-challenge-passed-at:" + location.pathname + location.search;
  var statusLine = document.getElementById("gateon-challenge-status");
  var retry = document.getElementById("gateon-challenge-retry");
  function reloadPage() { if (method === "GET") { location.reload(); } else { location.replace(here); } }
  function say(text) { statusLine.textContent = text; }
  function fail(text) { say(text); retry.hidden = false; retry.focus(); }
  function lost() { fail("The connection to the site failed. Check your connection, then select Try again."); }
  function remember() { try { sessionStorage.setItem(marker, String(Date.now())); } catch (e) {} }
  function passedJustNow() {
    try { return Date.now() - Number(sessionStorage.getItem(marker) || 0) < 30000; } catch (e) { return false; }
  }
  retry.addEventListener("click", function () {
    try { sessionStorage.removeItem(marker); } catch (e) {}
    reloadPage();
  });
  function done() { say("Done. Loading the page."); remember(); reloadPage(); }

  var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var W = new Int32Array(64);
  function sha256(s) {
    var l = s.length, nb = ((l + 8) >> 6) + 1, M = new Int32Array(nb * 16), i, b;
    for (i = 0; i < l; i++) { M[i >> 2] |= (s.charCodeAt(i) & 255) << (24 - (i & 3) * 8); }
    M[l >> 2] |= 0x80 << (24 - (l & 3) * 8);
    M[nb * 16 - 1] = l * 8;
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    for (b = 0; b < nb; b++) {
      for (i = 0; i < 16; i++) { W[i] = M[b * 16 + i]; }
      for (i = 16; i < 64; i++) {
        var x = W[i - 15], y = W[i - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
      }
      var a = H[0], c1 = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var t2 = (S0 + ((a & c1) ^ (a & c) ^ (c1 & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = c1; c1 = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + c1) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    return H;
  }
  function leadingZero(H, n) {
    for (var i = 0; n > 0; i++, n -= 32) {
      if ((H[i] >>> (32 - (n < 32 ? n : 32))) !== 0) { return false; }
    }
    return true;
  }
  function toHex(H) {
    var out = "";
    for (var i = 0; i < 8; i++) { out += ("0000000" + (H[i] >>> 0).toString(16)).slice(-8); }
    return out;
  }

  function confirmed(res) {
    if (res.status !== 204) {
      fail("Your browser did not keep the site's confirmation cookie. Allow cookies for this site, then select Try again.");
      return;
    }
    done();
  }
  function answered(res) {
    if (res.status === 410) {
      fail("This check expired before it finished. Select Try again to start a new one.");
      return;
    }
    if (res.status !== 204) {
      fail("The site could not confirm this check. Select Try again. If it keeps failing, contact the site owner.");
      return;
    }
    return fetch(here, {method: method, headers: {"X-Gateon-Challenge": "check"}, credentials: "same-origin", cache: "no-store"}).then(confirmed);
  }
  function submitAnswer(nonce) {
    return fetch(here, {method: method, credentials: "same-origin", cache: "no-store",
      headers: {"X-Gateon-Challenge": "answer", "X-Gateon-Challenge-ID": id, "X-Gateon-Challenge-Nonce": String(nonce)}}).then(answered);
  }
  function submitPow(nonce, H) {
    return fetch(here, {credentials: "same-origin", cache: "no-store",
      headers: {"X-Gateon-Pow-ID": id, "X-Gateon-Pow-Nonce": String(nonce), "X-Gateon-Pow-Solution": toHex(H)}}).then(function (res) {
      if (res.status === 429) {
        fail("The site did not accept this check. Select Try again. If it keeps failing, contact the site owner.");
        return;
      }
      done();
    });
  }

  var nonce = 0;
  function work() {
    try {
      for (var end = nonce + 20000; nonce < end; nonce++) {
        var H = sha256(mode === "pow" ? id + nonce : id + ":" + nonce);
        if (leadingZero(H, bits)) {
          say("Almost done. Confirming with the site.");
          (mode === "pow" ? submitPow(nonce, H) : submitAnswer(nonce)).catch(lost);
          return;
        }
      }
      setTimeout(work, 0);
    } catch (e) {
      fail("Your browser could not run this check. Select Try again, or try another browser.");
    }
  }
  if (passedJustNow()) {
    fail("The site asked for this check again right after your browser passed it. Select Try again. If it keeps happening, contact the site owner.");
    return;
  }
  work();
})();
</script>
</body>
</html>
`
