// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// Any web page can make its visitors' browsers request this gateway's trap
// paths -- an <img src="https://gateway/.env"> in a forum post is enough -- and
// the honeypot treated that request exactly as a scanner's. One page view
// banned the visitor's address for fifteen minutes, a page left open walked it
// up the ladder to a day, and behind CGNAT or an office egress it took everyone
// sharing the address. Nothing about those requests is unusual except what the
// browser itself says about them: Sec-Fetch-Site cross-site, Sec-Fetch-Mode
// no-cors, Sec-Fetch-Dest image.
//
// Skipping the honeypot's ban alone would not have fixed it. The trap hit is
// recorded as a blocked threat, and a recorded threat carries a reputation
// penalty and counts toward escalating its fingerprint to a block: two trap
// images took the visitor's reputation to zero and three had its browser's
// fingerprint refused on every route, each a ban by another name.
//
// Root cause in one sentence: a request the visitor's browser was made to send
// was held against the visitor, as though the visitor had chosen to send it.

// crossSiteLoad is what a browser sends for <img src="https://gateway{path}">
// (or another subresource, per dest) on a page at another site: the page as
// Referer, no cookie, and the Fetch Metadata that says so.
func crossSiteLoad(ip, path, dest string) *http.Request {
	return browserRequest(ip, path, map[string]string{
		"Referer":          "https://unrelated-forum.example/thread/42",
		headerSecFetchSite: "cross-site",
		headerSecFetchMode: "no-cors",
		headerSecFetchDest: dest,
	})
}

// visitorRequest is a stock browser's own request for path.
func visitorRequest(ip, path string) *http.Request {
	return browserRequest(ip, path, nil)
}

// browserRequest is a stock browser's request carrying extra headers, as the
// entrypoint hands it to the middlewares: a request state holding the resolved
// fingerprint. Without the fingerprint on the state, UserMitigation -- which
// reads it there and nowhere else -- passes every request, and a test built on
// that would miss a fingerprint block the deployed gateway applies.
func browserRequest(ip, path string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = net.JoinHostPort(ip, "51000")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0")
	req.Header.Set("Accept-Language", "en-US")
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	req = req.WithContext(request.WithState(req.Context(), &request.RequestState{}))
	return telemetry.WithFingerprint(req)
}

// deployedChain is a honeypot in front of the enforcement every route carries
// (router.go: IPMitigation, UserMitigation, ReputationBlocker), over a backend
// that answers 200 -- the path a visitor's next request takes.
func deployedChain(t *testing.T, honeypot kind.Middleware) http.Handler {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return honeypot(kind.Chain(
		identity.IPMitigation(),
		identity.UserMitigation(),
		identity.ReputationBlocker("honeypot-crosssite-test"),
	)(ok))
}

// recordedThreats runs the telemetry store in a scratch directory -- the threat
// pipeline, with its reputation penalty and fingerprint escalation -- and
// returns a function reporting every threat processed since.
func recordedThreats(t *testing.T) func() []telemetry.SecurityThreat {
	t.Helper()
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "telemetry.db"), 1); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	ch := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() {
		telemetry.ThreatBroadcaster.Unsubscribe(ch)
		_ = telemetry.ClosePathStatsStore(context.Background())
		telemetry.ResetFingerprintSightings()
	})
	return func() []telemetry.SecurityThreat {
		// FlushThreats returns once everything queued before it is processed,
		// which is when it is broadcast, so the drain below misses nothing.
		telemetry.FlushThreats()
		var out []telemetry.SecurityThreat
		for {
			select {
			case th := <-ch:
				out = append(out, th)
			default:
				return out
			}
		}
	}
}

// forgetReputation resets the score of the identity req resolves to once the
// test ends; scores are process-wide.
func forgetReputation(t *testing.T, req *http.Request) {
	t.Helper()
	id := telemetry.GetReputationID(req)
	t.Cleanup(func() { telemetry.ResetReputation(id) })
}

// newTestGlobals is a stock global configuration in a scratch file: deception
// off, so the built-in trap paths apply.
func newTestGlobals(t *testing.T) config.GlobalConfigStore {
	t.Helper()
	return config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
}

func serveCode(h http.Handler, req *http.Request) (int, string) {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, strings.TrimSpace(rr.Body.String())
}

// honeypotThreatsFrom counts the honeypot threats recorded against ip.
func honeypotThreatsFrom(threats []telemetry.SecurityThreat, ip string) int {
	n := 0
	for _, th := range threats {
		if th.Type == "honeypot_triggered" && th.SourceIP == ip {
			n++
		}
	}
	return n
}

// TestAThirdPartyPageCannotBanItsVisitors is the regression test, through both
// honeypots and the whole threat pipeline: four trap images on a forum page are
// refused and recorded, and the visitor is refused nothing afterwards -- not
// the page's other images, which carry the same fingerprint as the trap loads,
// and not their own browsing.
func TestAThirdPartyPageCannotBanItsVisitors(t *testing.T) {
	for name, hp := range map[string]kind.Middleware{
		"global":    HoneypotGlobal(newTestGlobals(t)),
		"per-route": Honeypot(HoneypotConfig{Paths: defaultHoneypotPaths()}),
	} {
		t.Run(name, func(t *testing.T) {
			resetHoneypotState(t)
			threats := recordedThreats(t)
			visitor := map[string]string{"global": "198.51.100.199", "per-route": "198.51.100.198"}[name]
			gateway := deployedChain(t, hp)
			forgetReputation(t, crossSiteLoad(visitor, "/", "image"))
			forgetReputation(t, visitorRequest(visitor, "/"))

			for _, path := range []string{"/.env", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa"} {
				if got, _ := serveCode(gateway, crossSiteLoad(visitor, path, "image")); got != http.StatusForbidden {
					t.Fatalf("a cross-site image load of the trap %s got %d; the trap must still refuse it", path, got)
				}
			}
			if n := honeypotThreatsFrom(threats(), visitor); n != 4 {
				t.Errorf("%d of the 4 trap loads were recorded as threats; each must still be recorded", n)
			}

			for what, req := range map[string]*http.Request{
				"the forum page's own image from this gateway": crossSiteLoad(visitor, "/logo.png", "image"),
				"the visitor's own browsing":                   visitorRequest(visitor, "/account"),
			} {
				if got, body := serveCode(gateway, req); got != http.StatusOK {
					t.Errorf("after a third-party page made the visitor's browser load four trap images, "+
						"%s got %d (%q): the visitor was banned for a request it did not choose to send", what, got, body)
				}
			}
		})
	}
}

// TestAForgedCrossSiteMarkerGainsOnlyAMissingBan pins exactly what a scanner
// gets for sending the three headers itself: its request is still refused and
// still recorded, and only the ban -- every consequence that would outlive the
// request -- is missing. The same scanner without them is banned, which is what
// makes this a statement about the headers and not about the scanner.
func TestAForgedCrossSiteMarkerGainsOnlyAMissingBan(t *testing.T) {
	resetHoneypotState(t)
	threats := recordedThreats(t)
	const scanner = "203.0.113.251"
	h := deployedChain(t, Honeypot(HoneypotConfig{Paths: defaultHoneypotPaths()}))

	forged := browserRequest(scanner, "/.env", map[string]string{
		"User-Agent":       "curl/8.9.1",
		headerSecFetchSite: "cross-site",
		headerSecFetchMode: "no-cors",
		headerSecFetchDest: "image",
	})
	forgetReputation(t, forged)
	if got, _ := serveCode(h, forged); got != http.StatusForbidden {
		t.Fatalf("a trap request carrying forged cross-site headers got %d: the headers skipped the deny decision", got)
	}
	if n := honeypotThreatsFrom(threats(), scanner); n != 1 {
		t.Errorf("the forged trap request was recorded %d times, want once", n)
	}
	if honeypotBanActive(scanner) {
		t.Fatal("control: the forged request banned the scanner, so this test says nothing about the headers")
	}

	plain := browserRequest(scanner, "/.env", map[string]string{"User-Agent": "curl/8.9.1"})
	if got, _ := serveCode(h, plain); got != http.StatusForbidden {
		t.Fatalf("control: the same trap request without the headers got %d", got)
	}
	if !honeypotBanActive(scanner) {
		t.Error("the scanner's own trap request, without the headers, did not ban it")
	}
}

// TestOnlyACrossSiteSubresourceIsSpared pins how narrow the exemption is. Every
// value the rule accepts is one a scanner can claim, so anything that is not a
// subresource embedded by another site's page -- a same-site load, a
// navigation, an iframe, a script's fetch(), a CORS request -- is banned as
// before.
func TestOnlyACrossSiteSubresourceIsSpared(t *testing.T) {
	h := Honeypot(HoneypotConfig{Paths: defaultHoneypotPaths()})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, tc := range []struct {
		site, mode, dest string
		spared           bool
	}{
		{"cross-site", "no-cors", "image", true},
		{"cross-site", "no-cors", "script", true},
		{"cross-site", "no-cors", "style", true},
		{"cross-site", "no-cors", "font", true},
		{"cross-site", "no-cors", "audio", true},
		{"cross-site", "no-cors", "video", true},
		{"cross-site", "no-cors", "track", true},
		{"cross-site", "no-cors", "embed", true},
		{"cross-site", "no-cors", "object", true},

		{"", "", "", false},                           // no Fetch Metadata at all: a scanner, or an old client
		{"same-origin", "no-cors", "image", false},    // the gateway's own page
		{"same-site", "no-cors", "image", false},      // a sibling subdomain the operator controls
		{"none", "navigate", "document", false},       // typed into the address bar
		{"cross-site", "navigate", "document", false}, // a clicked link
		{"cross-site", "navigate", "iframe", false},   // an iframe
		{"cross-site", "no-cors", "empty", false},     // a script's fetch(url, {mode: "no-cors"})
		{"cross-site", "cors", "image", false},        // <img crossorigin>
		{"cross-site", "no-cors", "", false},          // no destination named
		{"cross-site", "no-cors", "serviceworker", false},
		{"Cross-Site", "No-Cors", "Image", false}, // browsers send lower case; nothing else is theirs
		{"cross-site", "", "image", false},
		{"", "no-cors", "image", false},
	} {
		name := tc.site + "|" + tc.mode + "|" + tc.dest
		t.Run(name, func(t *testing.T) {
			resetHoneypotState(t)
			const ip = "198.51.100.197"
			req := browserRequest(ip, "/.env", map[string]string{
				headerSecFetchSite: tc.site, headerSecFetchMode: tc.mode, headerSecFetchDest: tc.dest,
			})
			if got, _ := serveCode(h, req); got != http.StatusForbidden {
				t.Fatalf("the trap answered %d; it refuses every request whatever the headers", got)
			}
			if banned := honeypotBanActive(ip); banned == tc.spared {
				t.Errorf("banned=%v for Sec-Fetch-Site %q, Sec-Fetch-Mode %q, Sec-Fetch-Dest %q; want banned=%v",
					banned, tc.site, tc.mode, tc.dest, !tc.spared)
			}
		})
	}
}

// TestTheHoneypotSaysWhatItDid pins the log line's and the threat record's
// account of a trap hit. It used to say "IP blocked for 24h" whatever rung
// applied, whether or not anything was banned -- which, with a cross-site load
// that bans nothing and an IPv6 ban that covers a /64, would now be wrong in
// both directions.
func TestTheHoneypotSaysWhatItDid(t *testing.T) {
	resetHoneypotState(t)
	threats := recordedThreats(t)
	mitigation.SetAllowlist([]netip.Prefix{netip.MustParsePrefix("192.0.2.77/32")})
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
	h := Honeypot(HoneypotConfig{Paths: defaultHoneypotPaths()})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	hit := func(req *http.Request) string {
		forgetReputation(t, req)
		serveCode(h, req)
		for _, th := range threats() {
			if th.Type == "honeypot_triggered" {
				return th.Details
			}
		}
		t.Fatalf("no honeypot threat was recorded for %s %s", req.RemoteAddr, req.URL.Path)
		return ""
	}
	for _, tc := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{"first hit", visitorRequest("203.0.113.61", "/.env"), "banned 203.0.113.61 for 15m0s"},
		{"second hit", visitorRequest("203.0.113.61", "/.aws"), "banned 203.0.113.61 for 1h0m0s"},
		{"ipv6", visitorRequest("2001:db8:1:2::10", "/.git/config"), "banned 2001:0db8:0001:0002:: for 15m0s"},
		{"cross-site", crossSiteLoad("203.0.113.62", "/.env", "image"), "not held against the source (no strike, no ban)"},
		{"allowlisted", visitorRequest("192.0.2.77", "/.env"), "source not banned"},
	} {
		if got := hit(tc.req); !strings.Contains(got, tc.want) {
			t.Errorf("%s: the threat says %q, want it to say %q", tc.name, got, tc.want)
		}
		// A banned client never reaches the trap again; let the ban run out, as
		// waiting would, so the next hit is recorded. Its strikes stay.
		lapseBan(telemetry.ClientIPOf(tc.req))
	}

	// Last, because it leaves the ban list full: at capacity nothing new is
	// banned, and the record must not claim otherwise.
	until := time.Now().Add(time.Hour)
	for i := range maxHoneypotBlocklist {
		blockHoneypotIP(ipv4For(i), until)
	}
	if got, want := hit(visitorRequest("203.0.113.63", "/.env")), "source not banned"; !strings.Contains(got, want) {
		t.Errorf("with the ban list full, the threat says %q, want it to say %q", got, want)
	}
}

// lapseBan moves ip's ban into the past, as waiting it out would; its strikes
// stay, as they would inside the strike window.
func lapseBan(ip string) {
	key := honeypotKey(ip)
	blocklistMu.Lock()
	defer blocklistMu.Unlock()
	if _, banned := honeypotBlocklist[key]; banned {
		honeypotBlocklist[key] = time.Now().Add(-time.Second)
	}
}
