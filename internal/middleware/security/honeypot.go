// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
)

var (
	honeypotBlocklist = make(map[string]time.Time)
	honeypotStrikes   = make(map[string]honeypotStrike)
	blocklistMu       sync.RWMutex
)

// honeypotStrike counts how many times one address has reached a trap, and when
// it last did, so a ban can escalate rather than starting at its maximum.
type honeypotStrike struct {
	count int
	last  time.Time
}

// honeypotBanLadder is how long an address is banned for on its 1st, 2nd, 3rd
// and subsequent trap hits.
//
// A single hit used to cost 24 hours. The trap paths are chosen so that no
// legitimate client requests them (/.env, /.git, /.aws ...), which makes one hit
// strong evidence about the *request* — but the ban lands on an address, and an
// address is shared. Behind CGNAT or a corporate egress, one security scan the
// customer ran themselves, one compromised laptop, or one over-eager crawler
// took the whole office off the site until the next day.
//
// Escalation is the corroboration. A one-off costs fifteen minutes, which is
// unremarkable if it was a mistake and useless to an attacker; anyone who comes
// back reaches the full day quickly, and repetition over time is exactly the
// independent evidence a single request cannot supply. This is the same
// principle internal/security/mitigation applies to correlated incidents:
// escalate on repetition rather than act at maximum severity on first contact.
var honeypotBanLadder = []time.Duration{
	15 * time.Minute,
	1 * time.Hour,
	6 * time.Hour,
	24 * time.Hour,
}

// honeypotStrikeWindow is how long a strike counts toward escalation. An address
// that stays away for a day starts again at the bottom of the ladder, so a
// dynamic address reassigned to someone else does not inherit a stranger's
// record.
const honeypotStrikeWindow = 24 * time.Hour

// ipv6BanBits is how much of an IPv6 address a ban, and the strikes behind it,
// cover: the /64, the network ADR 0011 scopes reputation to.
//
// Keyed by the exact address, the ban could not hold an IPv6 client at all. A
// customer is delegated a /64 -- 2^64 addresses it can source from at no cost --
// so a scanner rotating through it was refused for the one request that tripped
// each ban, never climbed the ladder, and after ten thousand trap hits had filled
// both maps to maxHoneypotBlocklist. At the cap the blocklist refuses to grow, so
// the next scanner to reach a trap, on any address, was not banned at all: one
// customer could switch the honeypot off for everyone.
//
// The cost is that a ban now covers everything in the /64. That is normally one
// subscriber -- a household, a phone, a VM -- which is why ADR 0011 chose it; on
// a provider that puts several customers in one /64, one of them tripping a trap
// takes the others with it. IPv4 keeps per-address bans, and a v4-mapped address
// is banned as the IPv4 address it is.
const ipv6BanBits = 64

// honeypotKeyBufLen fits every key the request path formats without spilling
// to the heap: an IPv6 key is 21 bytes at the /64 (see appendIPv6Key), 41 if the
// ban ever widened to a whole address, and an IPv4 address is at most 15. A
// longer value -- not an address at all -- still works; it just allocates.
const honeypotKeyBufLen = 48

// appendHoneypotKey appends the key a ban and its strikes are recorded under.
//
// Every read and every write of honeypotBlocklist and honeypotStrikes goes
// through this one function -- the ban check, the strike, the ban, and the
// operator's release -- because a ban recorded under one key and looked up under
// another is a ban that silently never applies.
//
// Anything without a colon is returned as it is: an IPv4 address, which the
// ladder keys per address as it always has, or a value that is not an address,
// which keeps its own key rather than being merged with others. That branch
// costs no parse, so IPv4 traffic pays nothing for the IPv6 rule.
func appendHoneypotKey(dst []byte, clientIP string) []byte {
	if strings.IndexByte(clientIP, ':') < 0 {
		return append(dst, clientIP...)
	}
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return append(dst, clientIP...)
	}
	if addr.Is4In6() {
		// The same host as its IPv4 spelling, and a dual-stack listener or a
		// forwarding header can present either.
		return addr.Unmap().AppendTo(dst)
	}
	prefix, err := addr.Prefix(ipv6BanBits)
	if err != nil {
		return append(dst, clientIP...)
	}
	return appendIPv6Key(dst, prefix.Addr().As16())
}

// appendIPv6Key writes the hextets of the masked address that the ban covers,
// four digits each, then "::": "2001:0db8:0001:0002::" for anything in
// 2001:db8:1:2::/64 -- the network's own address, in a spelling any IPv6
// parser accepts.
//
// Not the canonical text: finding the longest zero run to compress to "::" was
// most of the cost of formatting, and this runs on every IPv6 request through
// either honeypot. A key has to be unique, not canonical. The hextets past the
// ban's width are all zero after the mask, so they are left to the "::".
func appendIPv6Key(dst []byte, a [16]byte) []byte {
	const hexDigits = "0123456789abcdef"
	for i := 0; i < (ipv6BanBits+15)/16*2; i += 2 {
		if i > 0 {
			dst = append(dst, ':')
		}
		dst = append(dst,
			hexDigits[a[i]>>4], hexDigits[a[i]&0x0f],
			hexDigits[a[i+1]>>4], hexDigits[a[i+1]&0x0f])
	}
	return append(dst, "::"...)
}

// honeypotKey is appendHoneypotKey as a string, for the paths that store one.
func honeypotKey(clientIP string) string {
	var buf [honeypotKeyBufLen]byte
	return string(appendHoneypotKey(buf[:0], clientIP))
}

// honeypotBanFor records a strike for clientIP's key and returns how long it
// should be banned. Callers hold no lock; this takes it.
func honeypotBanFor(clientIP string, now time.Time) time.Duration {
	key := honeypotKey(clientIP)

	blocklistMu.Lock()
	defer blocklistMu.Unlock()

	st := honeypotStrikes[key]
	if now.Sub(st.last) > honeypotStrikeWindow {
		st.count = 0
	}
	st.count++
	st.last = now

	// Bounded by the same cap as the blocklist and swept the same way: this map
	// is keyed by attacker-supplied addresses, so it needs a ceiling for the
	// same reason.
	if _, exists := honeypotStrikes[key]; !exists && len(honeypotStrikes) >= maxHoneypotBlocklist {
		for ip, s := range honeypotStrikes {
			if now.Sub(s.last) > honeypotStrikeWindow {
				delete(honeypotStrikes, ip)
			}
		}
		if len(honeypotStrikes) >= maxHoneypotBlocklist {
			// Cannot record the strike, so escalation is unavailable. Fall back to
			// the top of the ladder rather than the bottom: under a scan large
			// enough to fill this map, being generous to each new address is how
			// the trap stops working at exactly the moment it is needed.
			return honeypotBanLadder[len(honeypotBanLadder)-1]
		}
	}
	honeypotStrikes[key] = st

	if st.count > len(honeypotBanLadder) {
		return honeypotBanLadder[len(honeypotBanLadder)-1]
	}
	return honeypotBanLadder[st.count-1]
}

// maxHoneypotBlocklist caps the blocklist. Entries are keyed by client IP and
// otherwise only removed when that same address returns after its ban expires,
// so a scan from many sources would retain every one of them forever. At the
// cap we sweep expired entries first and, if that frees nothing, refuse to grow
// — a ban that cannot be recorded is far cheaper than an unbounded map fed by
// attacker-chosen keys.
const maxHoneypotBlocklist = 10_000

// defaultHoneypotPaths lists the trap paths used when deception is active but
// the operator configured none.
//
// Every entry must be a path no legitimate client ever requests. /admin and
// /wp-admin were deliberately removed: they are the front door of most admin
// panels and of every WordPress install, so trapping them by default bans the
// first real administrator to sign in — and behind CGNAT or a corporate egress,
// everyone sharing that address. Operators who front no such app can still add
// them explicitly via SecurityAdvanced.Deception.HoneypotPaths.
func defaultHoneypotPaths() []string {
	return []string{"/.env", "/.git", "/config.php", "/backup.sql", "/.aws", "/.ssh"}
}

// ReleaseHoneypotBan lifts the honeypot's ban on ip and forgets its strikes,
// reporting whether there was a ban to lift.
//
// The ban lives only here, in memory, in front of every route, so the
// operator's release has to reach it by name: clearing the IP mitigation table,
// the eBPF shun and the reputation scores left it in force, and the dashboard's
// "Remove Mitigation / Allow IP" reported success on an address that was still
// refused on every request. The strikes go too: a release is the operator's
// judgement that the hits were a mistake, and keeping them would put the next
// hit straight back on the rung the mistake had reached.
//
// It releases by the ban's key, so releasing any address of an IPv6 /64 lifts
// the ban the whole /64 is under (see ipv6BanBits): the ban was never on the
// address the operator is looking at, and deleting that address would find
// nothing while the dashboard reported success.
func ReleaseHoneypotBan(ip string) bool {
	key := honeypotKey(ip)
	blocklistMu.Lock()
	defer blocklistMu.Unlock()
	_, banned := honeypotBlocklist[key]
	delete(honeypotBlocklist, key)
	delete(honeypotStrikes, key)
	return banned
}

// blockHoneypotIP records a ban, keeping the blocklist bounded.
//
// Loopback is never banned. The ban lasts up to 24 hours, lives only in memory,
// and ends by expiring, by a restart or by an operator's release
// (ReleaseHoneypotBan), so recording one against 127.0.0.1 takes out every
// local caller at once until one of those happens: health
// checks, the management API, and an administrator browsing the dashboard from
// the same host. That is a self-inflicted outage triggered by anything local
// touching a trap path, and it buys nothing — an attacker who can originate
// from loopback is already inside the machine. telemetry.RecordSecurityThreat
// drops loopback sources for the same reason.
//
// The request itself is still refused; only the durable ban is skipped.
func blockHoneypotIP(clientIP string, until time.Time) {
	if httputil.IsLoopback(clientIP) {
		return
	}
	// An allowlisted source is not banned. A trap hit from the customer's own
	// scanner, or from a monitoring vendor they told us about, is exactly the
	// case GATEON_MITIGATION_ALLOWLIST exists for -- and a ban lands on an
	// address, so without this it takes out everything sharing that egress.
	// The security event is still recorded; only the ban is skipped.
	if mitigation.IsAllowlisted(clientIP) {
		return
	}
	key := honeypotKey(clientIP)

	blocklistMu.Lock()
	defer blocklistMu.Unlock()

	if _, exists := honeypotBlocklist[key]; !exists && len(honeypotBlocklist) >= maxHoneypotBlocklist {
		now := time.Now()
		for k, exp := range honeypotBlocklist {
			if now.After(exp) {
				delete(honeypotBlocklist, k)
			}
		}
		if len(honeypotBlocklist) >= maxHoneypotBlocklist {
			return
		}
	}
	honeypotBlocklist[key] = until
}

// HoneypotConfig defines the configuration for the Honeypot middleware.
type HoneypotConfig struct {
	Paths []string
}

// HoneypotGlobal returns a middleware that detects access to "trap" paths and blocks them globally.
func HoneypotGlobal(globalStore config.GlobalConfigStore) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveHoneypotGlobal(globalStore, next, w, r)
		})
	}
}

func serveHoneypotGlobal(globalStore config.GlobalConfigStore, next http.Handler, w http.ResponseWriter, r *http.Request) {
	clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())
	if honeypotBanActive(clientIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	paths, deceptionEnabled := honeypotPaths(globalStore, r)
	if trap, hit := honeypotTrapFor(r.URL.Path, paths); hit {
		recordHoneypotThreat(r, trap)
		blockHoneypotIP(clientIP, time.Now().Add(honeypotBanFor(clientIP, time.Now())))
		// Return 403 Forbidden to the attacker
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// If deception is enabled, wrap ResponseWriter to inject breadcrumbs
	if deceptionEnabled {
		next.ServeHTTP(&breadcrumbWriter{ResponseWriter: w, request: r}, r)
		return
	}

	next.ServeHTTP(w, r)
}

// honeypotBanActive reports whether this client is still inside its ban, and
// drops the entry when it is not. The expiry sweep happens on read because
// there is no other pass over this map, and leaving expired entries would make
// it a map keyed by attacker-supplied address with no eviction.
//
// Every request through either honeypot pays for this. With no ban in force --
// most of the time, on most installs -- it is one read-locked length check and
// no key at all, which spares IPv6 clients the address parse their key needs.
// Otherwise the key is built in a stack buffer and looked up as string(key),
// which the compiler does without allocating.
func honeypotBanActive(clientIP string) bool {
	if noHoneypotBans() {
		return false
	}
	var buf [honeypotKeyBufLen]byte
	key := appendHoneypotKey(buf[:0], clientIP)

	blocklistMu.RLock()
	until, blocked := honeypotBlocklist[string(key)]
	blocklistMu.RUnlock()

	if !blocked {
		return false
	}
	if time.Now().Before(until) {
		// An allowlisted address is never banned itself (blockHoneypotIP), but
		// an IPv6 ban covers the whole /64, so a neighbour's ban would otherwise
		// refuse it. Asked only once a ban has matched, so it costs the
		// unbanned majority nothing.
		return !mitigation.IsAllowlisted(clientIP)
	}

	blocklistMu.Lock()
	delete(honeypotBlocklist, string(key))
	blocklistMu.Unlock()
	return false
}

// noHoneypotBans reports whether the blocklist is empty. Read from the map
// itself under its lock rather than from a counter kept beside it: a counter
// that drifted to zero while bans existed would skip every ban check, and this
// shortcut must never be the reason a ban does not apply.
func noHoneypotBans() bool {
	blocklistMu.RLock()
	defer blocklistMu.RUnlock()
	return len(honeypotBlocklist) == 0
}

// honeypotPaths resolves the configured trap paths, falling back to the
// built-in set so an enabled honeypot with no paths still traps something.
func honeypotPaths(globalStore config.GlobalConfigStore, r *http.Request) (paths []string, deceptionEnabled bool) {
	gc := globalStore.Get(r.Context())
	if gc != nil && gc.SecurityAdvanced != nil && gc.SecurityAdvanced.Deception != nil &&
		gc.SecurityAdvanced.Deception.Enabled {
		paths = gc.SecurityAdvanced.Deception.HoneypotPaths
		deceptionEnabled = true
	}
	if len(paths) == 0 {
		paths = defaultHoneypotPaths()
	}
	return paths, deceptionEnabled
}

// honeypotTrapFor reports which trap a path hit, if any. A trap matches
// exactly, or as a directory prefix so everything under it counts.
func honeypotTrapFor(path string, paths []string) (string, bool) {
	// Dynamic breadcrumbs are checked first: the gateway planted them, so a
	// request for one is unambiguous rather than merely suspicious.
	if strings.HasPrefix(path, "/_gateon_trap_") {
		return "dynamic_breadcrumb", true
	}

	for _, trapPath := range paths {
		if trapPath == "" {
			continue
		}
		if path == trapPath || strings.HasPrefix(path, trapPath+"/") {
			return trapPath, true
		}
	}
	return "", false
}

type breadcrumbWriter struct {
	http.ResponseWriter
	request     *http.Request
	wroteHeader bool
	isHTML      bool
}

// Flush forwards to the underlying writer so a Server-Sent Events stream behind
// this middleware reaches the client as it is produced.
//
// Embedding http.ResponseWriter promotes only Header, Write and WriteHeader, so
// a wrapper silently stops being an http.Flusher -- and an SSE response then
// buffers until the upstream closes, arriving complete and far too late. That
// reads as a dead feed rather than as a middleware bug, which is why it
// survived: Hijack was added here for WebSocket upgrades and Flush was not,
// so the streaming case that fails is the one nobody was thinking about.
func (w *breadcrumbWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying writer so a WebSocket upgrade behind the
// honeypot breadcrumb middleware can take the raw connection. Breadcrumb
// injection only touches an HTML response body, which a hijacked connection
// does not have.
func (w *breadcrumbWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

func (w *breadcrumbWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	contentType := w.Header().Get("Content-Type")
	if strings.Contains(contentType, "text/html") && code == http.StatusOK {
		w.isHTML = true
		// Remove Content-Length as we will modify the body
		w.Header().Del("Content-Length")
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *breadcrumbWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.isHTML {
		return w.ResponseWriter.Write(b)
	}

	// Simple breadcrumb injection: find </body> and insert a hidden link
	bodyTag := []byte("</body>")
	idx := bytes.LastIndex(b, bodyTag)
	if idx == -1 {
		return w.ResponseWriter.Write(b)
	}

	// Generate a unique trap path
	trapID := newTrapID()
	trapLink := fmt.Sprintf("\n<!-- Gateon Breadcrumb -->\n<a href=\"/_gateon_trap_%d\" style=\"display:none\" aria-hidden=\"true\" tabIndex=\"-1\"></a>\n", trapID)
	return writeAround(w.ResponseWriter, b, idx, trapLink)
}

// Honeypot returns a middleware that detects access to "trap" paths and blocks them.
func Honeypot(cfg HoneypotConfig) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())
			// The same check as the global honeypot's rather than a copy of it:
			// the copy each kept had to learn every rule the other did, and the
			// IPv6 key is one more.
			if honeypotBanActive(clientIP) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			path := r.URL.Path
			for _, trapPath := range cfg.Paths {
				if trapPath == "" {
					continue
				}
				// Exact match or prefix match for directories
				if path == trapPath || strings.HasPrefix(path, trapPath+"/") {
					recordHoneypotThreat(r, trapPath)
					blockHoneypotIP(clientIP, time.Now().Add(honeypotBanFor(clientIP, time.Now())))

					// Return 403 Forbidden to the attacker
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func recordHoneypotThreat(r *http.Request, trapPath string) {
	clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())
	routeID := kind.GetRouteName(r)
	if routeID == "" {
		routeID = "global-honeypot"
	}

	logger.SecurityEvent("honeypot_triggered", r, "access to trap path: "+trapPath+"; IP blocked for 24h")

	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		Type:        "honeypot_triggered",
		SourceIP:    clientIP,
		Score:       100,
		Details:     "Access to deception trap path: " + trapPath,
		Time:        time.Now(),
		RouteID:     routeID,
		RequestURI:  r.URL.Path,
		Category:    "deception",
		Severity:    kind.SeverityHigh,
		ActionTaken: kind.ActionBlocked,
	}))
}

// parseHoneypotConfig parses the middleware configuration into HoneypotConfig.
func parseHoneypotConfig(cfg map[string]string) HoneypotConfig {
	pathsStr := cfg["paths"]
	if pathsStr == "" {
		// Same default list as the global honeypot, and for the same reason:
		// a trap that bans an address for 24 hours must only cover paths no
		// legitimate client requests. See defaultHoneypotPaths.
		return HoneypotConfig{Paths: defaultHoneypotPaths()}
	}

	parts := strings.Split(pathsStr, ",")
	paths := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			paths = append(paths, p)
		}
	}
	return HoneypotConfig{Paths: paths}
}

// newTrapID returns an unpredictable identifier for a breadcrumb trap path.
//
// crypto/rand rather than math/rand, and that is the point of the whole
// mechanism rather than a lint fix. A breadcrumb only works if an attacker
// cannot tell a trap path from a real one; with a predictable generator the
// sequence can be reproduced offline and every trap enumerated and avoided,
// which turns the deception layer into an oracle for exactly the visitors it
// exists to catch. The space is widened at the same time -- a million values is
// small enough to sweep.
func newTrapID() uint64 {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice, and a trap that silently
		// became predictable would be worse than no trap. Fall back to a value
		// derived from the clock, which is still not enumerable offline.
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}
