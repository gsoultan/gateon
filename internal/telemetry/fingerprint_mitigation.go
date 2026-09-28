// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"hash/maphash"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// Deciding when a client class is safe to block, and where.
//
// A JA4+ is not an identity. Its header component hashes header *names*, and
// gateon tracks two of them, so that component has four possible values in
// total — see TestJA4HHeaderHashSpace. The TLS half adds more, but the result
// still describes a client *class*: a browser build on an operating system, not
// a person. Every Chrome on Windows sending User-Agent and Accept-Language
// looks the same from here.
//
// So a fingerprint block is never a block on the class alone. It is recorded
// under, and enforced against, the class on one network -- repid.For, the
// identity reputation already uses (ADR 0011, 0024) -- so it reaches the clients
// of one browser build on one /24 or /64, and not every user of that build on
// every network (ADR 0026). And the class is the part a client cannot vary per
// request, so dropping a Referer or a cookie does not shed the block.
//
// Three gates on the automatic block, all conservative in the same direction:
// when unsure, do not block. The WAF has already refused the request that got
// us here; declining to *also* block the class costs a rule evaluation on the
// next request, not a breach.
//
//   - Evidence. Only attack evidence counts (AttackEvidenceWeight): a request
//     the WAF blocked on its payload, a trap sprung, a malware upload, a
//     brute-force or exploit-scan detection. A rate-limit rejection, a geo or
//     bot-policy block, or a reputation or mitigation block that follows an
//     earlier decision says nothing about what the client did, and three of
//     them from one busy office used to block that office's browser class.
//
//   - Repetition. A single hit is noise, and one user retrying a form the WAF
//     misjudges is three. Three pieces of evidence within
//     mitigationEvidenceWindow is a client class that keeps attacking; three
//     spread over a week is three unrelated mistakes, and does not add up.
//
//   - Blast radius. The number of distinct addresses behind the evidence is how
//     many parties a block would hit inside the network. One address is a
//     client. Five is a population, and blocking it is doing the attacker's
//     work.
const (
	// defaultMitigateAfter is how many pieces of attack evidence one class must
	// produce on one network, within mitigationEvidenceWindow, before it is
	// blocked there.
	defaultMitigateAfter = 3

	// defaultMaxBlastRadius is the largest number of distinct source addresses
	// the evidence may come from and still be treated as one actor.
	defaultMaxBlastRadius = 4

	// maxTrackedIPs bounds the per-key address set. Anything above the
	// blast-radius ceiling already disqualifies the key, so the exact count
	// past that point is not worth the memory — the set stops growing and the
	// key stays disqualified for the window.
	maxTrackedIPs = defaultMaxBlastRadius + 1

	// mitigationEvidenceWindow is how long the evidence towards one block
	// accumulates. An attack produces its blocked requests within seconds or
	// minutes; a count that never lapsed turned three false positives, days
	// apart, into a block, and once past the threshold made every later one a
	// block on its own.
	mitigationEvidenceWindow = 10 * time.Minute
)

var (
	mitigateAfter  = envPositiveInt("GATEON_JA4_MITIGATE_AFTER", defaultMitigateAfter)
	maxBlastRadius = envPositiveInt("GATEON_JA4_MAX_BLAST_RADIUS", defaultMaxBlastRadius)
)

// envPositiveInt reads a positive integer from the environment, falling back to
// def for anything absent, unparseable or non-positive. A zero or negative
// threshold would mean "block on sight", which is the behaviour these gates
// exist to remove, so it is not an accepted configuration.
func envPositiveInt(key string, def int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// Threat kinds that are attack evidence. See AttackEvidenceWeight.
const (
	threatHoneypotTriggered = "honeypot_triggered"
	threatFastPathSignature = "fast_path_signature"
	threatWAFPrefix         = "waf_"
	categoryMalware         = "malware"
	categoryBruteForce      = "brute_force"
	categoryExploitScanning = "exploit_scanning"

	// DecisiveAttackWeight is a decision no ordinary client provokes by
	// accident, worth as much as three WAF blocks.
	DecisiveAttackWeight = 3.0
)

// AttackEvidenceWeight is what a recorded threat says about its source: 1 for a
// request the WAF blocked on an attack payload, DecisiveAttackWeight for a trap
// sprung, a malware upload, or a brute-force or exploit-scan detection, and 0
// for everything else.
//
// Everything else deliberately includes: rate-limit rejections, which a busy
// office egress earns without attacking anyone; geo and bot-management blocks,
// which are policy about who a client is rather than evidence of what it did;
// the mitigation and reputation blocks that follow an earlier decision, which
// would feed a block back in as its own evidence; the WAF's detection-only
// matches, which the operator has not trusted enough to block on; and every
// threat the analysis engine records itself, which would make one false
// positive the evidence for the next.
//
// One definition for everything that turns evidence into a limit: the
// analysis engine's harm rule and Graph Intelligence (ADR 0025), and the
// fingerprint block (ADR 0026).
func AttackEvidenceWeight(th *SecurityThreat) float64 {
	switch {
	case th.Type == threatHoneypotTriggered, th.Category == categoryMalware,
		th.Category == categoryBruteForce, th.Category == categoryExploitScanning:
		return DecisiveAttackWeight
	case th.Type == threatFastPathSignature, strings.HasPrefix(th.Type, threatWAFPrefix) && th.Mitigated:
		return 1
	default:
		return 0
	}
}

// fingerprintSighting is the evidence towards blocking one key in the current
// window.
type fingerprintSighting struct {
	since   time.Time // when the current window opened, at its first evidence
	threats int
	ips     map[string]struct{}
	// ipOverflow records that the address set stopped growing at maxTrackedIPs,
	// so len(ips) is a floor rather than a count.
	ipOverflow bool
}

// shouldMitigateFingerprint records one piece of attack evidence against key --
// a class on a network, repid.For -- at now, and reports whether the key has
// earned a block. The returned reason is for the operator log when it has not.
func shouldMitigateFingerprint(key, sourceIP string, now time.Time) (bool, string) {
	if key == "" {
		return false, "no fingerprint"
	}

	fingerprintMu.Lock()
	defer fingerprintMu.Unlock()

	var s *fingerprintSighting
	if v, ok := fingerprintSightings.Get(key); ok {
		s, _ = v.(*fingerprintSighting)
	}
	if s == nil || now.Sub(s.since) > mitigationEvidenceWindow {
		s = &fingerprintSighting{since: now, ips: make(map[string]struct{}, 1)}
	}

	s.threats++
	if sourceIP != "" {
		if _, known := s.ips[sourceIP]; !known {
			if len(s.ips) < maxTrackedIPs {
				s.ips[sourceIP] = struct{}{}
			} else {
				s.ipOverflow = true
			}
		}
	}
	fingerprintSightings.Add(key, s)

	if s.threats < mitigateAfter {
		return false, "below threshold: " + strconv.Itoa(s.threats) + " of " + strconv.Itoa(mitigateAfter) +
			" within " + mitigationEvidenceWindow.String()
	}
	if s.ipOverflow || len(s.ips) > maxBlastRadius {
		return false, "blast radius too wide: seen from " + strconv.Itoa(len(s.ips)) +
			"+ addresses, which is a client population rather than one actor"
	}
	return true, ""
}

// escalateFingerprint blocks the class a threat came from, on the network it
// came from, once the class has attacked from there repeatedly (see the gates
// above). The key is the one UserMitigation enforces -- repid.For, from the
// same fingerprint and address -- or the block would be written where nothing
// reads it.
func escalateFingerprint(st *SecurityThreat) {
	if st.Fingerprint == "" || st.SourceIP == "" || AttackEvidenceWeight(st) == 0 {
		return
	}
	key := repid.For(st.Fingerprint, st.SourceIP)
	ok, reason := shouldMitigateFingerprint(key, st.SourceIP, time.Now())
	if ok && userMitigationHeld(key) {
		ok, reason = false, "released by an operator in the last 24h"
	}
	if !ok {
		logger.Default().LogInfo("declined to mitigate fingerprint",
			"identity", key, "reason", reason, "threat", st.Type)
		return
	}
	MarkUserMitigated(key, "JA4+", st.Details, st.Category)
}

// userMitigationHeld reports whether an operator released key, or its whole
// class, within the hold window, so the next threat does not undo the release.
// A release of a bare fingerprint releases the class on every network and holds
// it under the class alone (ReleaseUserMitigationClass).
func userMitigationHeld(key string) bool {
	return IsUserUnmitigated(key) || IsUserUnmitigated(repid.ClassOf(key))
}

// FingerprintBlastRadius reports how many distinct source addresses the current
// evidence against a key came from, and whether that count is a floor.
// Exported for the diagnostics surface: an operator looking at a mitigation
// should be able to see how many parties it covers.
func FingerprintBlastRadius(key string) (count int, atLeast bool) {
	fingerprintMu.Lock()
	defer fingerprintMu.Unlock()

	v, ok := fingerprintSightings.Get(key)
	if !ok {
		return 0, false
	}
	s, ok := v.(*fingerprintSighting)
	if !ok || s == nil {
		return 0, false
	}
	return len(s.ips), s.ipOverflow
}

// ResetFingerprintSightings clears the sighting table. Tests only.
func ResetFingerprintSightings() {
	fingerprintMu.Lock()
	defer fingerprintMu.Unlock()
	fingerprintSightings.Purge()
}

// How long a fingerprint block lasts.
//
// A JA4+ block had no expiry. It sat in the table until somebody removed it by
// hand, which made every block a permanent decision taken automatically on
// evidence from a single moment. For a key this coarse — a client class, not a
// client — that is the wrong default in both directions: a real attacker
// changes one header and returns under a new class, while the bystanders who
// share the old one stay blocked with nobody aware they were caught.
//
// An hour is short enough that a mistake ages out before it becomes a support
// case, and long enough to be worth applying. A class that keeps attacking
// from the network re-earns it within the evidence window.
const defaultMitigationTTL = time.Hour

var mitigationTTL = envDuration("GATEON_JA4_MITIGATION_TTL", defaultMitigationTTL)

// envDuration reads a Go duration from the environment. A non-positive or
// unparseable value falls back to def: "0" would mean blocks never take effect,
// which is a way to disable the defence by typo.
func envDuration(key string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(os.Getenv(key))
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// mitigationCutoff is the oldest updated_at a mitigation row may carry and
// still count. Computed here rather than with the database's own clock
// arithmetic, because datetime('now', ...) is SQLite-only and this store also
// runs on Postgres. The format matches what CURRENT_TIMESTAMP writes, so the
// comparison is a plain lexicographic one on both.
func mitigationCutoff() string {
	return time.Now().UTC().Add(-mitigationTTL).Format("2006-01-02 15:04:05")
}

// userMitigationRetention is how long a user_mitigations row is kept: past both
// the block's TTL and a release's hold, a row decides nothing.
func userMitigationRetention() time.Duration {
	return max(mitigationTTL, unmitigationHoldWindow)
}

// When an address, rather than a class on its network, is safe to shun.
//
// A shun refuses every request from one address, on every route and, with eBPF,
// in the kernel; and it does not lapse: it holds until an operator releases it.
// One address can be an office, a campus, a carrier's NAT pool. So the evidence
// for a shun must be something the per-class controls cannot answer, and
// something an address full of ordinary users does not produce.
//
// A few client classes attacking from one address is what an office with a few
// infected machines looks like, or a few browser builds tripping one misjudged
// WAF rule. The WAF refuses each of those requests, and the fingerprint block
// and the reputation blocker refuse each class on its network once it repeats,
// so a shun would add only the people behind the address who did nothing. What
// the per-class controls cannot contain is a client presenting a new class per
// connection (ADR 0024's residue): each class earns too little to be blocked on
// its own, and the address presents a stream of them. That is what counting
// classes behind an address is for, and why the bar sits above "a few".
//
// Only attack evidence counts (AttackEvidenceWeight), classes are what a client
// cannot vary per request (repid.Class), a class counts for
// mitigationEvidenceWindow after its latest evidence, and an allowlisted source
// is never counted. ADR 0029.
const (
	// ipShunMinClasses is how many distinct client classes must produce attack
	// evidence from one address, within mitigationEvidenceWindow, before the
	// address is shunned.
	ipShunMinClasses = 5

	// maxEvidenceAddresses bounds the addresses whose evidence is remembered.
	// The key is the attacker's to choose, and an address evicted early only
	// loses evidence, which can delay a shun but never cause one.
	maxEvidenceAddresses = 10000
)

// addressSightings is the evidence towards shunning one address: the classes
// that attacked from it, each with when it last did. The decision needs no
// more than ipShunMinClasses of them, so no more are kept.
type addressSightings struct {
	classes [ipShunMinClasses]classSighting
	n       int
}

// classSighting is one class's latest attack evidence at an address. The class
// is kept as a hash, so the table holds nothing a client wrote.
type classSighting struct {
	class uint64
	last  int64 // UnixNano
}

// classSeed keys the class hashes for the life of the process.
var classSeed = maphash.MakeSeed()

// escalateAddress shuns the address a threat came from once ipShunMinClasses
// classes have attacked from it within the window.
func escalateAddress(st *SecurityThreat) {
	if st.SourceIP == "" || st.Fingerprint == "" || AttackEvidenceWeight(st) == 0 ||
		mitigation.IsAllowlisted(st.SourceIP) {
		return
	}
	classes := recordAddressEvidence(st.SourceIP, repid.Class(st.Fingerprint), evidenceTime(st))
	if classes < ipShunMinClasses || IsIPUnmitigated(st.SourceIP) {
		return
	}
	reason := "IP shunning triggered: attack evidence from " + strconv.Itoa(classes) +
		" different client builds at this address within " + mitigationEvidenceWindow.String()
	if err := MarkIPMitigated(st.SourceIP, reason); err != nil {
		// Nobody is waiting on this one, so logging is all there is -- but an
		// automatic shun that did not persist is a block the operator will never
		// know was not applied. The evidence is kept, so the next piece retries.
		logger.Default().LogError("automatic IP shun did not persist",
			"ip", st.SourceIP, "classes", classes, "error", err)
		return
	}
	forgetAddressEvidence(st.SourceIP)
}

// evidenceTime dates a threat's evidence by when it happened, which the
// recording path stamps, rather than by when the store got to it; never later
// than now.
func evidenceTime(st *SecurityThreat) time.Time {
	now := time.Now()
	if st.Time.IsZero() || st.Time.After(now) {
		return now
	}
	return st.Time
}

// recordAddressEvidence records attack evidence from class at ip, dated at, and
// returns how many distinct classes have attacked from ip within
// mitigationEvidenceWindow of the latest evidence there.
func recordAddressEvidence(ip, class string, at time.Time) int {
	h := maphash.String(classSeed, class)
	addressEvidenceMu.Lock()
	defer addressEvidenceMu.Unlock()

	var s *addressSightings
	if v, ok := addressEvidence.Get(ip); ok {
		s, _ = v.(*addressSightings)
	}
	if s == nil {
		s = &addressSightings{}
	}
	s.record(h, at.UnixNano())
	addressEvidence.Add(ip, s)
	return s.n
}

// record adds one piece of evidence from class at at. Classes whose latest
// evidence is more than a window older than the newest here lapse first, and a
// piece that is itself that old -- a threat the store reached late -- is not
// counted.
func (s *addressSightings) record(class uint64, at int64) {
	newest := at
	for _, c := range s.classes[:s.n] {
		newest = max(newest, c.last)
	}
	s.dropBefore(newest - int64(mitigationEvidenceWindow))
	if newest-at > int64(mitigationEvidenceWindow) {
		return
	}
	for i := range s.classes[:s.n] {
		if s.classes[i].class == class {
			s.classes[i].last = max(s.classes[i].last, at)
			return
		}
	}
	if s.n < len(s.classes) {
		s.classes[s.n] = classSighting{class: class, last: at}
		s.n++
		return
	}
	// Every slot holds a class inside the window, which is already a shun's
	// worth; the stalest makes way, and the count stays at the bar.
	s.classes[s.stalest()] = classSighting{class: class, last: at}
}

// dropBefore removes the classes whose latest evidence is older than cutoff.
func (s *addressSightings) dropBefore(cutoff int64) {
	kept := 0
	for _, c := range s.classes[:s.n] {
		if c.last >= cutoff {
			s.classes[kept] = c
			kept++
		}
	}
	s.n = kept
}

// stalest returns the index of the class whose latest evidence is oldest.
func (s *addressSightings) stalest() int {
	oldest := 0
	for i, c := range s.classes[:s.n] {
		if c.last < s.classes[oldest].last {
			oldest = i
		}
	}
	return oldest
}

// forgetAddressEvidence drops what is remembered against ip: after a shun,
// which needs no more of it, and after an operator's release, so that nothing
// gathered before a release counts after it -- the rule ADR 0025 set for every
// automatic limit.
func forgetAddressEvidence(ip string) {
	addressEvidenceMu.Lock()
	defer addressEvidenceMu.Unlock()
	addressEvidence.Remove(ip)
}
