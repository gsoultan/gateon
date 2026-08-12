// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"os"
	"strconv"
)

// Deciding when a JA4+ fingerprint is safe to block.
//
// A JA4+ is not an identity. Its header component hashes header *names*, and
// gateon tracks two of them, so that component has four possible values in
// total — see TestJA4HHeaderHashSpace. The TLS half adds more, but the result
// still describes a client *class*: a browser build on an operating system, not
// a person. Every Chrome on Windows sending User-Agent and Accept-Language
// looks the same from here.
//
// escalateMitigation used to block on the first qualifying threat, with no
// threshold and no ceiling. That turns one attacker into an outage for everyone
// who happens to share their class, and it is cheap to trigger deliberately:
// send one injection from an ordinary browser and take out that browser's
// users. The e2e suite demonstrated it accidentally for months — one spec's
// SQLi 403'd every later spec, because Playwright's HTTP client is a class of
// exactly one shared fingerprint.
//
// Two gates, both necessary:
//
//   - Repetition. A single hit is noise; a client class that keeps producing
//     blocked requests is a signal. Waiting for N costs an attacker nothing
//     they were not already paying, and costs a bystander everything.
//
//   - Blast radius. The number of distinct source addresses seen behind a
//     fingerprint is a direct measure of how many parties a block would hit.
//     One address is a client. Dozens is a population, and blocking it is
//     doing the attacker's work.
//
// Both are deliberately conservative in the same direction: when unsure, do not
// block. The WAF has already refused the request that got us here — declining
// to *also* blocklist the fingerprint costs a rule evaluation on the next one,
// not a breach.
const (
	// defaultMitigateAfter is how many qualifying threats one fingerprint must
	// produce before it is blocked outright.
	defaultMitigateAfter = 3

	// defaultMaxBlastRadius is the largest number of distinct source addresses
	// a fingerprint may span and still be treated as one actor.
	defaultMaxBlastRadius = 4

	// maxTrackedIPs bounds the per-fingerprint address set. Anything above the
	// blast-radius ceiling already disqualifies the fingerprint, so the exact
	// count past that point is not worth the memory — the set stops growing and
	// the fingerprint stays disqualified.
	maxTrackedIPs = defaultMaxBlastRadius + 1
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

// fingerprintSighting is what we know about one JA4+ so far.
type fingerprintSighting struct {
	threats int
	ips     map[string]struct{}
	// ipOverflow records that the address set stopped growing at maxTrackedIPs,
	// so len(ips) is a floor rather than a count.
	ipOverflow bool
}

// shouldMitigateFingerprint records this sighting and reports whether the
// fingerprint has earned an outright block. The returned reason is for the
// operator log when it has not.
//
// sourceIP may be empty; it simply contributes nothing to the blast-radius
// estimate rather than counting as a distinct address.
func shouldMitigateFingerprint(fingerprint, sourceIP string) (bool, string) {
	if fingerprint == "" {
		return false, "no fingerprint"
	}

	fingerprintMu.Lock()
	defer fingerprintMu.Unlock()

	var s *fingerprintSighting
	if v, ok := fingerprintSightings.Get(fingerprint); ok {
		s, _ = v.(*fingerprintSighting)
	}
	if s == nil {
		s = &fingerprintSighting{ips: make(map[string]struct{}, 1)}
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
	fingerprintSightings.Add(fingerprint, s)

	if s.threats < mitigateAfter {
		return false, "below threshold: " + strconv.Itoa(s.threats) + " of " + strconv.Itoa(mitigateAfter)
	}
	if s.ipOverflow || len(s.ips) > maxBlastRadius {
		return false, "blast radius too wide: seen from " + strconv.Itoa(len(s.ips)) +
			"+ addresses, which is a client population rather than one actor"
	}
	return true, ""
}

// FingerprintBlastRadius reports how many distinct source addresses have been
// seen behind a fingerprint, and whether that count is a floor. Exported for
// the diagnostics surface: an operator looking at a mitigation should be able
// to see how many parties it covers.
func FingerprintBlastRadius(fingerprint string) (count int, atLeast bool) {
	fingerprintMu.Lock()
	defer fingerprintMu.Unlock()

	v, ok := fingerprintSightings.Get(fingerprint)
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
