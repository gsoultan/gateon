// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ha

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

var (
	testKey = []byte("correct horse battery staple")
	testNow = time.Unix(1_700_000_000, 0)
)

// forgedLegacyAdvert is exactly what the pre-fix wire format was: eight plaintext
// bytes, no authentication of any kind. Anyone who could reach the port could
// send this, and the receiver acted on it by releasing a virtual IP.
func forgedLegacyAdvert(vrid, priority int32) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], uint32(vrid))
	binary.BigEndian.PutUint32(buf[4:8], uint32(priority))
	return buf
}

// TestForgedAdvertIsRejected is the regression guard for the defect. An attacker
// claiming the maximum priority must not be able to influence the election, and
// must not be distinguishable from noise by the parser.
func TestForgedAdvertIsRejected(t *testing.T) {
	_, err := parseAdvert(forgedLegacyAdvert(51, 255), testKey, testNow, time.Minute)
	if err == nil {
		t.Fatal("an unauthenticated 8-byte advert was accepted; this is the VIP-takeover bug")
	}
	if !errors.Is(err, errAdvertMalformed) {
		t.Errorf("got %v, want a malformed-advert error", err)
	}
}

// A well-formed packet signed with the wrong key is the realistic attack once
// the wire format is public: right shape, wrong secret.
func TestAdvertSignedWithWrongKeyIsRejected(t *testing.T) {
	buf, err := encodeAdvert(advert{VRID: 51, Priority: 255, Sent: testNow}, []byte("wrong key"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := parseAdvert(buf, testKey, testNow, time.Minute); !errors.Is(err, errAdvertUnauthenticated) {
		t.Fatalf("got %v, want errAdvertUnauthenticated", err)
	}
}

func TestAuthenticatedAdvertRoundTrips(t *testing.T) {
	buf, err := encodeAdvert(advert{VRID: 51, Priority: 200, Sent: testNow}, testKey)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := parseAdvert(buf, testKey, testNow, time.Minute)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.VRID != 51 || got.Priority != 200 {
		t.Errorf("got vrid=%d priority=%d, want 51/200", got.VRID, got.Priority)
	}
	if !got.Sent.Equal(testNow) {
		t.Errorf("got sent=%v, want %v", got.Sent, testNow)
	}
}

// Replay is the attack a MAC alone does not stop: capture one advert from the
// high-priority node, then replay it after that node dies to keep the survivor
// from ever taking the VIP.
func TestReplayedAdvertIsRejectedOutsideTheWindow(t *testing.T) {
	buf, err := encodeAdvert(advert{VRID: 51, Priority: 255, Sent: testNow}, testKey)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if _, err := parseAdvert(buf, testKey, testNow.Add(5*time.Second), 10*time.Second); err != nil {
		t.Fatalf("a fresh advert inside the window was rejected: %v", err)
	}
	if _, err := parseAdvert(buf, testKey, testNow.Add(11*time.Second), 10*time.Second); !errors.Is(err, errAdvertStale) {
		t.Fatalf("got %v, want errAdvertStale for a replayed advert", err)
	}
	// Clocks drift both ways; a packet stamped in the future is equally suspect.
	if _, err := parseAdvert(buf, testKey, testNow.Add(-11*time.Second), 10*time.Second); !errors.Is(err, errAdvertStale) {
		t.Fatalf("got %v, want errAdvertStale for a future-dated advert", err)
	}
}

// An empty auth pass must never produce or accept traffic, because that is
// exactly the unauthenticated mode the fix exists to remove.
func TestEmptyAuthPassIsRefusedOnBothSides(t *testing.T) {
	if _, err := encodeAdvert(advert{VRID: 1, Priority: 1, Sent: testNow}, nil); !errors.Is(err, errNoAuthPass) {
		t.Errorf("encode with no key: got %v, want errNoAuthPass", err)
	}
	buf, err := encodeAdvert(advert{VRID: 1, Priority: 1, Sent: testNow}, testKey)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := parseAdvert(buf, nil, testNow, time.Minute); !errors.Is(err, errNoAuthPass) {
		t.Errorf("parse with no key: got %v, want errNoAuthPass", err)
	}
}

// Truncation must not be parseable as a short-but-valid advert.
func TestTruncatedAdvertIsRejected(t *testing.T) {
	buf, err := encodeAdvert(advert{VRID: 51, Priority: 255, Sent: testNow}, testKey)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, n := range []int{0, 8, advertBodyLen, advertLen - 1} {
		if _, err := parseAdvert(buf[:n], testKey, testNow, time.Minute); !errors.Is(err, errAdvertMalformed) {
			t.Errorf("%d bytes: got %v, want errAdvertMalformed", n, err)
		}
	}
}

// Flipping any single bit of the body must invalidate the tag — otherwise an
// attacker could edit the priority of a captured advert in flight.
func TestTamperedPriorityInvalidatesTheMAC(t *testing.T) {
	buf, err := encodeAdvert(advert{VRID: 51, Priority: 10, Sent: testNow}, testKey)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	binary.BigEndian.PutUint32(buf[4:8], 255) // promote self to highest priority

	if _, err := parseAdvert(buf, testKey, testNow, time.Minute); !errors.Is(err, errAdvertUnauthenticated) {
		t.Fatalf("got %v, want errAdvertUnauthenticated after editing priority", err)
	}
}

func TestReplayWindowScalesWithAdvertInterval(t *testing.T) {
	if got := replayWindow(time.Second); got != 10*time.Second {
		t.Errorf("replayWindow(1s) = %v, want the 10s floor", got)
	}
	if got := replayWindow(30 * time.Second); got != 90*time.Second {
		t.Errorf("replayWindow(30s) = %v, want 90s", got)
	}
}
