// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Advert wire format. Fixed length, so a truncated datagram is unambiguous
// rather than being parsed as a short-but-valid packet.
//
//	[0:4]   vrid      uint32 big-endian
//	[4:8]   priority  uint32 big-endian
//	[8:16]  sent      uint64 big-endian, Unix nanoseconds
//	[16:48] mac       HMAC-SHA256 over [0:16], keyed with the HA auth pass
//
// The timestamp is inside the MAC'd region on purpose. A MAC alone authenticates
// the sender but not the moment: an attacker who captures one advert from a
// high-priority node could replay it forever, suppressing failover after that
// node is genuinely gone. Bounding how old an advert may be closes that.
const (
	advertMACLen  = sha256.Size
	advertBodyLen = 16
	advertLen     = advertBodyLen + advertMACLen
)

var (
	// errAdvertMalformed covers anything that is not the right shape.
	errAdvertMalformed = errors.New("malformed advert")
	// errAdvertUnauthenticated means the MAC did not verify: either the peer
	// holds a different auth pass, or the packet did not come from a peer.
	errAdvertUnauthenticated = errors.New("advert failed authentication")
	// errAdvertStale means the advert verified but is outside the replay window.
	errAdvertStale = errors.New("advert outside the replay window")
	// errNoAuthPass is returned when HA is asked to run without a shared secret.
	errNoAuthPass = errors.New("ha.auth_pass is empty")
)

// advert is a decoded, authenticated heartbeat.
type advert struct {
	VRID     int32
	Priority int32
	Sent     time.Time
}

// advertMAC computes the tag over the body. Split out so encode and parse cannot
// disagree about what is covered.
func advertMAC(body, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return mac.Sum(nil)
}

// encodeAdvert renders a signed advert. An empty key is refused rather than
// producing a packet anyone can forge.
func encodeAdvert(a advert, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errNoAuthPass
	}
	buf := make([]byte, advertLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(a.VRID))
	binary.BigEndian.PutUint32(buf[4:8], uint32(a.Priority))
	binary.BigEndian.PutUint64(buf[8:16], uint64(a.Sent.UnixNano()))
	copy(buf[advertBodyLen:], advertMAC(buf[:advertBodyLen], key))
	return buf, nil
}

// parseAdvert authenticates a datagram and returns it only if the MAC verifies
// and the timestamp is inside the window. Every failure path returns an error;
// there is deliberately no "unauthenticated but well-formed" result, because the
// only caller acts on the result by releasing a virtual IP.
func parseAdvert(buf, key []byte, now time.Time, window time.Duration) (advert, error) {
	if len(key) == 0 {
		return advert{}, errNoAuthPass
	}
	if len(buf) != advertLen {
		return advert{}, fmt.Errorf("%w: got %d bytes, want %d", errAdvertMalformed, len(buf), advertLen)
	}

	// Constant-time compare: a byte-at-a-time comparison would leak the expected
	// tag to anyone able to time the responses.
	if !hmac.Equal(buf[advertBodyLen:], advertMAC(buf[:advertBodyLen], key)) {
		return advert{}, errAdvertUnauthenticated
	}

	a := advert{
		VRID:     int32(binary.BigEndian.Uint32(buf[0:4])),
		Priority: int32(binary.BigEndian.Uint32(buf[4:8])),
		Sent:     time.Unix(0, int64(binary.BigEndian.Uint64(buf[8:16]))),
	}

	// Symmetric window: peers' clocks drift in both directions, and a packet
	// stamped in the future is as suspect as one stamped too far in the past.
	if skew := now.Sub(a.Sent); skew > window || skew < -window {
		return advert{}, fmt.Errorf("%w: %v off", errAdvertStale, skew.Round(time.Millisecond))
	}
	return a, nil
}

// replayWindow bounds how old an advert may be. Scaled to the advertisement
// interval so a slow cluster is not constantly rejecting its own traffic, with a
// floor that tolerates ordinary NTP-level clock skew between nodes.
func replayWindow(advertInt time.Duration) time.Duration {
	const floor = 10 * time.Second
	if w := 3 * advertInt; w > floor {
		return w
	}
	return floor
}
