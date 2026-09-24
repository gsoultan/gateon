// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ha

import (
	"bytes"
	"testing"
	"time"
)

// FuzzParseAdvert feeds arbitrary datagrams to the heartbeat parser. It runs in
// listenLoop, a goroutine with no recover reading a UDP port any host on the
// segment can reach, so a bounds error is a remote crash. Anything it accepts
// must be exactly what encodeAdvert produces for the decoded fields, since an
// accepted advert can make this node release its virtual IPs.
func FuzzParseAdvert(f *testing.F) {
	key := []byte("fuzz-auth-pass")
	now := time.Unix(1_700_000_000, 0)
	valid, err := encodeAdvert(advert{VRID: 51, Priority: 100, Sent: now}, key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid, int64(10*time.Second))
	f.Add([]byte{}, int64(0))
	f.Add(bytes.Repeat([]byte{0xff}, advertLen), int64(-1))
	f.Fuzz(func(t *testing.T, buf []byte, window int64) {
		a, err := parseAdvert(buf, key, now, time.Duration(window))
		if err != nil {
			return
		}
		again, err := encodeAdvert(a, key)
		if err != nil {
			t.Fatalf("re-encoding an accepted advert failed: %v", err)
		}
		if !bytes.Equal(again, buf) {
			t.Fatalf("accepted %x, which re-encodes as %x", buf, again)
		}
	})
}
