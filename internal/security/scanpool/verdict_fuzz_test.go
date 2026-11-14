// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package scanpool

import (
	"strings"
	"testing"
)

// FuzzParseVerdict: the reply is whatever the other end of a socket sent. No
// reply may be read as clean except the one clamd sends for a clean file, and
// none as a detection without a name.
func FuzzParseVerdict(f *testing.F) {
	for _, seed := range []string{
		"stream: OK", "stream: Win.Test.EICAR_HDB-1 FOUND", "stream: x ERROR", "INSTREAM size limit exceeded. ERROR",
		"", "OK", "stream: OK ", " FOUND", "stream:  FOUND", "stream: OK\x00", "stream: a FOUND FOUND",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		verdict, err := parseVerdict(line)
		switch {
		case err != nil && verdict.Found:
			t.Fatalf("%q: a detection and an error", line)
		case err == nil && !verdict.Found && line != replyClean:
			t.Fatalf("%q was read as clean", line)
		case verdict.Found && (verdict.Signature == "" || !strings.HasPrefix(line, replyPrefix) || !strings.HasSuffix(line, suffixFound)):
			t.Fatalf("%q was read as a detection of %q", line, verdict.Signature)
		}
		if err != nil && len(err.Error()) > 4*maxQuotedReply+200 {
			t.Fatalf("%d-byte error for a %d-byte reply", len(err.Error()), len(line))
		}
	})
}
