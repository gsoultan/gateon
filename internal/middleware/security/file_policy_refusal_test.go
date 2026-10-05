// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// pngHead is the start of a PNG file.
var pngHead = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}

// TestAnUploadRefusedForWhatItIsIsNotMalware: the file-security middleware
// filed "file too large" and "type not allowed" as malware, at 90 -- the
// strongest attack evidence the gateway keeps, counted three times towards a
// fingerprint block and an address shun -- and a user who tried a large phone
// photo three times was refused on every route. They are refused, and cost
// what an ordinary refusal does.
func TestAnUploadRefusedForWhatItIsIsNotMalware(t *testing.T) {
	cases := []struct {
		name   string
		cfg    FileSecurityConfig
		upload func(t *testing.T) *http.Request
		status int
	}{
		{"a file over the size limit", FileSecurityConfig{MaxFileSize: 64}, func(t *testing.T) *http.Request {
			return uploadRequest(t, "photo", "holiday.png", append(pngHead, bytes.Repeat([]byte{0}, 4096)...))
		}, http.StatusRequestEntityTooLarge},
		{"a type the route does not take", FileSecurityConfig{AllowedMimeTypes: []string{"image/png"}}, func(t *testing.T) *http.Request {
			return uploadRequest(t, "doc", "notes.txt", []byte(strings.Repeat("meeting notes ", 40)))
		}, http.StatusForbidden},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			threats := detectionStore(t)
			client := []string{"100.64.40.10", "100.64.41.10"}[i]
			t.Cleanup(func() { telemetry.ResetReputation(repid.For(detectingBuild, client)) })
			tc.cfg.RouteID = "upload-route"
			h := enforcedRoute("upload-route", FileSecurity(tc.cfg))

			for n := range requestsToExhaust {
				if code := sendAs(h, client, tc.upload(t)); code != tc.status {
					t.Fatalf("upload %d got %d, want the file check's %d: the refusals before it "+
						"were held against the client as malware", n+1, code, tc.status)
				}
			}
			if code := sendAs(h, client, uploadRequest(t, "photo", "small.png", pngHead)); code != http.StatusOK {
				t.Fatalf("an acceptable upload after the refused ones got %d", code)
			}
			seen := drained(threats)
			if len(seen) == 0 {
				t.Fatal("nothing was recorded, so the assertions above prove nothing")
			}
			for _, th := range seen {
				if th.Category == "malware" || telemetry.AttackEvidenceWeight(&th) != 0 {
					t.Errorf("%q was filed as %s/%s, attack evidence %v: a policy refusal is not malware",
						th.Details, th.Type, th.Category, telemetry.AttackEvidenceWeight(&th))
				}
			}
		})
	}
}

// TestAMalwareUploadIsStillHeldAgainstItsSender is the control: an
// executable disguised as an image is malware, and a client that uploads it
// three times is refused on its next, ordinary request.
func TestAMalwareUploadIsStillHeldAgainstItsSender(t *testing.T) {
	const attacker = "100.64.42.10"
	threats := detectionStore(t)
	t.Cleanup(func() { telemetry.ResetReputation(repid.For(detectingBuild, attacker)) })
	h := enforcedRoute("upload-route", FileSecurity(FileSecurityConfig{RouteID: "upload-route"}))
	elf := append([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}, make([]byte, 64)...)

	for n := range 3 {
		if code := sendAs(h, attacker, uploadRequest(t, "photo", "cat.png", elf)); code != http.StatusForbidden {
			t.Fatalf("disguised executable %d got %d, want 403", n+1, code)
		}
	}
	if code := sendAs(h, attacker, uploadRequest(t, "photo", "small.png", pngHead)); code != http.StatusForbidden {
		t.Fatalf("after three disguised executables an ordinary upload got %d, want the reputation blocker's 403", code)
	}
	for _, th := range drained(threats) {
		if th.Type == threatFileMalware && telemetry.AttackEvidenceWeight(&th) != telemetry.DecisiveAttackWeight {
			t.Errorf("a disguised executable weighs %v as attack evidence, want %v",
				telemetry.AttackEvidenceWeight(&th), telemetry.DecisiveAttackWeight)
		}
	}
}
