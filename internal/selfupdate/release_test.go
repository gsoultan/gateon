// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	t.Parallel()
	good := map[string]Version{
		"1.8.3":      {1, 8, 3},
		"v1.8.3":     {1, 8, 3},
		"0.0.0":      {0, 0, 0},
		"10.20.300":  {10, 20, 300},
		"999999.0.1": {999999, 0, 1},
	}
	for in, want := range good {
		if got, ok := ParseVersion(in); !ok || got != want {
			t.Errorf("ParseVersion(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	// Not release versions: a snapshot, a development build, and shapes a
	// hostile release list might carry.
	bad := []string{"", "dev", "1.8", "1.8.3.4", "1.8.3-next", "v1.8.3-rc1", "1.08.3", "1.-8.3", "+1.8.3",
		"1.8.x", "1.8.3 ", "vv1.8.3", "1.99999999999999999999.0", "1000000.0.0", "1..3", "１.8.3"}
	for _, in := range bad {
		if got, ok := ParseVersion(in); ok {
			t.Errorf("ParseVersion(%q) = %v, accepted; want refused", in, got)
		}
	}
}

func TestVersionNewer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.8.3", "1.8.2", true},
		{"1.9.0", "1.8.9", true},
		{"2.0.0", "1.99.99", true},
		{"1.10.0", "1.9.0", true}, // numeric, not lexical
		{"1.8.2", "1.8.2", false},
		{"1.8.2", "1.8.3", false},
		{"1.8.9", "1.9.0", false},
	}
	for _, c := range cases {
		a, _ := ParseVersion(c.a)
		b, _ := ParseVersion(c.b)
		if got := a.Newer(b); got != c.want {
			t.Errorf("%s newer than %s = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// checksumsFor is a release list shaped like the one GoReleaser writes.
func checksumsFor(version string) []byte {
	sum := strings.Repeat("ab", 32)
	names := []string{
		"gateon_" + version + "_linux_amd64.tar.gz",
		"gateon_" + version + "_linux_arm64.tar.gz",
		"gateon_" + version + "_amd64.deb",
		"gateon_" + version + "_linux_amd64.tar.gz.sbom.json",
	}
	var b strings.Builder
	for _, n := range names {
		b.WriteString(sum + "  " + n + "\n")
	}
	return []byte(b.String())
}

func TestParseChecksums(t *testing.T) {
	t.Parallel()
	rel, err := ParseChecksums(checksumsFor("1.8.3"))
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	if rel.Version != (Version{1, 8, 3}) {
		t.Errorf("version = %v, want 1.8.3", rel.Version)
	}
	if got := rel.Artifacts["gateon_1.8.3_linux_arm64.tar.gz"]; got != strings.Repeat("ab", 32) {
		t.Errorf("arm64 archive checksum = %q", got)
	}
	if len(rel.Artifacts) != 4 {
		t.Errorf("artifacts = %d, want 4", len(rel.Artifacts))
	}
}

func TestParseChecksumsRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()
	sum := strings.Repeat("ab", 32)
	cases := map[string][]byte{
		"empty":             nil,
		"no gateon archive": []byte(sum + "  something_else.tar.gz\n"),
		"two versions": []byte(sum + "  gateon_1.8.3_linux_amd64.tar.gz\n" +
			sum + "  gateon_9.9.9_linux_arm64.tar.gz\n"),
		"snapshot version": []byte(sum + "  gateon_1.8.3-next_linux_amd64.tar.gz\n"),
		"short checksum":   []byte("abcd  gateon_1.8.3_linux_amd64.tar.gz\n"),
		"not hex":          []byte(strings.Repeat("zz", 32) + "  gateon_1.8.3_linux_amd64.tar.gz\n"),
		"no file name":     []byte(sum + "\n"),
		"path in name":     []byte(sum + "  ../gateon_1.8.3_linux_amd64.tar.gz\n"),
		"an error page":    []byte("<html><body>503 Service Unavailable</body></html>\n"),
		"too long":         bytes.Repeat([]byte("a"), MaxChecksumsBytes+1),
		"too many files":   []byte(manyLines(sum, maxArtifacts+1)),
	}
	for name, data := range cases {
		if rel, err := ParseChecksums(data); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: ParseChecksums = %v, %v; want ErrMalformed", name, rel.Version, err)
		}
	}
}

func manyLines(sum string, n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString(sum + "  file" + strconv.Itoa(i) + "\n")
	}
	return b.String()
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func TestSignatureVerifiesOnlyTheListThatWasSigned(t *testing.T) {
	t.Parallel()
	pub, priv := testKey(t)
	other, _ := testKey(t)
	list := checksumsFor("1.8.3")
	sig := Sign(priv, list)

	if err := Verify([]ed25519.PublicKey{pub}, list, sig); err != nil {
		t.Fatalf("the signed list did not verify: %v", err)
	}
	// A rotation: the list verifies under either trusted key.
	if err := Verify([]ed25519.PublicKey{other, pub}, list, sig); err != nil {
		t.Errorf("the signed list did not verify with two trusted keys: %v", err)
	}
	refused := map[string]error{
		"another release's list": Verify([]ed25519.PublicKey{pub}, checksumsFor("9.9.9"), sig),
		"one byte changed":       Verify([]ed25519.PublicKey{pub}, append([]byte("x"), list...), sig),
		"a key not trusted":      Verify([]ed25519.PublicKey{other}, list, sig),
		"no trusted key":         Verify(nil, list, sig),
		"an empty signature":     Verify([]ed25519.PublicKey{pub}, list, nil),
		"a truncated signature":  Verify([]ed25519.PublicKey{pub}, list, sig[:20]),
		"not base64":             Verify([]ed25519.PublicKey{pub}, list, []byte("!!!")),
	}
	for name, err := range refused {
		if !errors.Is(err, ErrSignature) {
			t.Errorf("%s: Verify = %v, want ErrSignature", name, err)
		}
	}
}

// A signature over the bare list, without the context, is what the same key
// would produce signing the file for any other purpose. It must not verify.
func TestSignatureIsBoundToItsContext(t *testing.T) {
	t.Parallel()
	pub, priv := testKey(t)
	list := checksumsFor("1.8.3")
	bare := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, list))
	if err := Verify([]ed25519.PublicKey{pub}, list, []byte(bare)); !errors.Is(err, ErrSignature) {
		t.Fatalf("a signature without the context verified: %v", err)
	}
}

func TestParseKeys(t *testing.T) {
	t.Parallel()
	pub, _ := testKey(t)
	line := base64.StdEncoding.EncodeToString(pub)
	keys, err := ParseKeys([]byte("# a comment\n\n" + line + "\n  " + line + "  \n"))
	if err != nil || len(keys) != 2 || !keys[0].Equal(pub) {
		t.Fatalf("ParseKeys = %d keys, %v; want the key twice", len(keys), err)
	}
	for _, bad := range []string{"not-a-key", base64.StdEncoding.EncodeToString(pub[:16]), line + " trailing"} {
		if _, err := ParseKeys([]byte(bad)); err == nil {
			t.Errorf("ParseKeys(%q) accepted", bad)
		}
	}
}

// The committed key file is what every release binary trusts. A line in it
// that does not parse would make ReleaseKeys trust nothing, silently.
func TestCommittedReleaseKeysParse(t *testing.T) {
	t.Parallel()
	keys, err := ParseKeys(releaseKeysFile)
	if err != nil {
		t.Fatalf("internal/selfupdate/release_keys.txt: %v", err)
	}
	if len(ReleaseKeys()) != len(keys) {
		t.Fatalf("ReleaseKeys() = %d keys, the file holds %d", len(ReleaseKeys()), len(keys))
	}
}
