// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package builtinca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

// Every entry must read, match its pinned fingerprint, be a CA, and carry the
// key type its name promises: an RSA leaf chained to the ECC root (or the
// reverse) is the mistake an operator picking from a list is most likely to
// make, so the list itself has to be right.
func TestCatalogEntriesAreThePublishedCertificates(t *testing.T) {
	wantAlgo := map[string]x509.PublicKeyAlgorithm{
		Prefix + "cloudflare-origin-ca-rsa":  x509.RSA,
		Prefix + "cloudflare-origin-ca-ecc":  x509.ECDSA,
		Prefix + "cloudflare-origin-pull-ca": x509.RSA,
	}
	all := All()
	if len(all) != len(wantAlgo) {
		t.Fatalf("catalog has %d entries, want %d", len(all), len(wantAlgo))
	}
	for _, a := range all {
		cert, err := a.Certificate()
		if err != nil {
			t.Fatalf("%s: %v", a.Ref, err)
		}
		if !cert.IsCA || !cert.BasicConstraintsValid {
			t.Errorf("%s: not a CA certificate", a.Ref)
		}
		if cert.PublicKeyAlgorithm != wantAlgo[a.Ref] {
			t.Errorf("%s: key algorithm %s, want %s", a.Ref, cert.PublicKeyAlgorithm, wantAlgo[a.Ref])
		}
		if a.Use != UseServerChain && a.Use != UseClientCA {
			t.Errorf("%s: no use", a.Ref)
		}
		data, err := Read(a.Ref)
		if err != nil {
			t.Fatalf("Read(%s): %v", a.Ref, err)
		}
		if !x509.NewCertPool().AppendCertsFromPEM(data) {
			t.Errorf("Read(%s) is not a PEM certificate", a.Ref)
		}
	}
}

// A built-in CA cannot be refreshed without a release, so CI starts failing
// half a year before one expires rather than on the day handshakes do.
func TestNoBuiltinCAExpiresWithinSixMonths(t *testing.T) {
	deadline := time.Now().AddDate(0, 6, 0)
	for _, a := range All() {
		cert, err := a.Certificate()
		if err != nil {
			t.Fatalf("%s: %v", a.Ref, err)
		}
		if cert.NotAfter.Before(deadline) {
			t.Errorf("%s expires %s: replace it from the CA's published file and update its pinned fingerprint",
				a.Ref, cert.NotAfter.Format(time.DateOnly))
		}
	}
}

// A reference that names nothing fails; it is not passed on to be read as a
// path, where a file of that name could stand in for a trust anchor.
func TestUnknownReferenceIsAnError(t *testing.T) {
	_, err := Read(Prefix + "cloudflare-origin-ca")
	if !errors.Is(err, ErrUnknown) {
		t.Fatalf("Read(unknown) = %v, want ErrUnknown", err)
	}
}

// The pin is checked on every read, so an embedded file that is not the
// published certificate is refused rather than trusted.
func TestFingerprintMismatchIsRefused(t *testing.T) {
	a, ok := Lookup(Prefix + "cloudflare-origin-ca-rsa")
	if !ok {
		t.Fatal("rsa entry missing")
	}
	a.SHA256 = strings.Repeat("0", 64)
	if _, err := a.Certificate(); err == nil || !strings.Contains(err.Error(), "does not match pinned") {
		t.Fatalf("Certificate() with a wrong pin = %v, want a fingerprint error", err)
	}
	// And the right pin against another entry's file.
	a, _ = Lookup(Prefix + "cloudflare-origin-ca-rsa")
	a.file = "certs/cloudflare-origin-ca-ecc.pem"
	if _, err := a.Certificate(); err == nil {
		t.Fatal("RSA pin accepted the ECC file")
	}
}

// Text around the block (the provenance header) is allowed; a second block is
// not, because the pin would not cover it.
func TestReadReturnsExactlyOneBlock(t *testing.T) {
	data, err := Read(Prefix + "cloudflare-origin-ca-ecc")
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("Read returned more than one PEM block or trailing text")
	}
	if strings.Contains(string(data), "Source:") {
		t.Fatal("Read returned the provenance header")
	}
}
