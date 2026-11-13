// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package builtinca holds CA certificates compiled into the gateon binary, so
// an operator can name one instead of downloading it and pasting it in every
// time a certificate or client CA is added.
//
// A built-in CA is referenced from any ca_file setting (Certificate,
// ClientAuthority, TlsClientConfig) as Prefix followed by its name, for example
// "builtin:cloudflare-origin-ca-ecc". Nothing is fetched at runtime: the PEM is
// embedded, and its SHA-256 fingerprint is pinned here and checked on every
// read, so an embedded file that does not match the published certificate is
// refused rather than trusted.
package builtinca

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Prefix marks a ca_file value as a built-in CA rather than a path.
const Prefix = "builtin:"

// Use says what a built-in CA is for. It is a hint for the dashboard; any CA
// can be named in any ca_file setting.
type Use int

const (
	// UseServerChain is a CA whose certificates gateon serves. Naming it as a
	// certificate's ca_file appends it to the served chain.
	UseServerChain Use = iota + 1
	// UseClientCA is a CA that signs client certificates gateon verifies,
	// named as a Client Authority's ca_file.
	UseClientCA
)

// ErrUnknown is returned for a reference with Prefix that names no built-in
// CA. It is never resolved as a path: a typo must fail, not fall through to
// whatever file happens to carry that name.
var ErrUnknown = errors.New("unknown built-in CA")

// Authority is one built-in CA certificate.
type Authority struct {
	// Ref is the value to put in a ca_file setting.
	Ref string
	// Name is what the dashboard shows.
	Name string
	Use  Use
	// SHA256 is the pinned fingerprint of the DER certificate, lowercase hex,
	// as Cloudflare's published file produces it.
	SHA256 string
	file   string
}

//go:embed certs/*.pem
var files embed.FS

// catalog is the fixed list of built-in CAs. Each fingerprint was taken from
// the file Cloudflare publishes under developers.cloudflare.com/ssl/static/
// (source of record: github.com/cloudflare/cloudflare-docs,
// public/ssl/static/). The source URL, fingerprint and expiry are repeated in
// the header of each PEM file.
var catalog = [...]Authority{
	{
		Ref:    Prefix + "cloudflare-origin-ca-rsa",
		Name:   "Cloudflare Origin CA (RSA)",
		Use:    UseServerChain,
		SHA256: "d3c7e85c91707fc0a12abc5d88266747aa4fa8e7b162f633ffb3c9d989947620",
		file:   "certs/cloudflare-origin-ca-rsa.pem",
	},
	{
		Ref:    Prefix + "cloudflare-origin-ca-ecc",
		Name:   "Cloudflare Origin CA (ECC)",
		Use:    UseServerChain,
		SHA256: "aa63697a22764b67b2134ce14cb5690ea336940b93986113f49545917832d80d",
		file:   "certs/cloudflare-origin-ca-ecc.pem",
	},
	{
		Ref:    Prefix + "cloudflare-origin-pull-ca",
		Name:   "Cloudflare Authenticated Origin Pulls CA",
		Use:    UseClientCA,
		SHA256: "9a1ac2b4be15f9f27eee20a734cba4e9898f61001b3bd7c84b69b56a3e25a2b9",
		file:   "certs/cloudflare-origin-pull-ca.pem",
	},
}

// IsRef reports whether a ca_file value names a built-in CA.
func IsRef(caFile string) bool {
	return strings.HasPrefix(caFile, Prefix)
}

// All returns every built-in CA, in a fixed order.
func All() []Authority {
	out := make([]Authority, len(catalog))
	copy(out, catalog[:])
	return out
}

// Lookup returns the built-in CA a reference names.
func Lookup(ref string) (Authority, bool) {
	for _, a := range catalog {
		if a.Ref == ref {
			return a, true
		}
	}
	return Authority{}, false
}

// Read returns the PEM bytes of the built-in CA ref names, after checking the
// embedded certificate against its pinned fingerprint.
func Read(ref string) ([]byte, error) {
	a, ok := Lookup(ref)
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknown, ref)
	}
	data, _, err := a.load()
	return data, err
}

// Certificate returns the parsed built-in certificate, after the same
// fingerprint check Read makes.
func (a Authority) Certificate() (*x509.Certificate, error) {
	_, cert, err := a.load()
	return cert, err
}

func (a Authority) load() ([]byte, *x509.Certificate, error) {
	data, err := files.ReadFile(a.file)
	if err != nil {
		return nil, nil, fmt.Errorf("built-in CA %s: %w", a.Ref, err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("built-in CA %s: no PEM certificate", a.Ref)
	}
	// One certificate per file, so the pinned fingerprint covers everything
	// the file can add to a trust pool.
	if next, _ := pem.Decode(rest); next != nil {
		return nil, nil, fmt.Errorf("built-in CA %s: more than one PEM block", a.Ref)
	}
	sum := sha256.Sum256(block.Bytes)
	if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
		return nil, nil, fmt.Errorf("built-in CA %s: fingerprint %s does not match pinned %s", a.Ref, got, a.SHA256)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("built-in CA %s: %w", a.Ref, err)
	}
	return pem.EncodeToMemory(block), cert, nil
}
