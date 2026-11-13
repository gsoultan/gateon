# 86. Cloudflare's CA certificates are built in

Date: 2026-11-13

## Status

Accepted.

## Context

A Gateon behind Cloudflare needs Cloudflare's CA certificates in two places:

- **Origin CA (RSA and ECC).** A Cloudflare Origin certificate is issued by
  one of two roots, and a certificate's `ca_file` appends that root to the
  served chain. Operators downloaded `origin_ca_rsa_root.pem` or
  `origin_ca_ecc_root.pem` and uploaded or pasted it for every certificate
  they added. The dashboard's own placeholder (`certs/cloudflare-origin-ecc-ca.pem`)
  showed the expected workflow.
- **Authenticated Origin Pulls CA.** A Client Authority that verifies the
  certificate Cloudflare presents when it connects to the origin.

The files are public, stable for years, and identical for every installation,
so asking each operator to fetch them is busywork and a chance to pick the
wrong one (an RSA leaf chained to the ECC root fails the handshake).

## Decision

**The three certificates are embedded in the binary** in
`internal/tls/builtinca`, and any `ca_file` setting (Certificate,
ClientAuthority, TlsClientConfig) may name one as `builtin:<name>` instead of
a path:

| Reference | Certificate | Expires |
| :--- | :--- | :--- |
| `builtin:cloudflare-origin-ca-rsa` | CloudFlare Origin SSL Certificate Authority | 2029-08-15 |
| `builtin:cloudflare-origin-ca-ecc` | CloudFlare Origin SSL ECC Certificate Authority | 2029-08-15 |
| `builtin:cloudflare-origin-pull-ca` | origin-pull.cloudflare.net | 2029-11-01 |

- **Nothing is fetched at runtime.** The PEMs were taken from Cloudflare's
  published files (`developers.cloudflare.com/ssl/static/`, source of record
  `github.com/cloudflare/cloudflare-docs` `public/ssl/static/`); each file's
  header records the source URL, fingerprint and expiry.
- **Pinned.** Each entry carries the SHA-256 of its DER certificate, checked on
  every read. A file that is not the published certificate, or holds a second
  PEM block the pin would not cover, is refused.
- **Fail closed on a typo.** A `builtin:` reference that names nothing is an
  error. It is never resolved as a relative path, which would let a file of
  that name in the working, data or config directory stand in for a trust
  anchor.
- **Listed on every transport.** `ListBuiltinCertificateAuthorities` (gRPC and
  Connect) and `GET /v1/certs/builtin` (REST) answer the catalog, with key
  type, subject, fingerprint, expiry and `expired`/`expiring_soon` flags,
  under the same `certs` read permission as the certificates themselves. The
  dashboard's certificate and Client CA forms offer the list beside the paste
  and upload buttons.
- **Staleness is visible, early.** Certificate validation now warns when any CA
  in a certificate's `ca_file` (built-in or not) has expired or expires within
  90 days, and that warning is shown on the certificate. `builtinca` tests fail
  CI six months before a built-in CA expires, which is the lead time a
  replacement needs to reach a release.

## Consequences

- A built-in CA changes only with a release. When Cloudflare rotates a root,
  the file and its pin are replaced together and the old reference keeps
  working if the name still applies.
- Adding a CA to the catalog is adding a trust anchor every installation can
  select; it needs `sec` sign-off, a published source and a pinned fingerprint.
- Existing installations are unaffected: a `ca_file` that is a path is read
  exactly as before.

Driver: `sec` · Challenger: `arch`.
