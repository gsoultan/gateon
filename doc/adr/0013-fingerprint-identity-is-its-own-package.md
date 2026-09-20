# 13. Fingerprint identity is its own package

Date: 2026-09-20

## Status

Accepted. Co-signed `arch` ↔ `sec`: every file it moves either produces the
identity a security decision is keyed on, or refuses a request based on one.

## Context

ADR-0002 named five subpackages for `internal/middleware` and got four of them
right. The fifth, `security`, it named as one stage — and stage 4 found that it
is not one concern but six that share an adjective. The ratchet records that
honestly rather than hiding it: `scripts/checkfolders/baseline.txt` pins
`internal/middleware/security` at twenty-four files with the six groups written
out and the next seam named.

The WAF cluster came out first, in the commit after the stage landed, because
ADR-0002 had already named it. It left exactly at the ten-file limit and needed
no pin.

This ADR covers the seam that pin names next, and it is a different kind of
group from the WAF. The WAF is a subsystem: one engine, one config, one entry
point. Fingerprint identity is a *layer* — four files that answer "who is this
client" before anything else can decide what to do about them:

- `tls_fingerprint.go` computes JA3/JA4 from the TLS ClientHello and keeps the
  per-connection map that carries them to the HTTP side.
- `tls_binding.go` refuses a session cookie presented from a different TLS
  connection than the one it was issued on.
- `reputation.go` turns a fingerprint into a score and refuses below it.
- `ip_mitigation.go` refuses an address or a fingerprint an operator has
  mitigated.

## Decision

Move those four to `internal/middleware/security/identity`.

The group is cohesive by the only test that matters here: a scratch-package
probe builds all four against **one** undefined symbol — `recordAdvancedThreat`,
the shared threat-recording helper. Nothing else in `security` reaches into
them, and they reach into nothing else.

`recordAdvancedThreat` moves to `kind` as `kind.RecordThreat`. It is the fourth
thing to make that trip (after the parse helpers, the header constants, and the
severity/action vocabulary) and for the same reason each time: it is shared
vocabulary rather than anybody's implementation. Leaving it in `security` and
importing that from `identity` would make a leaf package depend on the package
it was extracted from, which is the shape ADR-0002 exists to avoid.

## Consequences

`security` drops to twenty files and its pin comes down with it, in the same
commit, as ADR-0010 requires. `identity` is four files and needs no pin.

The trust boundary does not move. Every refusal these four make is made in the
same place, on the same input, with the same verdict; what changes is that the
code producing a client identity now sits behind a package boundary from the
code consuming it, so a future change that tries to derive identity from
something the client writes has to cross that boundary to do it.

Two smaller consequences worth naming. `internal/server/tls.go`,
`internal/router/router.go`, `internal/server/entrypoint/` and
`internal/middleware/standard.go` all import the new package — that surface was
already exported and already used from those places, so the change is an import
line rather than a new dependency. And the `security` ↔ `internal/security`
name collision that made stage 4 introduce the `secmw` alias does not recur:
there is no other `identity` package in the tree.

## Related

- ADR-0002, which named `security` as one stage and was wrong about it.
- ADR-0010, the package-size ratchet that made the wrongness measurable.
- ADR-0011, which is about what `reputation.go` keys on; this one is only about
  where it lives.
