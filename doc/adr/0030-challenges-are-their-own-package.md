# 30. Challenges are their own package

Date: 2026-09-28

## Status

Accepted. Co-signed `arch` ↔ `sec`: every file it moves decides whether a
client has proved something — that it runs JavaScript, that it spent the CPU,
that Cloudflare vouched for it — before the request reaches the origin.

## Context

ADR-0013 took fingerprint identity out of `internal/middleware/security` and
left the package at twenty files. The pin in
`scripts/checkfolders/baseline.txt` wrote out what was left and named the
challenge middlewares as the next seam, on the grounds that they "already share
a shape -- issue a challenge, verify a solution, record the outcome."

That shape is the whole of the case, so it is worth stating what it covers:

- `bot_management.go` issues a JavaScript challenge, verifies the signed seed
  the page posts back, and hands out a pass cookie bound to the user agent and
  client address. It also runs the browser-integrity check.
- `bot_management_factory.go` builds it from a route's config map, falling
  back to the global `waf.bot_management` settings, and owns the per-process
  fallback secret that replaced the published constant.
- `pow.go` issues a proof-of-work puzzle to a client whose reputation has
  fallen below a threshold, and verifies the nonce against a challenge it
  signed for that client.
- `turnstile.go` verifies a Cloudflare Turnstile token with Cloudflare's
  siteverify endpoint; `turnstile_factory.go` builds it.

Three mechanisms, one question: *has this client proved it is worth serving?*
None of them refuses a request on what it contains, which is what the WAF,
the recognition scanners and file inspection do; and none of them works out
who the client is, which is what `identity` does. They consume that answer
and ask the client for more.

The pin said seven files. It is five: `pow` has no factory file — its config
is parsed inline in `internal/middleware/factory.go` and in the router's
global-advanced block — and the count was taken from the concern rather than
the directory.

## Decision

Move those five to `internal/middleware/security/challenge`.

The probe ADR-0013 used gives the same answer here. Built as a scratch
package, the five compile against **one** undefined symbol: `security.Deps`,
which `NewBotManagement` took and from which it read one field, the global
config store. Nothing else in `security` reaches into them, and they reach
into nothing else — the threat recording, severity and action vocabulary,
config parsers and preflight test they use were already in `kind` by the time
this landed.

So the seam is closed by narrowing, not by moving: `NewBotManagement` now takes
the `config.GlobalConfigStore` it actually reads. The alternative — `challenge`
importing `security` for the struct, as `waf` does — would make the new leaf
depend on the package it was extracted from, which is the shape ADR-0002 and
ADR-0013 both exist to avoid. `Deps` stays where it is for the WAF, which
genuinely needs four of its fields. `resolveBotSecret` also took `Deps` and
read nothing from it; the parameter is gone.

`factory.go` dispatches to the new package directly, as it already did for
`identity`, `waf`, `traffic` and `transform`: the `case` arms change
`security.` to `challenge.`, and `router.go`'s global proof-of-work does the
same. There is no registry to update because dispatch is a switch.

## What stays

`security` keeps fifteen files and three concerns, plus the two files they
share:

- network access — `geoip`, `ipfilter`, `policy` and their factories;
- API-shape validation — `openapi`, `schema_validation`, `graphql_firewall`,
  `graphql_factory`;
- content inspection — `file_security`, `deception`, `honeypot`;
- `deps.go`, and `security_advanced.go` with the recognition scanners, tarpit
  and entropy check.

The pin names network access as the next seam, because it is the only single
cut that brings the package under the limit and retires the pin.

## Consequences

`security` drops to fifteen files and its pin comes down in the same commit,
as ADR-0010 requires. `challenge` is five files and needs no pin. It enters the
coverage baseline so that it is gated from the start rather than skipped as an
unknown package.

The trust boundary does not move. Each middleware makes the same decision on
the same input in the same position in the chain; the constructors produce
the same middleware from the same config. The one boundary the invariants
script draws around these files moves with them: `check-security-invariants.sh`
permits `kind.IsCorsPreflight` in `bot_management.go` and `turnstile.go`,
because a preflight can neither run a JavaScript challenge nor carry a
Turnstile token, and its allowlist now names them under `challenge/`. `pow.go`
was not on that list and is not now — a proof-of-work challenge does not
exempt a preflight.

Tests moved with the code: the bot-management, redirect, bypass and factory
tests, the three proof-of-work tests, and `security_test.go`, which only ever
tested bot management and is now `bot_management_test.go`.
`allowlist_test.go` split along the boundary the way it did for ADR-0013: the
proof-of-work case moved, the honeypot and allowlist-parsing cases stayed, and
each half names where the other went. `internal/middleware/middleware_test.go`
still drives Turnstile through the root package and now imports `challenge`
for it.

## Related

- ADR-0002, which named `security` as one stage.
- ADR-0010, the package-size ratchet.
- ADR-0013, the extraction this one is modelled on.
- ADR-0015, which made the preflight allowlist the only thing between a
  preflight and the origin.
