# 106. A refusal tells the client nothing it can act on

Date: 2026-11-28

## Status

Accepted. `sec` drives: what a refusal says is part of the boundary. `ux`
challenges what an operator loses; `perf` challenges the request path.

## Context

Each security decision wrote its own refusal, and most of them named the check
that fired:

| Decision | Body |
| --- | --- |
| A WAF rule | `Forbidden by Security Policy (WAF)` |
| Header or body entropy | `Forbidden by Security Fast-Path (High Entropy Detected)` / `(High Body Entropy Detected)` |
| Fingerprint consistency | `Forbidden by Security (Client Spoofing Detected)`, `(Protocol Violation)`, `(Suspicious Client)` |
| Token structure | `Forbidden by Security (Malformed Security Token)` |
| Protocol checks | `Forbidden by Security Policy (<reason>)`, e.g. `(method not allowed)` |
| Fail-closed inspection error | `Forbidden by Security Policy (request could not be inspected)` |
| A refused response | `Forbidden by Security Policy (response blocked)` |
| Reputation | `Forbidden by Security Policy (Reputation Block)` |
| Browser integrity | `Forbidden - Browser Integrity Check Failed` |
| TLS session binding | `Security Check Failed: Session binding mismatch` |
| Zero trust | `Security check failed: ` + the error, e.g. `impossible travel detected` |

To a person, that is a curiosity. To an attacker who changes the payload after
every answer, it is the next step. That attacker used to be a fuzzer with a
fixed mutation list. Now it is just as often a language model running a loop,
which reads the answer and reasons about it. "High Entropy Detected" tells it
to lower the entropy. "Browser Integrity Check Failed" tells it to add the
`Sec-Fetch` headers. "Reputation Block" tells it to change address rather
than payload. "Could not be inspected" tells it the payload found the edge of
the inspection budget. Each of these shortens the search that ends in a
bypass.

The operator does not need the text in the response. The reason is already in
the Security Hub entry, in the log line and in the request's trace. The
`X-Request-Id` the response carries finds the trace.

## Decision

**Every refusal a security decision makes has one body:
`Forbidden by Security Policy`** (`kind.RefusalMessage`, written by
`kind.Refuse`). It is the same whichever decision refused and whatever it
matched, and it is the same for a refused response. The reason is recorded
where it was before, and nowhere the client reads it.

**The status is kept.** A 405 for a method outside the allowlist, a 431 for
oversized headers, a 400 for a malformed request, and a rule's own status
carry HTTP semantics that well-behaved clients act on. They say nothing the
request did not already show. 503 with `Retry-After` for a body the gateway
had no room to inspect is not a refusal and keeps its own text, because it
asks for a retry and says nothing against the request.

**Out of scope:** answers that are an API's contract with its caller. Schema
validation (`Invalid JSON`), the GraphQL firewall's `400`s, authentication
challenges, and an upload refused as too large keep their messages, because a
legitimate client needs them to fix its request. The honeypot, GeoIP and
deception refusals already said only `Forbidden`.

## Cost

Less than before: a constant body and no concatenation. The zero-trust
refusal now logs its reason, once per refusal, at info level, since that line
was the only place the reason had been visible.

## Upgrade and rollback

There is no migration, no proto change and no new setting. A client or script
that matched on a refusal's old text sees the new one. Rolling back restores
the old texts.

## Consequences

- A test that wants to know *which* decision refused reads what was recorded,
  not the body. Two tests did so and were changed.
- A staging switch for verbose refusals was considered and not added. It is
  one more setting that can be left on in production, and the request ID
  already gives the operator the reason.

## Rejected

- **A random or rotating body.** Sameness is the property that matters. A
  body that varies is a signal of its own.
- **Answering every refusal 200 with a decoy page.** That would break API
  clients that rely on status codes, and it is a deception policy. It belongs
  to the deception middleware, per route, not to every refusal.
