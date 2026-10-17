# 74. Schema validation decodes a bounded body, a bounded number of times at once

Date: 2026-10-17

## Status

Accepted.

## Context

The `schema_validation` middleware reads the request body and decodes it into
a generic `any` before it validates it. The only limit on that read was the
gateway's 10 MiB request limit. Decoding JSON into `any` holds many times the
input's length. Measured on 1 MiB inputs, an array of strings held 5.7 MiB, an
array of integers 15.6 MiB, and an array of small objects 45.2 MiB. An earlier
review measured one 10 MiB array at about 225 MiB live. Validating a 4 MiB
array of two million items also took over a minute of one core under the race
detector.

ADR 0069 bounds how many large bodies the WAF inspects at once. It covers only
the WAF. Nothing bounded how many of these decodes ran at once.

## Decision

**Schema validation has its own body limit.** A body longer than the limit is
refused with `413` before any of it is decoded. The middleware reads at most
one byte past the limit, and a declared `Content-Length` over the limit is
refused before anything is read.

- The default is `TierDefaults.SchemaMaxBodyBytes`: 1 MiB on minimal
  and standard, 4 MiB on enterprise. `GATEON_SCHEMA_VALIDATION_MAX_BODY_BYTES`
  overrides it for every route. A route's `max_body_bytes` (shown in the
  dashboard's schema validation editor) overrides both for that route. A
  `max_body_bytes` that is not a positive integer is refused when the route is
  built.

**A body over 64 KiB needs a decode slot.** The slots are one counting
semaphore for the whole process.

- The count is `TierDefaults.SchemaMaxLargeBodies`: 2 on minimal, 8
  on standard and 16 on enterprise. `GATEON_SCHEMA_VALIDATION_MAX_LARGE_BODIES`
  overrides it. The limit cannot be turned off, and a value that is not a
  positive integer is ignored with a warning.
- A body waits up to 2 s for a slot, or until its request is cancelled, as in
  ADR 0069. A body that gets no slot is answered `503` with `Retry-After: 2`. It
  is never forwarded unvalidated.
- The slot is held only while the body is decoded and validated, and is given
  back before the request goes on.

The worst-case memory is the number of slots times the body limit times the
decode multiple. At 45 times, that is about 90 MiB on minimal, 360 MiB on
standard and 2.9 GiB on enterprise. Most JSON costs far less.

## Considered and rejected

**Sharing the WAF's large-body slots.** The brief preferred this, and the
semaphore can be reached without breaking the layering: the WAF package already
imports this one. But it would deadlock. A per-route WAF placed before
`schema_validation` keeps its slot until the request has been proxied. The
validation after it would then wait for a second slot from the same pool while
holding the first. If as many such requests arrive as there are slots, every
one holds a slot, every one waits for another, and after 2 s every one gets
`503`. Two separate pools cannot deadlock. A decode slot is never held while a
WAF slot is being waited for, because validation gives its slot back before
calling the next handler.

**Only the body limit.** A 1 MiB body still decodes to as much as 45 MiB.
Without a cap on concurrency, the management in-flight cap (500) or the
entrypoint connection cap still multiplies that past the host's memory.

## Consequences

- A body over the limit that used to be validated is now refused with `413`.
  Routes that validate larger documents must set `max_body_bytes`.
- When many large bodies arrive at once, some legitimate ones get `503` and
  have to retry.
