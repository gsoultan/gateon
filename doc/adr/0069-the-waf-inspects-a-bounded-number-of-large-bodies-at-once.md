# 69. The WAF inspects a bounded number of large bodies at once

Date: 2026-10-14

## Status

Accepted.

## Context

Inspecting a request body costs a multiple of its length. gwaf keeps one buffer
per transform depth and a set of readings per value, each sized to the value,
and holds them until the transaction is closed. gateon closes it after the
request has been proxied, because the response phases still need it. Measured
in gwaf, an open transaction holding a 1 MiB form used about 7.75 MiB live; JSON
about 2.9 times its length and plain text about 3.3 times. A 1 MiB form also
took about 52 ms of one core.

On the 2 core / 2 GB target, 600 clients from 600 addresses each posting a
1 MiB form took the gateway to 1.73 GB with `GATEON_MEMORY_LIMIT=1536MiB`.
About half the uploads timed out, and so did small `GET`s from unrelated
clients. Every one of those clients stayed inside the per-address connection
cap (ADR 0036), the entrypoint cap (ADR 0032) and the body limit. Those bound
what one client or one connection holds. Nothing bounded how many large bodies
were being inspected at once, and that sum is what ran out.

## Decision

**A body over 64 KiB needs a large-body slot to be inspected.** The slots are
one counting semaphore for the whole process, because the memory they protect
is the process's. A cap per route would multiply by the number of routes.

- The count is `TierDefaults.WAFMaxLargeBodyInspections`: 4 on minimal, 16 on
  standard and 64 on enterprise. Override it with
  `GATEON_WAF_MAX_LARGE_BODY_INSPECTIONS`. It cannot be switched off. A value
  that is not a positive integer is ignored with a warning.
- The slot is taken after the body is read and before it is handed to the
  engine. It is given back after the transaction is closed, because that is
  when the engine lets go of what it built.
- A body waits up to 2 s for a slot, or until its request is cancelled. A
  burst of real uploads queues briefly.
- A body that gets no slot is answered `503` with `Retry-After: 2`. It is never
  forwarded uninspected, whatever `FailOpen` says. Forwarding would let a flood
  buy an uninspected body just by being a flood. It is not `403`, because
  nothing is known against the request and its client is not penalised.
- `gateon_middleware_waf_shed_large_bodies_total{route}` counts the 503s.

Bodies of 64 KiB or less never take a slot. Ordinary API, form and GraphQL
requests never queue behind a flood of large ones.

## Considered and rejected

**Taking the slot before reading the body.** This would bound the read buffers
too. But a client that sends its body slowly would hold a slot for the whole
read timeout, so a few slow uploads could starve every other one. The read
buffer is already bounded per request by the body limit and per client by the
connection caps.

**Releasing gwaf's buffers after the body phase.** That would let the slot be
returned before proxying. It is a gwaf change, and it is still worth making,
because it shortens how long each slot is held. The two compose. Without this
cap, though, the peak is still unbounded while inspections overlap.

## Consequences

- With 1 GiB as the memory limit, the same 600-client flood peaked at about
  1.06 GB. A small probe request failed or took over 2 s 0 times in 28, and no
  upload was left hanging. About 7 of every 100 uploads were inspected and the
  rest got 503. Without the cap, the same run timed out 724 uploads, and the
  probe managed 3 requests in 30 s.
- During a flood, a legitimate large upload can get 503 and has to retry. That
  is load shedding, reported honestly with the metric above. It is not a
  detection result.
- `tests/e2e/hostile_load_test.go` holds the flood as an opt-in test
  (`GATEON_FP_LOAD_TEST=1`).
