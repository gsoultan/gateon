# 10. The package-size limit is a ratchet, not a wall

Date: 2026-09-03

## Status

Accepted. Supplements ADR-0002, which stays in force: its staged plan for
`internal/middleware` is still the plan. This ADR adds the enforcement that plan
turned out to need.

## Context

ADR-0001 set a limit of ten files per package, and `arch` carries it as a veto.
Nothing enforced it. A count on 2026-09-03 found **nine packages over the limit**:

| Files | Package |
|------:|---------|
| 67 | `internal/middleware` |
| 36 | `internal/api` |
| 31 | `internal/telemetry` |
| 22 | `internal/server/handlers` |
| 20 | `internal/config` |
| 17 | `pkg/proxy` |
| 13 | `internal/server` |
| 13 | `internal/security/waf` |
| 11 | `internal/middleware/auth` |

(Implementation files only; `_test.go` is excluded — see *Decision*.)

The important part is not the size of that list but what happened to the one
package that was actively being fixed.

ADR-0002 laid out a careful staged refactor of `internal/middleware`: extract the
cycle-free core into `kind`, then move one cohesive group at a time, never leaving
`main` non-compiling. It is a good plan. **Two of its stages shipped.** Stage 0
created `internal/middleware/kind`; Stage 1 moved ten files into
`internal/middleware/auth`.

ADR-0002 recorded the package at **65 non-test files** on 2026-06-15. After both
stages extracted roughly thirteen files, `internal/middleware` today holds **67**.

The refactor moved thirteen files out and the package still grew by two. New
middleware landed in the root package faster than the extraction drained it. Over
the same period its test count went from 8 to 45, which is real progress on a
different axis and is exactly why the file limit must not count tests.

`internal/middleware/auth` tells the same story in miniature. ADR-0002 promised
each new subpackage would "land within the ≤10-files budget", and it did — at ten
files. It is now at eleven. The budget was met on the day of the move and lost
afterwards, because nothing was watching.

So the failure is not a missing plan, a missing decision, or a missing sense of
where the seams are. ADR-0002 has all three. The failure is that a limit which
nothing measures is not a limit, and a staged refactor without a ratchet is a
footrace against the feature work landing in the package being refactored.

Two responses were available and both are wrong. Splitting all nine packages is a
months-long refactor of the request path, taken on at once, in the least-covered
and most security-sensitive code in the tree — `internal/middleware` sits at 59.3%
coverage, `factory.go` alone resolves symbols from 37 of its siblings, and only
three of its files have no intra-package dependency at all. Splitting only the
largest fixes one ninth and leaves the rule exactly as unenforced for the other
eight, which is how all nine got here.

## Decision

Enforce the limit as a ratchet, the way `make lint-new` gates new lint findings and
`check-coverage` gates the tested surface. `scripts/checkfolders` runs in `make sec`
and in CI, and fails on three things:

1. **An unlisted package over ten files.** A tenth package cannot quietly join the
   list. The failure arrives when the package is eleven files, which is when
   splitting it is still cheap.
2. **A pinned package growing.** The nine are recorded in
   `scripts/checkfolders/baseline.txt` at their 2026-09-03 size. They may shrink;
   they may not grow. Code that would push one of them up goes in its own package.
   This is the rule that would have stopped `internal/middleware` going 65 → 67
   while it was being refactored, and `auth` going 10 → 11 after it landed.
3. **A pinned package shrinking without banking the gain.** Dropping below the
   baseline is also a failure, whose fix is to lower that line in the same commit.
   Without this the ratchet only holds in one direction: a package could be split
   to eight files and drift back to fifteen while still passing.

Test files do not count. The limit exists so a reader can hold a package in their
head, and `_test.go` files are read when working on the thing they test, not when
trying to find it. Counting them would also make the gate push back on writing
tests, which is precisely backwards — and this package added 37 tests over the same
window in which it added two implementation files.

Generated code is excluded (`proto/gateon/v1`, `bpf2go` output): its size is decided
by a schema, so capping it would only ever block a legitimate proto change.

The check is negative-tested, per the invariant rule: `scripts/checkfolders/main_test.go`
exercises each of the three failure modes plus a stale baseline line, and both
growth paths were confirmed failing against the real tree.

## Consequences

- **ADR-0002's remaining stages now converge.** `security`, `traffic`, `transform`
  and the registry dispatch are unchanged as a plan. The difference is that the
  parent package can no longer grow underneath them, so each stage's gain is
  permanent instead of being spent on the next month's middleware.
- **The nine are debt with a ceiling instead of debt with a slogan.** Nothing is
  required to shrink today. Nothing may get worse.
- **`internal/middleware/auth` is the cheapest correction available** — one file
  over, and retiring its line removes an entry from the list entirely.
- **The rule is no longer aspirational for the 64 packages that comply.** They were
  always the majority; they simply had nothing confirming it.
- **Cost:** a baseline file that must be lowered when a package shrinks. That is
  deliberate friction, and it is the whole mechanism: it makes progress explicit
  and irreversible rather than silent and refundable.
- **This does not amend the ten-file rule.** CLAUDE.md permits either splitting or
  amending it, and amending would have meant writing down that a limit violated by
  nine packages is fine. The limit is right; it was simply never load-bearing.

## Related

- ADR-0001 — layered architecture and the ≤10-files rule.
- ADR-0002 — the staged `internal/middleware` refactor this ratchet protects.
- `scripts/checkcoverage`, `scripts/checkconfig` — the same baseline-and-ratchet
  shape, for the tested surface and for config fields that nothing reads.
