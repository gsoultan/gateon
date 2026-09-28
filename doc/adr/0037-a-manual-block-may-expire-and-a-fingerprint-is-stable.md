# 37. A manual block may expire, and an API-key fingerprint is stable

Date: 2026-09-28

## Status

Accepted. Co-signed `api` ↔ `data`/`sec`: it adds a field to
`MitigateThreatRequest` and changes what a manual block's row means (`api`
owns the contract, `data` the store), and it changes how the dashboard's
API-key fingerprint is derived when no encryption key is set (`sec`). Two
unrelated decisions taken together because both landed in the mitigate/secret
surface `api` owns this round.

## Context — a manual block never lapsed

ADR 0031 made every automatic shun lapse: the address shun, the anomaly
detector, alert playbooks, the incident responder all shun through
`telemetry.ShunAutomatically`, which writes `ip_mitigations.expires_at` (the
column migration 66 added) and enforces it through `IsIPMitigated` until then.
An operator's own block -- `MarkIPMitigated`, from the mitigate API or an
applied recommendation -- was deliberately left holding until released, with a
NULL `expires_at`.

That left an operator no way to say "block this address for an hour". A short
block had to be set and then remembered and lifted by hand, which is the
never-lapsing shun ADR 0031 argued against, surviving on the one path an
operator drives directly. ADR 0031 named the fix and declined to take it: "An
optional duration for manual blocks was not added: it needs a field on
`MitigateThreatRequest`, a proto change this round did not take."

## Context — the API-key fingerprint changed on every restart

The apikey middleware stores each key as a config key `key_<APIKEY>`. ADR 0033
made middleware secrets write-only, so the API shows a key as a placeholder
marker `key_<Sentinel>_<fingerprint>` and a save sends the marker back to keep
the stored key it names. The fingerprint is an HMAC of the middleware id and the
key, keyed from `GATEON_ENCRYPTION_KEY` -- or, when that was unset, from a key
generated randomly once per process.

A per-process random key is not stable across a restart. A form opened, or a
config exported, before a restart carried markers whose fingerprints matched no
stored key afterward, so every API key in the save was refused by tenant and
the operator could not save the form at all. The failure was total for the
common deployment that never sets `GATEON_ENCRYPTION_KEY`.

## Decision

**A manual block may carry an optional duration.** `MitigateThreatRequest`
gains `int32 duration_seconds = 5` (the next free tag; the message reserved
none). A positive value makes the mitigate handler call a new
`telemetry.MarkIPMitigatedFor`, which writes the block with
`expires_at = now + duration`; zero or absent calls `MarkIPMitigated` as
before, with a NULL expiry. Both are unconditional operator writes that
override whatever the row held -- unlike the automatic shun's conditional
write, because an operator setting a bounded block means it. The duration
applies only to an IP block; a fingerprint block keeps its own hour-long TTL
(ADR 0026).

Nothing else changed to make it work: `IsIPMitigated` already lifts a shun the
moment its `expires_at` passes, and `GetIPMitigations` already surfaces
`expires_at` and the dashboard already counts it down. The kernel entry is
leased with `ShunIPUntil` for a bounded block, so it lapses in the kernel too,
exactly as an automatic shun does. **No migration** -- the `expires_at` column
exists (migration 66); a manual block now sets it instead of leaving it NULL.

The mitigation dashboard's Add Mitigation control gains a duration for an IP
block (until released, 1h, 6h, 24h, 7d).

**A consequence, accepted:** the automatic ladder reads the row, not the
reason. If a bounded manual block lapses and the address attacks again within
`autoShunMemory`, `nextShunDuration` reads the lapsed manual row and the next
automatic shun is twice the manual block's length (capped at a day). That is a
reasonable escalation, not a regression: a manual block that just lapsed is
evidence the address is worth watching, and the automatic path only writes when
no block is in force.

**The API-key fingerprint is stable when no encryption key is set.** The
fingerprint is not a secret: it identifies a stored key within one gateway and
is never compared across gateways. So when `GATEON_ENCRYPTION_KEY` is unset (or
shorter than the 16-byte floor the config encryption applies), the fingerprint
key is a fixed public constant, which makes the derivation deterministic and the
fingerprint identical across a restart. When the key is set the derivation is
unchanged: keyed from it, stable across a restart, and agreeing across gateways
that share it.

What the constant gives up, versus the random key, is unlinkability across
gateways (the same key now fingerprints the same on two of them) and
offline-guessing resistance for weak, hand-typed keys ("partner-2024") from a
leaked masked config. Neither matters when there is no encryption key: the
fingerprint identifies a stored key, not the key's value, and a deployment with
no `GATEON_ENCRYPTION_KEY` already stores its config -- and so its API-key
values -- unencrypted, so the fingerprint is not the weakest link. An operator
who wants either property back sets `GATEON_ENCRYPTION_KEY`, which restores
both.

## Consequences

- **An operator can block an address for a bounded time and forget it.** It
  lapses on its own, is listed with when it lifts, and needs no return visit.
  An open-ended block is unchanged: NULL expiry, held until released.
- **No new tunable and no new migration.** The duration is per request, and the
  expiry column already existed.
- **A form or export can be saved after a restart with no encryption key.**
  Every API key matched by fingerprint before was refused; now it is kept.
- **Tests that failed against the code before this change.** Item 4:
  `TestAManualBlockWithADurationLapsesWithoutAnOperator` and
  `TestAManualBlockWithNoDurationNeverLapses` (`internal/telemetry`, SQLite and
  Postgres), `TestMitigateThreatRoundTripsAManualDuration` and
  `TestMitigateThreatWithoutADurationIsOpenEnded` (`internal/api`), and the UI
  hook's "forwards a bounded block's duration". Item 5:
  `TestFingerprintIsStableWithoutAnEncryptionKey` and
  `TestASaveKeepsAnAPIKeyMadeBeforeARestart` (`internal/config/mwsecret`); each
  was mutation-checked.

## Related

- ADR 0031 (automatic shuns lapse; migration 66's `expires_at`), whose declined
  manual-duration follow-up this takes.
- ADR 0033 (middleware secrets are write-only), whose fingerprint marker this
  makes stable.
- ADR 0026 (the fingerprint block's hour and its release's day).
