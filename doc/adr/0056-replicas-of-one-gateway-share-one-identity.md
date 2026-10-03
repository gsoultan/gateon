# 56. Replicas of one gateway share one identity, and the chart runs one replica until they share their settings

Date: 2026-10-04

## Status

Accepted. `ops` drives (the chart, its Secret and its defaults); `arch`
co-signs, because where a gateway's identity lives is a structural decision
about what a replica is, and `sec` co-signs the session key moving from a file
on the volume into a Kubernetes Secret and the environment -- a trust boundary.

## Context

The 2026-10-04 review found (OPS-N1, confirmed with two real processes on one
Postgres, `/tmp/rv-ops2/replicas.py`):

- **With `replicaCount > 1` every replica was a gateway of its own.** The chart
  allowed more than one replica whenever `externalDatabase` and `redis` were
  set, on the reasoning that the database was then shared. It was; but each
  replica kept `global.json` on its own volume, and `global.json` holds what a
  gateway generates for itself on first start -- the session key (which signs
  dashboard sessions and encrypts stored second factors), the audit log's
  signature key and the proof-of-work secret -- as well as everything setup
  writes (`auth.enabled`, the audit log on) and every global setting saved in
  the dashboard. A session from pod A got 401 on pod B; the second step of a
  2FA sign-in on B answered 500 ("stored under a different session key"); the
  audit log was on only on the replica that ran setup.
- **With `persistence.enabled=false` every restart was such a second gateway.**
  The volume is an `emptyDir`, so each start generated a new session key:
  everyone was signed out, and every account with 2FA was locked out, because
  its second factor was encrypted under a key that no longer existed. The
  chart README said setup simply ran again, which is true only without an
  external database; with one, the administrator is still there and setup does
  not reopen.

Setup also stored the wizard's own session key over whatever the configuration
named, so even a key supplied by reference (`$env:`) was replaced on the
replica that ran setup.

## Decision

### The identity comes from the environment, and the chart supplies it

`GATEON_SESSION_KEY`, `GATEON_AUDIT_SIGNATURE_KEY` and `GATEON_POW_SECRET` are
the default values of `auth.paseto_secret`, `audit.signature_key` and
`security_advanced.pow.secret`. They are profile-free: a secret is not a
tunable, and has no per-tier default.

- **A default, as a reference.** When a variable is set, the shipped default of
  its field is `$env:<VARIABLE>`, resolved at load like any other secret
  reference. A gateway whose `global.json` names no value for the field -- a
  fresh install, and every start on a fresh volume -- runs on the
  environment's, and what setup and every later save write back is the
  reference, never the value.
- **`global.json` still wins.** A file that names its own value is an install
  whose sessions, second factors and audit chain were made with it. Replacing
  it would sign everyone out, and replacing the audit key would make the whole
  stored chain fail verification (`VerifyRange` checks with the current key),
  so the file's value is used and the gateway logs a warning naming the
  variables it is not using. An existing install upgraded onto the chart's new
  Secret is therefore unchanged. To adopt the environment's session key, set
  `auth.paseto_secret` to `$env:GATEON_SESSION_KEY` in Settings: that is a
  rotation, and moves the second factors with it.
- **Setup keeps a session key the configuration names by reference**, and uses
  the wizard's only when it names none. The 32-character check on the request
  is skipped then, since the request's key is not used.
- **Rotating a session key that comes from a reference is refused** in the
  settings: it would be in force on one replica, written over the reference on
  one volume, and the second factors re-encrypted under it unreadable wherever
  the reference is read again. The answer names the variable to change and
  `GATEON_PREVIOUS_SESSION_KEY`, which moves the second factors at the next
  start.
- **`audit.signature_key` accepts a secret reference**, which it did not: until
  now the audit key could live only in `global.json`, on one volume.

The chart's Secret (`<release>-secrets`) gains `session-key` (exactly 32
characters: the first 32 bytes are the PASETO v4 key), `audit-signature-key`
and `pow-secret`, and the pod reads them as the three variables. Each key is
reused from the Secret when it is there and generated only when it is not, so
an upgrade from a chart without them generates them once and no upgrade after
that changes them; the Secret keeps `helm.sh/resource-policy: keep`. With
`secrets.existingSecret`, the keys are optional on a persistent volume (where
the first start's generated identity is kept) and required without one, where
a missing key would make every restart a new gateway again.

### The chart refuses more than one replica

Two ways to make the global settings shared were on the table: (a) keep them
in the shared database for multi-replica installs, or (b) refuse
`replicaCount > 1` until (a) exists. (a) is a new store, a migration, a
cross-replica change notification for every subsystem that reads the global
config, and an answer to which of two concurrent saves wins; it is not a
change to make in the same step as the fix. (b) is correct now: the chart
fails at template time with a message naming this ADR, whatever
`externalDatabase` and `redis` say. `kubectl scale` bypasses the chart and is
not supported.

### A fresh volume over a set-up database is a set-up gateway

With persistence off the seed is all a restarted pod has, so:

- **The chart's seed starts the audit log on, signed**, as setup does
  (ADR 0050). On a persistent volume this changes nothing -- setup writes the
  same -- and `globalConfig.audit` still wins.
- **A start that seeded `global.json`, over a database that already holds an
  administrator, records `auth.enabled`.** Setup wrote it to a volume that no
  longer exists; without it the refusal to start on a database that lost its
  administrator (ADR 0049), and authentication of the management API on a
  public entrypoint, were off after every restart. Only a seeded start is
  adopted: on a volume that kept its `global.json`, `auth.enabled: false` is
  the operator's choice.

### The supported HA shape

On Kubernetes: one replica, on a persistent volume or on an external database
with the chart's Secret, restarted by the StatefulSet. Availability comes from
rescheduling, not from a second replica.

On hosts (deb/rpm, the VRRP failover in `internal/ha`): two nodes may share one
database when both run with the same `GATEON_SESSION_KEY`,
`GATEON_AUDIT_SIGNATURE_KEY` and `GATEON_POW_SECRET` (in
`/etc/default/gateon`) and their `global.json` names those variables, and the
operator applies every global-settings change to both nodes. Only the master
serves, so the window in which the two differ is a failover; that is what
[the two-node check](../ha-two-node-check.md) now says.

## Consequences

- A chart install with `replicaCount: 2` fails to render. One that rendered
  before was two gateways; there is no data to migrate, but the operator has
  to scale to one (the second replica's volume holds only its own
  `global.json`, traces and ACME cache).
- Sessions and second factors survive a restart with persistence off, and the
  audit log stays on. Dashboard-saved global settings still do not: with
  persistence off, `globalConfig` is the configuration.
- Existing installs keep their keys; the identity Secret is unused by them
  until `global.json` names the variables. The startup warning says so.
- Not addressed: global settings in the database (option (a)); the setup
  wizard's database step on a gateway whose configuration already names a
  database (found while verifying this: the wizard's default SQLite step
  switches `global.json` to SQLite after the administrator was created in the
  configured Postgres, and the next start refuses -- recorded for a decision).

## Related

- [ADR 0012](0012-session-revocation-propagates-but-expiry-guarantees.md) -- Redis carries
  session invalidations only; it never carried configuration, which is why the
  replicas diverged.
- [ADR 0049](0049-a-gateway-that-cannot-do-its-job-says-so-and-its-telemetry-cannot-take-it-down.md)
  -- `global.json` on the data volume, seeded once.
- [ADR 0050](0050-machines-get-a-scoped-token-and-a-stranger-cannot-lock-the-owner-out.md)
  -- the audit log on for new installs.
