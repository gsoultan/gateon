# 21. First-run setup requires a one-time token

Date: 2026-09-26

## Status

Accepted. Amends the first-run half of [ADR 0005](0005-session-lifecycle-and-first-run-trust.md).

## Context

Setup runs before any account exists, so it cannot ask for a login. ADR 0005
made the rest of the management API refuse until setup completes, and left the
management bind a wildcard by default, because loopback breaks every container
deployment. What remained open, on REST, Connect and gRPC alike, was setup
itself: whoever reached a fresh gateway first could make themselves its
administrator.

Two findings made that window worse than a race for the first account:

- The wizard's connection test opens a database connection to an address the
  caller chooses. Its errors told a refused port from a filtered one and from a
  service that was not Postgres, which made an unconfigured gateway a scanner
  for its own network -- a quiet one, unlike a takeover, which the operator
  notices when they find setup already done. The errors now say less (see
  `db.Probe`), but a connection test has to say whether a server answered.
- `lib/pq` allocates a buffer as large as a server's claimed message length
  before reading it. A probe of a hostile server can therefore attempt a
  multi-gigabyte allocation, which is fatal on the 2 GB hosts gateon targets.
  That is not fixable from outside the driver.

Both are only reachable by a caller who can use setup. Closing setup to callers
who are not the operator closes them.

## Decision

**Setup and its connection test require a one-time setup token.**

- At startup, when setup is required, the gateway generates 32 random bytes,
  writes them base64url-encoded to `setup-token` in its data directory (created
  afresh, `0600`, never through whatever was at that name), and prints the token
  in its log. Those are two places the operator can read -- the host, or the
  container's logs -- and a caller on the management port cannot. On a first run
  the log is local: log shipping is configured in `global.json`, which does not
  exist yet.
- `GATEON_SETUP_TOKEN` supplies the token instead, for automation, and is then
  neither printed nor written. Fewer than 16 characters is refused and a random
  token used in its place, with the refusal logged.
- The token is a field of `SetupRequest`, so one check in `ApiService.Setup`
  covers REST, Connect and gRPC; the connection test decodes the same message
  and checks the same token. Both compare in constant time, after the
  setup-required guard and before anything acts on the request.
- A token that was never wired in matches nothing: setup stays closed rather
  than open.
- A successful setup retires the token and deletes its file.
- `IsSetupRequired` stays public. The dashboard needs it to route to `/setup`,
  and whether setup is open is not a secret.

## Consequences

Scripted setup must send the token: read it from `setup-token`, or set
`GATEON_SETUP_TOKEN` and send that. A request without it is refused with a
message saying where the token is.

The operator needs the host or the container to set a gateway up, which is the
point. In Kubernetes that is `kubectl logs`, or a Secret mapped to
`GATEON_SETUP_TOKEN`.

The first-run window is closed to callers on the network, so the `lib/pq`
allocation and the remaining Postgres-discovery signal of the connection test
are reachable only by someone who already holds the token. The driver issue
stays open upstream.

A gateway that needs setup again after it has run -- every administrator gone --
publishes a new token at its next start, not before.
