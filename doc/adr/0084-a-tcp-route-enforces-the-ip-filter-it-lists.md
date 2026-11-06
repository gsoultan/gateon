# 84. A TCP route enforces the IP filter it lists

Date: 2026-11-06

## Status

Accepted.

## Context

CVE-2026-123158 ("sshole", CVSS 8.1) lets a very long password log in to an
account that has no password, on OpenSSH built against musl without PAM -- the
default `openssh-server` on Alpine. The password travels inside the encrypted
SSH session, so no gateway can see it: gwaf only reads HTTP, and Gateon's `ssh`
L4 routes read the plaintext version banner to choose a backend and pass the
rest through unread. The fix is a patched sshd.

What a gateway in front of SSH can decide is who may open the connection at
all. Gateon looked as if it could: a route's `middlewares` field is shared by
every route type, the dashboard offered the same policy picker on a TCP route
as on an HTTP one, and it saved an `ipfilter` attached to an SSH route without
complaint. Nothing on the L4 path ever read it. `l4.Resolver` resolved a TCP
route to its service's backends and nothing else, so an SSH route restricted to
an office range in the dashboard accepted every address on the internet.

## Decision

**An `ipfilter` middleware listed on a TCP route (`tcp`, `ssh`, `rdp`) is
enforced against the connection's TCP peer address**, before a backend is
dialled. It is built from the same lists, with the same validation, as the HTTP
filter (`security.NewAddrFilter`). On an L4 connection there is nothing to
believe but the peer, so `trust_cloudflare_headers` does not apply.

- **Where:** `l4.Resolver.ResolveTCP`, which every TCP path goes through --
  inspected (SSH/RDP), first-speaker and plain TCP entrypoints alike. The guard
  is cached beside the route's pool and rebuilt when the middlewares' content
  changes, which is checked on each connection without allocating, so an edit
  made through any transport (REST, gRPC, dashboard, config import) applies to
  the next connection.
- **Failing closed:** a listed middleware that no longer exists, or an
  `ipfilter` whose stored lists no longer build, refuses every connection to
  the route, as the HTTP router refuses a route whose security middleware does
  not build. Several filters must all admit.
- **Other middleware types** do nothing on a TCP connection, as before. They are
  logged when the route's guard is built, and the dashboard now offers only IP
  filters on a TCP route (none on UDP) and marks any other policy already on
  one as not applied.

## Consequences

- An install with an `ipfilter` already attached to a TCP route starts
  enforcing it on upgrade. That is the behaviour the dashboard always showed;
  anyone relying on the gap was relying on a bug.
- An install whose TCP route names a deleted middleware stops serving that
  route, with a WARN naming it. Before, the reference did nothing.
- UDP routes still enforce no filter. A per-packet check needs an
  allocation-free address match first, and UDP source addresses are spoofable,
  so it is left as separate work.
- Refused connections are logged at DEBUG only, so a scan cannot flood the log;
  there is no metric for them yet.
