# 90. ClamAV on the host is an administrator's decision

Date: 2026-11-13

## Status

Accepted.

## Context

ADR 0040 split the global configuration into what an operator may change and
what only an administrator may: where the gateway believes identity, who it
trusts, what record it keeps. ClamAV was classified operational, and it is not.

- `InstallClamav` and `UninstallClamav` run `docker run` or a package manager
  (with a sudo password) on the gateway's own host. They asked the caller for
  `global:write`, which the operator role holds.
- `waf.clamav.docker_image` is an argument of that `docker run`. Nothing
  checked that it was an image: a value starting with a dash is an option to
  docker, and any image an operator named ran on the host.
- `waf.clamav_addr` and `waf.clamav.clamav_addr` say where every scanned upload
  is sent, whole and unencrypted, and whose answer of "clean" is believed. A
  route's `file_security` middleware could name its own address too, and a
  middleware is `middlewares:write`.

So an operator could run a container of their choosing on the gateway, or
point upload scanning at a host of their own and both read every upload and
pass every one. Found in the 2026-11-13 review (finding S1), proven by a test
that an operator's save and an operator's install both succeeded.

## Decision

**What ClamAV runs on the host, and where uploads go to be scanned, are
administrator-only, on the same rule and the same code as ADR 0040.**

- `waf.clamav_addr`, and `waf.clamav`'s `clamav_addr`, `docker_image`,
  `installation_mode` and `auto_install` are `Boundary` in
  `internal/authz/globalbound/classes.go`. Every save of the global
  configuration goes through `Authorize`, whichever transport stored it.
  Scan schedules and low-resource mode stay operational: they decide when a
  scan runs, not what runs or where data goes.
- `InstallClamav` and `UninstallClamav` ask `Caller.Restricted()` -- the same
  question a save asks, exported for this -- in `ApiService`, which REST, gRPC
  and Connect all call. The refusal precedes the configuration write and the
  preflight. REST answers 403 rather than 500.
- `docker_image` must be an image reference (`security.ValidateClamAVImage`):
  refused at save, and again immediately before docker is run, because a
  configuration file edited on disk never passed the save.
- A route's `file_security.clamav_addr` may name only a scanner on the gateway
  itself: `unix://`, or `tcp://` on `localhost` or a loopback address. It is
  refused at save (`Factory.Validate`). A remote scanner is the global
  setting. A middleware already stored with a remote address keeps working
  until it is next saved; refusing it at build would stop scanning on a route
  that has it, which is the worse failure.

The route role is not given a way to name a remote scanner behind an
administrator's approval. One global answer to "where do uploads go" is the
property; ADR 0091 extends that answer from one address to a pool.

## Consequences

- An operator who installed ClamAV from the dashboard no longer can. That is
  the change, and `doc/upgrading.md` says so.
- The dashboard warns before an install on a host under 4 GB: clamd keeps about
  1 GB resident, which on a 2 GB gateway is half of what the proxy has.
- Not changed: the install still runs as the gateway's user with whatever
  docker or sudo access that user has. ADR 0091 proposes moving the scanner
  off the gateway, which removes the reason to hold that access at all.
