# Architecture Decision Records (ADRs)

This directory captures the significant architectural decisions for Gateon. Each
record is immutable once accepted; superseding decisions are added as new ADRs that
reference the ones they replace.

ADRs follow a lightweight [MADR](https://adr.github.io/madr/)-style format:
**Context → Decision → Consequences**, plus status and alternatives.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](./0001-layered-architecture.md) | Layered, domain-oriented architecture | Accepted |
| [0002](./0002-middleware-package-refactor.md) | Staged refactor of `internal/middleware` into cohesive subpackages | Accepted (staged) |
| [0003](./0003-config-store-interfaces.md) | Per-domain `Store` interfaces over a single mega-store | Accepted |
| [0004](./0004-waf-engine-replacement.md) | Replace the Coraza WAF engine with gwaf | Accepted |
| [0005](./0005-session-lifecycle-and-first-run-trust.md) | Session lifecycle and first-run trust | Accepted |
| [0006](./0006-transport-neutral-authorization.md) | Transport-neutral authorization for the management API | Accepted |
| [0007](./0007-xdp-attach-mode-and-the-tc-ingress-hook.md) | XDP attach mode and the TC ingress hook | Accepted; TC parts superseded by 0017 |
| [0008](./0008-response-inspection-must-control-its-own-encoding.md) | Response inspection must control its own content encoding | Accepted |
| [0009](./0009-authenticated-ha-heartbeats.md) | Authenticated HA heartbeats and gossip | Accepted |
| [0010](./0010-package-size-ratchet.md) | The package-size limit is a ratchet, not a wall | Accepted |
| [0011](./0011-reputation-is-scoped-to-a-network.md) | A reputation score belongs to a browser on a network, not to a browser | Accepted; class amended by 0024 |
| [0012](./0012-session-revocation-propagates-but-expiry-guarantees.md) | Session revocation propagates over Redis, but expiry is what guarantees it | Accepted |
| [0013](./0013-fingerprint-identity-is-its-own-package.md) | Fingerprint identity is its own package | Accepted |
| [0014](./0014-backend-client-identity-is-the-gateways-choice.md) | The backend client identity is the gateway's choice | Accepted |
| [0015](./0015-cors-is-decided-per-route.md) | CORS is decided per route, and a backend's own policy wins | Accepted |
| [0016](./0016-per-route-state-is-keyed-by-route-id.md) | Per-route state is keyed by the route's ID; its name is a label | Accepted |
| [0017](./0017-ebpf-falls-back-to-tc-on-its-own.md) | eBPF falls back to the TC hook on its own, and the TC hook enforces what it claims | Accepted |
| [0018](./0018-ebpf-privileges-are-capabilities.md) | eBPF privileges are capabilities, and a container gets them as uid 0 | Accepted |
| [0019](./0019-the-service-runs-as-its-own-account.md) | The packaged service runs as its own account, not root | Accepted |
| [0020](./0020-the-kernel-filters-ipv6-too.md) | The kernel filters IPv6 too | Accepted |
| [0021](./0021-first-run-setup-requires-a-token.md) | First-run setup requires a one-time token | Accepted |
| [0022](./0022-traces-are-archived-an-hour-at-a-time.md) | Traces are archived an hour at a time, in files named for the hour | Accepted |
| [0023](./0023-the-trace-archive-has-a-directory-per-node.md) | The trace archive has a directory per node, and every node reads them all | Accepted |
| [0024](./0024-a-reputation-score-belongs-to-what-a-client-cannot-vary.md) | A reputation score belongs to what a client cannot vary per request | Accepted |
| [0025](./0025-a-finding-limits-an-address-only-for-harmful-traffic-and-only-when-it-repeats.md) | A finding limits an address only for harmful traffic, and only when it repeats | Accepted |
| [0026](./0026-a-fingerprint-block-belongs-to-a-client-build-on-one-network.md) | A fingerprint block belongs to a client build on one network | Accepted |
| [0027](./0027-no-credential-means-nobody-unless-the-base-handler-waives-it.md) | No credential means nobody, unless the base handler waived it | Accepted |
| [0028](./0028-stored-secrets-are-write-only.md) | Stored secrets are write-only | Accepted |
| [0029](./0029-an-address-is-shunned-only-for-more-attacking-builds-than-an-office-has.md) | An address is shunned only for more attacking client builds than an office has | Accepted |
| [0030](./0030-challenges-are-their-own-package.md) | Challenges are their own package | Accepted |
| [0031](./0031-an-automatic-shun-lapses-and-a-repeat-lasts-longer.md) | An automatic shun lapses, and a repeat lasts longer | Accepted |
| [0032](./0032-every-entrypoint-is-capped-and-refuses-blocked-addresses.md) | Every entrypoint is capped, and every entrypoint refuses a blocked address | Accepted |
| [0033](./0033-middleware-secrets-are-write-only.md) | Middleware secrets are write-only | Accepted |
| [0034](./0034-a-middleware-resolves-only-the-secret-references-the-host-allows.md) | A middleware resolves only the secret references the host allows | Accepted |
| [0035](./0035-the-kernel-enforces-the-same-exemption-as-the-data-path.md) | The kernel shun map enforces the same exemption as the data path | Accepted |
| [0036](./0036-a-block-reaches-open-l4-sessions-and-a-per-address-connection-cap.md) | A block reaches open L4 sessions, and every entrypoint caps connections per source address | Accepted |
| [0037](./0037-a-manual-block-may-expire-and-a-fingerprint-is-stable.md) | A manual block may expire, and an API-key fingerprint is stable | Accepted |
| [0038](./0038-binding-a-credential-injecting-middleware-to-a-route-needs-admin.md) | Binding a credential-injecting middleware to a route needs an administrator | Accepted |
| [0039](./0039-the-second-sign-in-step-proves-the-first.md) | The second sign-in step proves the first | Accepted |
| [0040](./0040-the-security-boundary-in-global-settings-needs-an-administrator.md) | The security boundary in the global settings needs an administrator | Accepted |
| [0041](./0041-the-dashboard-session-stays-with-the-dashboard.md) | The dashboard session stays with the dashboard | Accepted |
| [0042](./0042-a-stream-is-what-the-server-answered-and-every-listener-bounds-what-a-client-holds.md) | A stream is what the server answered, and every listener bounds what one client can hold | Accepted |
| [0043](./0043-a-setting-that-saves-does-what-it-says-or-is-refused.md) | A setting that saves does what it says, or is refused | Accepted |
| [0044](./0044-a-waf-geo-or-reputation-switch-does-what-it-says.md) | A WAF, geo or reputation switch does what it says, or says why not | Accepted |
| [0045](./0045-a-challenge-proves-work-not-a-human.md) | A challenge proves work, not a human | Accepted |
| [0046](./0046-auth-cors-and-client-identity-settings-do-what-they-say.md) | Auth, CORS and client-identity settings do what they say, or are refused | Accepted |
| [0047](./0047-a-backend-the-dashboard-shows-is-a-backend-the-gateway-checks.md) | A backend the dashboard shows is a backend the gateway checks, weighs and reports truthfully | Accepted |
| [0048](./0048-a-dashboard-number-is-computed-from-what-runs-or-not-shown.md) | A dashboard number is computed from what runs, or not shown | Accepted |
| [0049](./0049-a-gateway-that-cannot-do-its-job-says-so-and-its-telemetry-cannot-take-it-down.md) | A gateway that cannot do its job says so, and its telemetry cannot take it down | Accepted |
| [0050](./0050-machines-get-a-scoped-token-and-a-stranger-cannot-lock-the-owner-out.md) | Machines get a scoped token, the audit log is kept and checked, and a stranger cannot lock the owner out | Accepted |

## Conventions

- File name: `NNNN-kebab-case-title.md` (4-digit, zero-padded, monotonically increasing).
- Status values: `Proposed`, `Accepted`, `Accepted (staged)`, `Superseded by NNNN`, `Deprecated`.
- Keep each ADR focused on a single decision. Link related ADRs explicitly.
