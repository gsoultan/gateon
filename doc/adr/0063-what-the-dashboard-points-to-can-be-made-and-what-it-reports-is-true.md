# 63. What the dashboard points to can be made, and what it reports is true

Date: 2026-10-05

## Status

Accepted. `ux` (what the dashboard offers and says) co-signs with `obs` (how
each number and gate is counted); `qa` for the gate (decision 7), `sec` for the
WAF and Apply-fix changes (decisions 3 and 4).

## Context

The second production-readiness review (2026-10-04) found the dashboard still
pointing operators at things they could not do, and reporting things that
were not so:

- **T36 / NEW-8** the Add Middleware picker could not create bot_management,
  file_security, honeypot, oidc, xfcc, tls_binding, security_headers, policy,
  pow or tarpit -- while the bot settings, the advisory and the posture told
  operators to attach them.
- **NEW-6** the AI Advisory recommended "Enable WAF DoS protection", a flag
  ADR 0044 removed because it selects no rule.
- **NEW-7** the waf_block "Apply fix" reported "shunned at XDP level" with
  eBPF off, and added one more unbounded, non-expiring ipfilter to every route
  per fix; the hardening fix claimed protections it did not turn on and left
  audit-only alone.
- **NEW-9** a route WAF's RCE switch removed the web-shell malware rule
  (tagged `rce`) while `/v1/waf/effective` said malware detection ran.
- **NEW-13** the posture credited a route WAF with every category off as
  blocking; "Update WAF Rules Now" always failed.
- **T41** "Global Threat Score" was the day's unscaled sum; "All checks
  active" was a literal; the log assistant called 401s and a `/.env` probe
  healthy.
- **NEW-10** the config gate matched keys by name across types, accepted
  baseline notes citing tests that bypass the factory, and had no rows for
  global settings.
- **OPS-N4** after an upgrade, routes that fail closed or match nothing were
  invisible until hit.

## Decision

1. **Creatable.** One list, `ui/src/components/MiddlewareConfig/middlewareTypes.ts`,
   offers every type the factory builds, each with an editor; new small
   editors write exactly the keys the factory reads. A tarpit without a
   threshold above 0 and a maximum delay cannot be saved from the dashboard
   (the factory reads an unset threshold as 0, which every client meets).
   `scripts/checkconfig` fails when the factory builds a type the picker does
   not offer.
2. **The advisory recommends what exists.** The DoS-switch check is replaced
   by rate-limit coverage: routes carrying `ratelimit` or `inflightreq`,
   counted in the posture (`rateLimited`).
3. **Apply fix does what it reports.** Blocking a source writes one entry to
   the mitigation block list for 24 hours (a manual-block duration, ADR 0037),
   read back and refused for an exempt address; the kernel is mentioned only
   when the XDP program is attached. No ipfilter, no route edits. The
   hardening fix turns the global WAF on and audit-only off and reports which
   it changed. The global category booleans it used to set are unread, and
   baselined as such.
4. **A category switch removes its own family only.** A family tag removes a
   rule only when the rule is filed under that family or under a category no
   switch owns; PHP, Java and Node.js tags belong to RCE. `/v1/waf/effective`
   is then true as it stands.
5. **Credit only what blocks.** A route WAF with every attack category off is
   `categoriesOff`: no WAF credit, "Not blocking attacks" on the card, an
   advisory finding. The update button that could only fail is gone.
6. **Compute or remove.** The threat-score card is removed; the dependency
   badge counts reported checks; the log assistant reads access-line status
   and path.
7. **The gate checks by type and holds notes to their claim.** Dashboard keys
   are attributed to the type whose editor writes them (the dispatcher's arms
   and the components they render); a row proves a key for its type only; an
   editor key no type renders fails. A baseline note says `unproven: ...`,
   `INERT <finding>`, or `proven by TestX` with X reaching `NewFactory` or
   `ApplyRouteMiddlewares` (directly or through a package helper). Global
   security thresholds (PoW score threshold and difficulty, feed block
   threshold, tarpit, entropy) need a row in
   `internal/router/global_setting_effects_test.go` -- a route chain built
   under two values, answers required to differ -- or a noted line in
   `globals-baseline.txt`.
8. **Say it at start, mark it in the list.** `router.RouteProblems` builds
   every enabled HTTP route's middlewares as the router does and parses its
   rule; the gateway logs one WARN at start naming each route that refuses or
   matches nothing, `GET /v1/routes/problems` returns them (rebuilt only when a
   route is invalidated), and the route list marks them.

## Consequences

- The posture score drops on installs with a route WAF that runs no attack
  category. Routes whose WAF switched RCE off refuse web-shell paths again.
- Fix-applied blocks lapse after 24 hours. Earlier `block-ip-*` middlewares
  stay until removed.
- 140 dashboard (type, key) pairs start the typed baseline, most `unproven`;
  four former notes that cited non-factory tests now say so. 26 pairs and 3
  global settings are proven. Time-based settings (breaker windows, tarpit
  delays, rate per minute) and detection-only ones (entropy) remain unproven:
  the registries record answers, not time or records.
- Building every route's middlewares for the report costs what the first
  request to each route costs; it runs off the start path and is cached.

## Alternatives considered

- **Remove the pointers instead of making the types creatable.** The posture
  and advisory would lose real coverage advice; the editors already existed.
- **Keep the ipfilter, add an expiry.** A per-route middleware outside the
  block list is invisible to Mitigations and the kernel path; the block list
  already has expiry, read-back and exemption.
- **Half credit for a WAF with every category off.** It blocks none of the
  attacks the control measures; half credit would repeat the overstatement.
- **Readiness 503 for a refusing route.** One misconfigured route would take
  the whole instance out of a load balancer.
