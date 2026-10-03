# 44. A WAF, geo or reputation switch does what it says, or says why not

Date: 2026-10-03

## Status

Accepted. `sec` co-signs with `ux`: every decision changes which requests the
gateway refuses at a trust boundary (the WAF, the geofence, the IP decision
every entrypoint makes) and what the dashboard tells an operator about it.
`perf` co-signs the reputation-feed lookup, which runs on every request.

## Context

ADR 0043 set the rule: a security setting either does what its label says or is
refused or flagged at save -- never a silent no-op. The 2026-10-02 truth review
found five controls in this area that broke it:

- **T1 -- global "Blocked Countries" blocked nobody without a GeoIP database.**
  A default install has geofencing enabled and no MaxMind licence key, so no
  database: every client resolved to the unknown country `XX`. A block list
  saved with success and refused no one; an allow list refused everyone. The
  card warned only that the map would be empty.
- **T3 -- the IP reputation feed refused no one on its own.** "Sync with threat
  feeds to block known malicious actors" loaded the feeds; the only reader was
  a WAF rule behind the WAF's own `ip_reputation` switch, off by default.
- **T7 -- a per-route WAF dropped rules the global WAF ran.** A route with its
  own WAF skips the global one, and it filled unset settings from the raw
  global proto booleans. The global WAF ignores those for malware and
  ransomware -- it forces them on -- so a default route WAF turned `/c99.php`
  from 403 into 200.
- **T8 -- the WAF category switches and "Use OWASP CRS" were inert.** A switch
  removed rules from gateon's corpus only; gwaf's core ruleset, where the
  structural SQLi/XSS/traversal/command-injection detection lives, was loaded
  whole. With every switch off every attack was refused, and the global card
  showed the categories OFF while they were enforced.
- **T12 (data half) -- an audit-only WAF was reported as protecting.** The
  posture report carried `waf.enabled` and nothing about the mode.

## Decision

### WAF switches (T8)

Each category switch names the gwaf core tags it turns off as well as gateon's
categories and tags (`categorySwitches` in `waf_engine.go`): SQLi `sqli`, XSS
`xss`, LFI `lfi`/`traversal`/`rfi`, RCE `rce`, PHP `php`, Java
`java`/`jndi`/`ognl`/`spel`, Node.js `nodejs`/`prototype-pollution`, scanner
`scanner`, WordPress `wordpress`. gwaf loads its core whole or not at all, so a
narrowed core is `core.Default()` filtered by `Policy.CoreDisabledTags` and
handed back first, under `WithoutCoreRuleset`; when nothing is filtered gwaf
loads it itself, so the stock engine is unchanged. The two corpora keep separate
tag sets because they tag differently (gwaf's scanner rule also carries
`reputation`, which is off by default in gateon's set).

PHP, Java and Node.js code injection are code execution: turning RCE off lets
those through too. The reverse does not hold -- turning Java off leaves RCE's
own Log4Shell rule in force. Switching every family off is not switching the
WAF off: rules no switch names (cloud-metadata SSRF, among others) still run.

**The global WAF's category switches stay ignored, and the dashboard no longer
offers them.** The proto booleans have no presence and `global.json` is written
with `omitempty`: a switch nobody touched and one switched off store the same
`false`. Every existing global WAF stores all of them false, and runs all of
them. Honouring them would strip detection from every install that never set
them; making them meaningful needs a field that records "off" explicitly (a
`disabled_categories` list), which is a proto change this round did not make.
The global card therefore shows, read-only, what the global WAF runs, from the
engine's config, and says how to narrow a family: attach a route WAF and switch
it off there. "Use OWASP CRS" selected nothing and is gone (it also could not be
stored: `use_crs` defaults to true and `false` is omitted from the file).
"DOS Protection" selected no rule either; it is gone from both cards, and a
stored `dos_protection` is named in the log once per engine build.

### Per-route merge (T7)

A route WAF starts from the config the global WAF is actually built from
(`globalWAFConfig`: tier baseline, forced malware/ransomware, paranoia level,
enforcement, app profiles, origins, SSRF, DLP), rendered as route keys
(`inheritedSettings`). A key the route sets wins; a key it leaves out (or leaves
empty) is the global WAF's. So a route adds to or narrows the global policy only
by saying so, and the dashboard shows which. Previously inheritance also
depended on `use_crs`; it no longer does.

### What runs, read from the engine (T8 card, T12)

`GET /v1/waf/effective` (read on the global resource) returns the global WAF's
mode (`enforcing`, `audit_only`, `off`), paranoia level and category map, and
the same for every `waf` middleware merged over it. The global card and the
route editor read it. The posture report's `waf` gains `mode`, from the same
function, so an audit-only WAF is distinguishable; the Security Hub copy is the
`dash` agent's (ADR 0048).

### IP reputation feeds (T3)

A feed listing is enforced by `identity.AddressBlocked` -- the decision every
HTTP entrypoint, TCP entrypoint and route already makes -- under the same
exemption (loopback, `GATEON_MITIGATION_ALLOWLIST`). `main` publishes the store
it starts (`reputation.Publish`), so no chain builder needed a new dependency.
A listing refuses at or above the block threshold (a listing scores 100; above
100 a feed loads and refuses no one). The refusal is recorded as an
`ip_mitigation` threat with no score: visible in the Security Hub, never
evidence towards an escalation, moving no reputation. The WAF's own switch is
relabelled "Behavioural Reputation": it still refuses clients whose own score
fell below 20.

Every request now asks the feed, so the store's index is an immutable
generation behind an atomic pointer (no lock). `BenchmarkIPMitigation`, n=6:
+1.4 ns (+2.4%) with no feed loaded, +17 ns with 4096 entries not listing the
client, no new allocations.

### Geofencing without a database (T1)

- **Save.** `ValidateGeoIPSave`, on the domain path REST, Connect, gRPC and the
  recommendation writer share, refuses a changed global country list when
  geofencing is enabled and no database is loaded and none at the proposed
  `db_path` opens. The message says what to install and where. A code that is
  not two letters is refused too, globally and on a route geofence (it matched
  nothing). A list that is not being changed is not re-judged, so a stored list
  does not hold every unrelated settings save hostage.
- **Runtime, when the database is missing** (a list stored before this check,
  or a database that went away): an **allow list fails closed** -- "only these
  countries" cannot be shown of anyone, and serving everyone would be the
  silent failure this ADR exists to remove. A **block list serves, loudly** --
  refusing everyone in its place would turn "block CN" into an outage nobody
  asked for, and a block list exists to refuse a subset. Both are logged at
  error at most once a minute, and `GET /v1/geoip/status` reports the
  geofence's state (`active`, `block_list_inactive`,
  `allow_list_refusing_all`, `off`) with the reason; the GeoIP card shows it.
- **The database cannot vanish by accident any more.** `InitGeoIP` (and the ASN
  and Country loaders) closed the loaded database before opening the new one,
  so saving a mistyped path took geolocation away until restart. The new one is
  opened first; a path that does not open leaves the old one in force. A
  Country database alone now resolves countries (it was loaded and never
  asked), and cached answers are dropped when the database changes.

## Consequences

- An install with a feed configured starts refusing what it lists on every
  route. An install with a global country list and no database cannot change
  the list until it installs one. A per-route WAF now enforces malware and
  ransomware detection, the global paranoia level and the global enforcement
  mode where it used to drop them. The category switches on route WAFs take
  effect. See the upgrade note.
- The global WAF cannot narrow a category gateway-wide. That needs a proto
  field recording an explicit "off"; until then a route WAF is the way.
- The WAF's feed rule (1910001) is now redundant with the entrypoint check, which
  refuses a listed address before any WAF sees it. It is left in place; it costs
  one more lock-free lookup, and only on a WAF with that switch on.

## Alternatives considered

- **Honour the global category booleans.** Would switch detection off on every
  existing install. Rejected.
- **Treat "all nine false" as unset.** An operator who had switched one on --
  the card showed them all off -- would lose the other eight. Rejected.
- **Fail closed for a block list with no database.** An outage for every client
  of every country, for a list meant to refuse a few. Rejected; it fails open
  loudly instead, and the save that would create it is refused.
- **Enforce the feed in the reputation blocker.** That keys on the client's
  class and network, not its address; a feed lists addresses. The IP decision
  is where addresses are refused.
