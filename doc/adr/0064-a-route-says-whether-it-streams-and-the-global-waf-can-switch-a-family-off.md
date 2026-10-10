# 64. A route says whether it streams, and the global WAF can switch a family off

Date: 2026-10-05

## Status

Accepted. `api` drives (three contract changes); `net` co-signs decision 1,
`data` co-signs decisions 1 and 3 (a new column, and what a stored config
means), `sec` co-signs decision 3.

## Context

Three contract gaps were left open by the second production-readiness review
and by ADR 0063:

- **DP-N7 (the half ADR 0062 did not close).** A response is lifted off the
  entrypoint's read and write timeouts -- and bounded instead by the stream
  idle timeout and maximum lifetime (ADR 0042) -- only when the backend
  answers a 200 `text/event-stream` with no `Content-Length`. A backend that
  streams NDJSON, long-polls or sends chunked progress was cut at the write
  deadline, and an operator could not stop a route's event stream from
  outliving its timeouts. The decision was the backend's alone.
- **TriggerWafUpdate.** The RPC and `POST /v1/waf/update` called
  `WAFUpdater.PerformUpdate`, which has returned `ErrRuleUpdatesRetired` since
  gwaf replaced the downloaded rule set (ADR 0004). Every call failed. ADR
  0063 removed the dashboard button; the RPC, the route and their permission
  entry remained.
- **The global WAF's category switches.** `WafConfig.sqli`, `xss`, `lfi`,
  `rce`, `php`, `scanner`, `protocol`, `java`, `nodejs`,
  `ransomware_detection` and `use_crs` were read by nothing: the gateway-wide
  WAF runs every family (ADR 0044). ADR 0044 explained why they could not
  simply be honoured -- a proto3 `bool` has no presence -- and that making
  them mean something needs a field that records an explicit "off".

## Decision

### 1. `Route.stream_mode`: auto, always, never

`Route` gains `StreamMode stream_mode = 11`, an enum nested in `Route`:

| Value | Which responses are streams |
| :--- | :--- |
| `STREAM_MODE_AUTO` (0, default) | A 200 `text/event-stream` with no `Content-Length` -- the rule every route had before. |
| `STREAM_MODE_ALWAYS` (1) | Every response, once its status is written. |
| `STREAM_MODE_NEVER` (2) | None; an event stream keeps the entrypoint's timeouts. |

The decision stays where ADR 0042 put it, in `deadline.StreamWriter`, which
the listener wraps around every request before routing. The entrypoint
middleware (`middleware.EntryPoint`, chain position 0 on every listener) finds
it once -- `request.FindStreamControl`, walking `Unwrap` -- and keeps it on the
request state. A route whose mode is not auto gets one middleware at the head
of its chain that sets the mode on it before anything can begin the response;
an auto route's chain is unchanged, so it costs nothing. A mode set after the
response began changes nothing. The writer is pooled; `Release` clears the
mode with everything else.

`always` never means "no timeout":

- The backend must still answer within the entrypoint's write timeout: the
  lift happens when the status is written, not when the request arrives, so a
  client still cannot hold a connection by asking (ADR 0042).
- The lifted response is bounded by the stream idle timeout and maximum
  lifetime, as an event stream is.
- With both stream bounds disabled (`GATEON_STREAM_IDLE_TIMEOUT=0` and
  `GATEON_STREAM_MAX_LIFETIME=0`) a lifted response would have no deadline at
  all, so a route that always streams keeps the entrypoint's deadlines instead,
  and the router warns each time it builds such a route. `auto` keeps today's
  behaviour in that configuration: the operator disabled the bounds for event
  streams on purpose.

Routes are stored in SQL columns, so migration 70 adds `routes.stream_mode
INTEGER NOT NULL DEFAULT 0` on SQLite and Postgres; every existing row is
auto. A value outside the enum is refused at save (400 over REST,
InvalidArgument over Connect/gRPC); the router reads one that is stored anyway
as auto. The route editor offers the three modes, with copy that says what
each does to the timeouts, for HTTP-family routes only.

No new tunable: the bounds are the existing stream bounds and their tier
defaults.

### 2. TriggerWafUpdate is removed

The RPC, `TriggerWafUpdateRequest`, `TriggerWafUpdateResponse`, `POST
/v1/waf/update`, the service method, its `apiPermissions` entry and
`WAFUpdater.PerformUpdate` are deleted. A proto service cannot reserve a method
name and a deleted message has no tag of its own, so `api.proto` and
`diagnostics.proto` carry a comment naming the retired names. `WAFUpdater`
stays: the posture report reads `LastUpdated`. A call now gets 404 from the
management mux, and 404 (unknown procedure) from Connect.

### 3. `WafConfig.categories`: a tri-state per family, under a new tag

The old booleans are removed and reserved (tags 2, 5-12, 14, 20 and their
names). `WafConfig` gains `WafCategories categories = 44`, a message of
`optional bool` fields: `sqli`, `xss`, `lfi`, `rce`, `php`, `java`, `nodejs`,
`scanner`, `protocol`, `ransomware_detection`.

**Why a new tag, not `optional` on the old ones.** `optional` on an existing
field is wire-compatible, and that is the trap: every encoding that ever wrote
the old fields can have written `false` for a switch nobody touched.
`global.yaml` is written by yaml.v3 from the generated struct, which has no
yaml tags, so it writes every field, `sqli: false` included. `GET
/v1/global` marshals with `EmitUnpopulated`, so any client that read the
config and wrote it back -- the dashboard, a script, a backup restored -- sent
`"sqli": false`. Read as presence, each of those would switch a family off on
upgrade. Under a new tag nothing written before this ADR can be read as a
switch at all: `encoding/json`, yaml.v3 and the API's protojson
(`DiscardUnknown`) all ignore the retired names. A v1.1.0 `global.json` or
`global.yaml` naming them loads and runs every family; a test asserts both.

**What each value means.** Unset runs the family as the WAF tier decides
(every family at standard and enterprise; minimal drops LFI, RCE, PHP, Java,
Node.js, scanner and ransomware). `true` runs it even where the tier would
not. `false` removes it. The switch is applied after the tier, in
`applyGlobalCategories`, by setting the same `WAFConfig` fields a route WAF's
keys set, so the family-to-rule mapping is the route WAF's
(`categorySwitches`, and `policy.go`'s rule that a family switch removes only
rules filed under its family -- ADR 0063 decision 4): switching RCE off
removes RCE (and lets PHP, Java and Node.js code injection through, as on a
route), and never the web-shell malware rule. Malware detection is not a
switch on the global WAF; it stays forced on. WordPress stays the opt-in
`wordpress` bool it was. `use_crs` selected nothing and is gone without a
replacement: every family off is the closest thing to "no CRS", and it is
expressible.

**Merge with a route WAF.** Unchanged in shape from ADR 0044: a route WAF
starts from the config the global WAF is built from. A switch the route sets
(`"sqli": "true"` or `"false"`) wins; one it leaves unset or empty inherits the
global WAF's value, off included. So a global off narrows every route WAF
that did not decide that family for itself, and a route can turn the family
back on for itself alone.

**What reports it.** `GET /v1/waf/effective` reads the engine's config, so it
shows a switched-off family off with no change of its own. The posture treats
a gateway-wide WAF that runs no attack family as a route WAF with every
category off (ADR 0063 decision 5): `no_categories`, counted under
`categoriesOff`, no WAF credit. The server resolves that from the engine's
own reading (`EffectiveGlobal`), so a minimal-tier WAF with SQLi, XSS and
protocol switched off -- which runs nothing although six switches are unset --
is caught; the proto-only fallback (`GlobalWAFMode`) counts explicit offs. A
partly switched-off global WAF keeps its credit, as a route WAF with one
family on does, and the control's detail names the families switched off.
The advisory counts the global `no_categories` like a route's. The dashboard's
global WAF card offers a switch per family beside a Running / Not running badge
from `/v1/waf/effective`, so a family the tier drops is not shown as running
because its switch is on; the copy says what off removes and that route WAFs'
own switches win.

The switches are `Operational` in the global-config bound (an operator may
change them, as they could change the old ones and `audit_only`). The dead-field
baseline loses all eleven old fields; the global effect registry gains a row
per family -- unset against explicit off, on a probe of that family, through
the route chain the router builds -- except `protocol`, which is baselined
because `httptest.NewRequest` cannot build a protocol violation.

## Consequences

- No behaviour changes on upgrade: every route is auto, every stored global
  config has no switch set. The first change is the operator's.
- A route set to `always` holds a connection, a goroutine and a backend
  connection for up to the stream lifetime per response once the backend has
  answered; `never` cuts an event stream at the write timeout. Both are the
  operator's choice per route, and the dashboard says so.
- The global WAF can now be narrowed gateway-wide, which is also a new way to
  weaken it. Only an explicit `false` does it; the card warns when any family
  is off, the posture names them, and a WAF with every family off earns no
  credit and an advisory finding.
- Clients that wrote the old category booleans or `use_crs` are not refused;
  what they send is ignored, as it always effectively was.
- A client still calling `TriggerWafUpdate` gets 404 instead of a failure
  message.

## Alternatives considered

- **`optional` on the old tags.** Wire-compatible, and wrong: see above. The
  stored `false` values are indistinguishable from offs.
- **A `disabled_categories` list (ADR 0044's suggestion).** No tri-state: it
  cannot say "run this family even at the minimal tier", and a list of strings
  admits typos the proto cannot catch.
- **An enum per family.** Equivalent on the wire; `optional bool` reads
  naturally in the dashboard (absent / true / false) and needs no new enum.
- **Decide the stream at the route instead of at the listener.** The listener
  owns the deadlines and already decides at the first status; moving the
  decision would duplicate it on every listener path (TCP, smart-TCP,
  HTTP/3, management).
- **Find the StreamWriter from the route by unwrapping the writer.** Several
  writers between the listener and the route (the status recorder among them)
  do not unwrap; the entrypoint middleware sees the writer before any of them.
- **Keep TriggerWafUpdate answering "retired".** A control that can only fail
  is not offered (ADR 0063).
