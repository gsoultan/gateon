<!--
Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
SPDX-License-Identifier: MIT
-->

# Turning the WAF on without breaking your application

A WAF that blocks a real user is a worse outage than the attack it stopped,
because it is indistinguishable from the site being down and it happens to the
customers who were already trying to give you money. This is the procedure for
finding out what enforcement would cost you **before** it costs you.

The short version: run it in audit-only mode, read one counter, fix what it
tells you, then enforce.

## Why not just enable it

Two failure modes, and the second is the one that gets skipped.

**Enforcing blind.** You turn the WAF on, it blocks something legitimate, and
you find out from a support ticket. The blast radius is however long it takes
someone to connect "checkout is broken" to "we changed the gateway".

**Leaving detection on forever.** This is the more common outcome. Audit-only
feels safe, so it stays on — and a WAF that never blocks is a log with running
costs. Deployments end up here because until the would-block counter existed
there was no way to answer "what would happen if I flipped this?", so nobody
ever felt ready to flip it.

The procedure below exists to make that question answerable in a week.

## Before you start

- Gateon has a WAF middleware attached to the routes you care about.
- `/metrics` is reachable, or you can see **Security Hub → Overview** in the
  dashboard.
- You know what "normal" looks like for these routes — roughly how much traffic,
  and when the quiet and busy periods are. Step 2 depends on it.

## Step 1 — Enable audit-only

Set `audit_only` to `true` on the WAF middleware. The stored shape is:

```json
{
  "id": "waf-main",
  "type": "waf",
  "config": {
    "audit_only": "true",
    "anomaly_threshold": "5"
  }
}
```

**Make the change through the dashboard or the API** (`PUT /v1/middlewares`),
not by editing the file. Both end up writing the same JSON, but only the API
path invalidates the affected route chains, so a dashboard change takes effect
on the next request while a hand-edited file does nothing until the process
restarts. There is no config file watcher — this matters most in step 7, where
the difference is whether your rollback works.

> **If you script the API call, send the whole middleware.** `PUT
> /v1/middlewares` replaces the stored object rather than merging into it, so a
> request whose `config` contains only `audit_only` silently drops
> `anomaly_threshold` and every other key you had tuned — with a `200` and no
> warning. Read the current object, change the one field, send it back. The
> dashboard already does this; only hand-rolled calls are exposed.

In audit-only the WAF runs every rule, scores every request, records what it
found — and then lets the request through. Latency cost is the same as
enforcing; only the decision changes.

Confirm it is actually running by watching the counter appear:

```bash
curl -s localhost:<port>/metrics | grep gateon_middleware_waf_would_block_total
```

If nothing appears after real traffic has flowed, the WAF is not on the route
you think it is. Fix that before continuing — an empty counter reads exactly
like "no false positives", and those are the two conclusions you must not
confuse.

## Step 2 — Let it run through a full traffic cycle

**At least seven days**, and it must include:

- a full weekly cycle — weekend traffic is a different shape from weekday
- any scheduled batch job, export, or partner integration that runs monthly
- at least one deploy of the application behind the gateway

Seven days is not a ritual. The false positives that matter are the rare ones:
the customer whose name contains an apostrophe, the one report that posts a
1 MB JSON body, the integration that authenticates once a month. A 24-hour
sample tells you about your median request and nothing about the tail, and the
tail is what pages you at 3am.

Resist tuning during this window. You are collecting a baseline; changing the
rules mid-collection means you have two half-samples of two different
configurations.

## Step 3 — Read what it would have cost

**Dashboard:** Security Hub → Overview (`/security-center`) shows a panel headed *"Detection only:
these requests would be blocked if you enforced"*, with the total and the top
ten rules by count.

**Prometheus:**

```promql
# Total requests that would have been refused, by rule
sum by (rule_id) (gateon_middleware_waf_would_block_total)

# As a fraction of all traffic — the number that decides whether you proceed
sum(rate(gateon_middleware_waf_would_block_total[1h]))
  / sum(rate(gateon_requests_total[1h]))
```

The counter is labelled `route`, `rule_id` and `phase`, so you can ask which
route and which rule, not just how many.

**How to read the fraction:**

| Would-block rate | What it means | What to do |
| :--- | :--- | :--- |
| **0%** | Either clean, or the WAF is not on this route | Verify the counter exists at all before believing it |
| **under ~0.1%** | Plausibly all attacks | Go to step 5, triage the handful by hand |
| **0.1%–2%** | Almost certainly false positives mixed in | Step 4. Do not enforce yet |
| **over 2%** | Something legitimate is matching a rule | Step 4. Enforcing here breaks your application |

These bands are judgement, not measurement — a site under active attack can
legitimately sit above 2%. They tell you how much triage to do, not whether you
are safe.

## Step 4 — Triage: attack or false positive?

For each `rule_id` in the top ten, ask **which requests matched it**. Security Hub →
Threat Explorer shows the requests; the rule id tells you what fired.

A would-block is a **false positive** if it has any of these shapes:

- it fires on a path only your own application calls
- it fires steadily, in proportion to traffic — attacks are bursty, features are
  not
- it fires on a request that succeeded and returned real data
- the payload is obviously your own: a rich-text field, a serialised form, a
  base64 upload, a customer name with an apostrophe

It is a **real detection** if:

- it arrives from addresses with no other legitimate traffic
- it is bursty, or arrives in a scan-shaped sequence across many paths
- the payload is recognisably an attack string rather than your data

For reference, against Gateon's benign corpus — 405 samples of ordinary
application traffic — the shipped ruleset refuses **0.49% at paranoia level 1**
and **1.23% at PL2**, and the request-chain harness passes 408 legitimate
requests through the full middleware chain with **0 refused**. Those are
synthetic corpora, not your application: they say the ruleset is not
gratuitously noisy, not that it is quiet on your traffic. Your measurement in
step 3 is the one that counts.

## Step 5 — Tune, narrowest change first

In order of preference. Prefer the change that removes the least protection.

1. **Fix the application.** If a rule fires because a field accepts unescaped
   HTML, the rule found something. This is the only option that makes you safer.
2. **Scope an app profile.** If you run a known application — a wiki, a paste
   site, a CMS — a profile carries the exceptions that application needs, scoped
   to its paths. See [waf-app-profiles.md](./waf-app-profiles.md). **Scope it to
   the paths that need it**; an unscoped profile exempts your whole site.
3. **Lower the paranoia level.** PL2 refuses roughly two and a half times what
   PL1 does on the same benign traffic. Going from 2 to 1 is a broad reduction —
   defensible as a starting position, not as a fix for one noisy rule.
4. **Raise `anomaly_threshold`.** Requires more evidence before refusing.
   Affects every rule at once; it is the bluntest instrument here.

After any rule or profile change, re-run the false-positive gate:

```bash
make test-fp
```

It is a ratchet in both directions: it fails if a change adds a false positive,
**and** if a recorded one starts passing without the record being updated.

Then reset the counter (restart, or note the current value) and observe again.
Tuning without re-measuring is guessing.

## Step 6 — Enforce

When the would-block traffic is attacks and only attacks, set
`audit_only` to `false` — again through the dashboard or `PUT /v1/middlewares`,
so it applies without a restart.

Do it at a **low-traffic hour on a day you are working**. Not Friday. The point
is not that something will go wrong — it is that if something does, you want the
smallest number of affected users and the largest number of awake colleagues.

Enforce **one route at a time** if you have more than a couple. A single bad
rule then breaks one thing instead of everything, and you learn which route it
was without bisecting.

## Step 7 — Watch, and know your rollback

For the first hour, and then daily for a week:

```promql
# What is now actually being refused
sum by (rule_id) (rate(gateon_middleware_waf_blocked_total[5m]))
```

Compare against the would-block figures from step 3. **They should match.** If
enforcement is blocking substantially more than audit-only predicted, something
changed between measuring and enforcing — a deploy, a new integration, a
different traffic mix — and the measurement no longer describes reality. Go back
to audit-only and re-measure.

**Rollback is one setting:** put `audit_only` back to `true` in the dashboard.
It takes effect on the next request and leaves the detection data intact — the
WAF keeps running and keeps scoring, it just stops refusing.

Do it in the dashboard, not the file. A hand-edited `middlewares.json` will not
be picked up until the process restarts, and discovering that during an incident
— change made, nothing happens, no error anywhere — is how a two-second rollback
becomes twenty minutes of doubting the change you correctly made. Reach for it
without ceremony — going back to measuring is not a defeat, and an operator
who feels they cannot roll back will instead leave a broken WAF enforcing while
they debug.

## What this procedure will not tell you

Stated plainly, because a measurement quoted past its limits is worse than none.

- **Nothing about traffic you did not receive.** A quarterly integration that
  did not run during your window is untested. Extend the window or expect it.
- **Nothing about request bodies you did not send.** The corpus figures above
  are dominated by GET traffic. If your application is POST-heavy, the body
  inspection path is where your false positives will be, and only your own
  measurement covers it.
- **Nothing about response-phase rules** unless you run the enterprise tier,
  where DLP and response inspection are enabled. Those inspect what your
  application *returns*, and a false positive there is a leaked-data alert on
  ordinary output.
- **Nothing that survives an application change.** A deploy that adds a rich
  text field or a file upload can invalidate this entire measurement. Re-run
  steps 2 and 3 after a significant change to what your application accepts.

## Reference

| | |
| :--- | :--- |
| Config key | `audit_only` on the WAF middleware (`"true"` / `"false"`) |
| Applying a change | Dashboard or `PUT /v1/middlewares` — a hand-edited file needs a restart |
| Would-block metric | `gateon_middleware_waf_would_block_total{route,rule_id,phase}` |
| Enforced-block metric | `gateon_middleware_waf_blocked_total` |
| Dashboard | Security Hub → Overview (`/security-center`) |
| Tuning exceptions | [waf-app-profiles.md](./waf-app-profiles.md) |
| False-positive gate | `make test-fp` |
| Host sizing | [deployment-sizing.md](./deployment-sizing.md) |
