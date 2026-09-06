<!--
Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
SPDX-License-Identifier: MIT
-->

# WAF app profiles and where they apply

An app profile is a small set of **scoped exceptions** for a platform whose
ordinary content trips a detection. A WordPress comment really does contain
`<?php echo $name; ?>`. A Jira issue really does quote `1' OR '1'='1`. A paste
service exists to store exactly the strings a WAF is built to refuse.

They are benign because of **where they land**: a field that is stored and
displayed, never executed or queried. That is knowledge the deployment has and
the engine does not, which is why this is configuration rather than detection.

A profile is not a compatibility mode and does not turn rules off. Weakening the
underlying rules instead was measured and rejected upstream: demoting the PHP
open-tag signal removed the false positive and also dropped 32 real exploits,
taking RCE detection from 84% to 43%.

## Selecting one

```
app_profiles = wordpress,issue_tracker
```

or `GATEON_WAF_APP_PROFILES`. Names are forgiving — `WordPress`,
`issue-tracker`, `jira` and `gitlab` all resolve. Profiles compose: an install
running WordPress behind a Laravel API can enable both, because every exception
is scoped by path and a path belongs to one application.

Shipped profiles: `wordpress`, `drupal`, `laravel`, `issue_tracker`.

## Scoping one to your application — usually required

**A profile on its own may do nothing.** The exceptions gwaf ships are scoped to
the paths and field names of the product they were written against — for
`issue_tracker` that is `/rest/api/*` with the fields `description` and `body`,
which is Jira's shape. Its own documentation says the paths are examples meant to
be edited.

Nothing edited them. An operator running a paste service on `/pastes`, a support
desk on `/tickets` or a wiki anywhere else selected `issue_tracker`, saw it listed
in the dashboard, and got no change at all. This was measured rather than
assumed: tagging the developer-tool cases in the false-positive corpus with
`issue_tracker` changed no verdict.

So tell it where your content lives:

```
app_profiles              = issue_tracker
app_profile_scope_paths   = /pastes,/tickets/*,/api/v1/issues
app_profile_scope_fields  = content,body,subject
```

or `GATEON_WAF_APP_PROFILE_SCOPE_PATHS` and
`GATEON_WAF_APP_PROFILE_SCOPE_FIELDS`.

The profile keeps deciding **which rules** its class of application legitimately
trips — that is the security half, and it belongs upstream where the evidence
is. You supply **where** — the half only you can know. Every exception the
profile names is re-pointed at each of your paths and each of your fields; rule
ids and targets are never changed, and an exception the profile deliberately left
un-keyed passes through untouched.

Leaving both unset keeps each profile's shipped defaults exactly as they are, so
an install that has configured nothing behaves as before.

### Path syntax

A trailing `*` makes a prefix, so `/tickets/*` covers the subtree. That is the
only wildcard position gwaf supports: `*` anywhere else is matched literally and
would silently match nothing, so it is rejected rather than accepted.

### What is refused, and why

| Rejected | Reason |
| :-- | :-- |
| `/`, `/*`, `*` | Matches every request. An exception scoped to it is a global off-switch that reads like a narrow setting. |
| paths but no fields | Exempts *every* argument on those paths — broader than anything a shipped profile does. |
| fields but no paths | Exempts that field name on every route. `body` is a common field name. |
| `body*` | Field names are matched exactly; a wildcard reads as covering more than it does. |
| more than 64 paths or fields | The expansion is rules × paths × fields, capped at 2000 exceptions. Latency should not be how you find out. |

An invalid scope is **ignored, not applied loosely** — the failure mode of a bad
scope is an exception broader than intended — and logged once per engine build so
you are not left comparing a dashboard against unchanged behaviour.

## What a profile exempts

Two halves, and both matter:

- **gwaf's rules** — the semantic detections (XSS, SQLi, shell, PHP) *and* their
  Medium-tier counterparts. gwaf v0.6.2 added the second group; before it, a
  profile exempted `IDSQLiSemantic` while `IDSQLiSuspicious` still refused the
  same stored SQL, so the exception only half applied. A lower bar fires more
  readily on prose, which makes the Medium tier the *more* likely of the two to
  refuse a page on an application built to store attack text.
- **gateon's own rules** — currently the internal-target SSRF rule (1150003) and
  the advanced shell-injection rule (1151008) for `issue_tracker`. gwaf answers
  "is this field displayed rather than executed?" for the rules it ships and
  cannot answer it for the rules gateon adds, because it has never heard of
  them. Without this half, selecting a profile applied gwaf's exceptions while
  gateon's own rules kept refusing the same content.

Both halves are re-pointed by the same scope, so one set of paths and fields
configures the lot.

The bar for adding a gateon rule to that list is not "it produced a false
positive" — every rule does, on an application whose purpose is to store attack
text. It is "this field is genuinely displayed rather than acted on". An SSRF
finding is about a URL the *server* fetches; a paste service renders the string
and nothing dials it. A shell-injection finding is about a string reaching a
shell; in a displayed field it reaches a renderer.

## Measured effect

Scoping `issue_tracker` to a paste service's real routes closed **7 of the 12**
false positives the corpus records at paranoia 1, taking the measured rate from
**2.96% to 1.23%**. Two gwaf rule narrowings (v0.6.1) took it to **0.49%**.

At paranoia 2 the same scoping plus the two exemption halves above took it from
**4.94% to 1.98%**. See `internal/middleware/testdata/benign/` and
`make test-fp`.

The cases it does not close are recorded with reasons in that corpus. One is
worth repeating here because it is the mechanism's limit rather than a missing
rule: a **markdown file upload** still blocks at paranoia 2. The value arrives
keyed by the multipart part name with a filename attached, not as a text field
called `content` or `body`, and the scope re-points exceptions at named argument
fields. Closing it means deciding what a profile should say about uploaded file
*contents*, which is a broader question than scoping answered.

## What a profile will not do for you

Two false positives are deliberately left for you to scope rather than fixed by
default, because the default would be worse than the symptom:

- **A password field full of metacharacters.** Field names are attacker-chosen.
  Exempting `password` globally would let any payload through any endpoint by
  naming the parameter `password`, and some applications reflect submitted form
  values. Scope it to the routes that actually have a password box.
- **SVG uploads.** An SVG served back as `image/svg+xml` executes its script in
  your origin's context, so a global exemption trades a false positive for stored
  XSS. Scope it to the upload route, and serve user SVGs from a separate origin.
