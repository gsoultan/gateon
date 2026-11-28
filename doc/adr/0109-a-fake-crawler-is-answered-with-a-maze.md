# 109. A fake crawler can be answered with a maze

Date: 2026-11-28

## Status

Accepted. `sec` drives. `mem` and `perf` challenge what a maze page costs,
and `ux` challenges what the route editor says it does.

## Context

ADR 0108 tells a real AI crawler from a client that only names one. On a
verifying route the fake gets the uniform refusal (ADR 0106). A refusal is an
answer the scraper can act on: it now knows the token was checked, changes its
User-Agent to a browser's, and comes back under a name nothing verifies.

## Decision

A route's `ai_agents` may be `maze`. It verifies exactly as `verify` does; the
only difference is what a fake gets: a **maze page**, `200`, instead of a
refusal.

- A maze page is a short article of neutral filler and six links, each to
  another maze page under `/notes/<hex>`. A scraper that follows links stays
  in the maze, because every request it makes under the agent's name from
  that address is answered with one, whatever the path.
- It is drawn from a fixed word list by an HMAC of the path under the route's
  bot-management secret. The same path always gives the same page, so the
  gateway keeps no state and a scraper that compares visits learns nothing;
  without the secret the maze cannot be predicted.
- Nothing in it comes from the request, the origin or the site. A scraper
  writes the path; the path only seeds the HMAC, and the page holds only
  words from the list and hex. Nothing can be reflected, and nothing of the
  site's can leak into what the scraper keeps.
- It says `noindex, nofollow, noarchive` in a meta tag and in `X-Robots-Tag`,
  `Cache-Control: no-store`, and each link is `rel="nofollow"`. A crawler that
  honours them, which is what the real one is, never walks it, and the real
  one is not sent there anyway.
- One page is under 4 KiB and about 14 µs to build. It is built only for a
  request already judged a fake, and costs no lock, no state and no I/O.
- Every maze answer is recorded as the refusal would have been, with
  "served a maze page" in its details.

A person who finds a leaked maze link reaches the origin, which has no such
path, and gets its 404.

## Consequences

- A scraper that lies about being a crawler spends its requests on pages that
  hold nothing, and keeps believing it is getting through.
- A maze answer is a `200`. Monitoring that reads only status codes sees it as
  served; the Security Hub and `gateon_middleware_bot_management_total`
  (`blocked`) see it as refused.
