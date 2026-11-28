# 108. A crawler is who its vendor says it is

Date: 2026-11-28

## Status

Accepted. `sec` drives. `arch` challenges where the lists live and who may
change them, `net` challenges the fetch, `mem` challenges what is held, and
`ux` challenges what the route editor promises.

## Context

AI crawlers and agents name themselves in the User-Agent: `GPTBot`,
`ClaudeBot`, `PerplexityBot`, `ChatGPT-User`. Operators want to treat them
differently from scrapers: let a search crawler in, keep a training crawler
out, or let an assistant fetch the page a person asked about. Bot management
could not tell them apart. The JavaScript challenge refuses a real crawler,
which runs no script, and a rule that waves the token through admits every
scraper that copies it, which is the reason scrapers copy it.

A User-Agent is the client's own word. What the vendors do publish is the
addresses their crawlers come from, as JSON lists at stable URLs (OpenAI's
`gptbot.json`, Perplexity's `perplexitybot.json`), the same shape Google uses
for Googlebot. The gateway already fetches address lists safely: the IP
reputation feeds (ADR 0061).

## Decision

**The operator lists the URLs; the gateway fetches them; each route decides.**

- `waf.bot_management.ai_agent_ranges` is a list of `{agent, url}`. `agent` is
  a token from the gateway's catalog (`internal/security/aiagent`), checked at
  save, so a typo is refused rather than stored and never read. The URL is
  held to the feeds' rule, https or loopback http, at save and at every
  redirect (`reputation.CheckFeedURL`). The field is administrator-only
  (`Boundary`): it decides which clients pass a route's challenge as a
  crawler, which is whom the gateway trusts.
- One goroutine, started by the security supervisor with the gateway's
  context, fetches every list when the configuration changes and every 12
  hours. A fetch has 30 seconds, a body is at most 1 MiB, and anything but a
  2xx is an error. A list that fails, or comes back empty, keeps its last good
  copy: an outage at the vendor must not make its real crawler a fake.
- A prefix wider than /16 (IPv4) or /32 (IPv6) is left out and logged. A fleet
  is a few hundred addresses; a list naming a /8 is wrong or hostile, and in
  force it would let a whole network pass as the agent.
- The lists in force hold at most `AIAgentMaxPrefixes` prefixes in all
  (`minimal` 4096, `standard` 16384, `enterprise` 65536, 32 bytes each;
  `GATEON_AI_AGENT_MAX_PREFIXES` overrides it). A list that would pass the
  bound is refused whole, never cut: half of a fleet's addresses would refuse
  the other half.
- An agent is judged only when every list configured for it has something in
  force. Otherwise its claim is **unverifiable**, and the client meets the
  route's other checks exactly as it did before this ADR.

**The route's `ai_agents` key** on bot management, strictly parsed:

| Value | A client that names an AI agent |
|---|---|
| `off` or absent | is treated like any other client (unchanged) |
| `verify` | from a published address passes bot management, past the challenge it cannot run; from any other address is refused and recorded as a `bot_detected` threat; unverifiable meets the other checks |
| `refuse` | is refused, real or not, and counted as `ai_agent_refused` |

A route that sets only `ai_agents` is a bot-management route, as one that sets
only a check is (the dashboard never writes `enabled`).

The policy runs first in bot management, before the browser check and the
challenge, because those are what a real crawler fails. It decides only bot
management: the WAF, rate limits and every other middleware still see a
verified crawler. A refusal is the uniform one (ADR 0106).

A request that names no agent pays a dozen substring searches of its
User-Agent, with no allocation; verification is a lock-free read of an
immutable index.

## Consequences

- An operator can let a crawler in without letting in everything that claims
  to be it, and can see the fakes in the Security Hub.
- An agent whose vendor publishes no list cannot be verified. Its claim stays
  unverifiable, never verified, so nothing is admitted on the token alone.
- The catalog is in code. A new agent is a code change; until then a list for
  it is refused at save.
- The lists are fetched only by a gateway with some configured; an install
  without them makes no request.
