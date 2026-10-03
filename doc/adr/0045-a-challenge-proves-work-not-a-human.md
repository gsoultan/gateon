# 45. A challenge proves work, not a human

Date: 2026-10-03

## Status

Accepted. `sec` co-signs with `ux`: each decision changes who reaches the origin
on a route that uses a challenge, and what the dashboard tells an operator the
challenge proves.

## Context

The 2026-10-02 truth review found the challenge middlewares (ADR 0030) did not
do what their labels said:

- **T9 -- the JavaScript challenge could not be solved on a route with a path
  rule.** The page fetched `/_gateon/seed` and posted to `/_gateon/challenge`.
  Routing runs before middleware, so those requests reached the challenge only
  on a route whose rule matched them -- a `Host()` route, say. On
  `PathPrefix(`/app`)` both were 404: the page never finished and every visitor
  was held on it.
- **T23 -- the challenge was passed by curl.** GET the seed, wait two seconds,
  POST it back: no JavaScript ran, no work was done. The "work" was the wait.
  And "Browser Integrity" let every client that did not claim to be a browser
  through; it was labelled "Verify request is from a legitimate browser".
- **T10 -- proof-of-work challenged nobody.** The setting reads "Serve challenge
  when IP threat score exceeds this (recommended 5)"; the middleware challenged
  when the *reputation* was below it. A reputation under 5 is refused by the
  reputation blocker first, and penalties step 100 -> 50 -> 0, so the challenge
  never fired. The tarpit, under the identical label, compared `100 -
  reputation`, as the label says.

Fixing T10 made two more defects live. A proof-of-work solution was honoured
only on the request that carried it, so the browser page -- solve, then reload
-- was challenged again on the reload, solved again, and reloaded again for as
long as the tab stayed open. And serving a challenge was recorded as a threat
(`pow_challenge_issued`, action "challenged"): on the built gateway one blocked
XSS plus the one challenge it caused correlated into a *critical* incident
(`signal_types=pow_challenge_issued,waf_blocked`), the responder took the
score to 0, and the reputation blocker refused the client on its next request
-- before it could solve the challenge it had just been handed.

## Decision

**What a challenge can honestly prove.** A pass proves that a client at this
address, with this User-Agent, did a fixed amount of computation -- by running
the page's script, or by reimplementing it -- within the pass lifetime. That
raises the cost of each automated identity and refuses every client that does
not do the work, which includes curl, API clients and most uptime monitors. It
does not prove a human: a headless browser passes, and so does a bot that
solves the puzzle natively, at a CPU cost per address and User-Agent. The
dashboard says exactly this beside the switch.

**The JavaScript challenge is a proof of work at the challenged URL.**

- The page carries a challenge ID: `<issued ms>.<HMAC>` over the client's
  address and User-Agent under the route's secret, in its own context
  (`gateon-bot-challenge-v3`). Holding it proves nothing -- it is in the page
  source.
- The script finds a nonce such that SHA-256(`id ":" nonce`) begins with 18
  zero bits (about 2^18 hashes; 0.1-0.4 s in a desktop browser), and sends it to
  the **same URL** with `X-Gateon-Challenge: answer` and the ID and nonce in
  headers, using the challenged request's method. The same URL reaches the
  same route by construction, whatever its rule -- that is the T9 fix. No
  `/_gateon/` path is used any more.
- The middleware answers that request itself, at its own place in the chain: 204
  with the pass cookie for a correct answer, 410 for a genuine ID past its
  five-minute lifetime (a tab left open, not recorded as an attack), 403 for
  anything else (forged, foreign, or short of the work, recorded as before).
  A second marked request, `X-Gateon-Challenge: check`, answers 204 only if the
  pass came back -- the cookie is HttpOnly, so the page has to ask.
- **Marked requests never reach the origin**, valid or not, with or without a
  pass. Every middleware before the challenge has already run on them, and the
  only thing they can earn is the pass, which skips only the challenge itself.
  So the marker is not a path past any other check on the route.
- The pass moved to context `gateon-bot-pass-v3`, so passes minted by the old
  wait-only flow stop verifying.
- SHA-256 is computed in script, not with `crypto.subtle`, which exists only in
  a secure context: on a plain-HTTP site the page could never have finished.

**Bounded by construction.** No store backs a challenge or a pass. A replayed
answer yields another pass for the same address and User-Agent, which that
client already holds, so a single-use list would bound nothing an attacker
wants; the five-minute lifetime bounds the replay instead. The work is a
constant, not a tunable: it is the price of one pass, and the pass lifetime is
what an operator adjusts.

**The page is usable without sight and without script.** `lang`, one heading,
a `role="status"` line the script writes progress and failures to, a
`<noscript>` explanation, and a Try again button that starts hidden. A failed
check never reloads by itself -- it says what happened (expired, refused, no
cookie, connection lost) and waits. A sessionStorage timestamp per URL (not a
credential) stops the one loop a page cannot otherwise see: work that was
accepted and a reload that is challenged anyway. The page reflects nothing the
client wrote, is `no-store`, and runs under a CSP that admits only its own
nonce'd script and same-origin fetches.

**"Browser Integrity" is a header consistency check and is labelled so.** It
refuses a request with no User-Agent, and one whose User-Agent claims Chrome,
Edge, Firefox or Safari (by the product token as those browsers write it) but
that carries none of the `Sec-Fetch-*` headers they send. Firefox is now among
the claims checked; it has sent fetch metadata since version 90. A client that
claims nothing is not judged -- refusing those is the JavaScript challenge's
job. Dashboard label: "Browser Header Check".

**Proof-of-work challenges when the threat score exceeds the threshold.** Threat
score is `100 - reputation`, the tarpit's scale; strictly greater, so a
threshold left at 0 challenges every client with any penalty rather than every
client. A route-level `pow` middleware's `threshold` (default 20) has the same
meaning.

**A solved proof of work earns a ten-minute pass** (`gateon_pow_pass`, bound to
address and User-Agent under the route's key, context `gateon-pow-pass-v1`),
so the browser's reload gets through. API clients may still present the
solution headers on each request. The browser fallback is the same accessible
page as the JavaScript challenge.

**Serving a challenge is not evidence.** It is the gateway's own action; the
signal that lowered the score is already on record. Proof-of-work no longer
files a threat when it challenges; it counts `pow_challenge_served` and
`pow_challenge_solved` on `gateon_middleware_bot_management_total` (two fixed
label values). A *wrong* solution is still a threat: that one the client sent.

The global "Bot Management" settings are labelled as what they are: defaults
for routes that attach a Bot Management middleware. They were never applied to
routes without one.

## Consequences

- A route with the JavaScript challenge refuses every client that does not run
  JavaScript -- as it was always described as doing. Operators who relied on
  curl or a monitor passing must exempt it (a separate route without the
  middleware) or use the allowlist.
- Every pass issued before the upgrade is re-challenged once.
- Proof-of-work starts challenging clients the day this ships. At the
  recommended 5, one penalty is enough.
- Firefox without fetch metadata (pre-90, or a script claiming Firefox) is
  refused by the header check.
- The tarpit's direction is pinned by a test, so the two settings sharing a
  label cannot drift apart again.

## Related

- ADR 0030, which made the challenges their own package.
- ADR 0024, the reputation identity the threshold reads.
- ADR 0043, the rule this applies: a setting does what it says.
