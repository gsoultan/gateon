# 25. A finding limits an address only for harmful traffic, and only when it repeats

Date: 2026-09-27

## Status

Accepted. `sec` and `arch`, with `mem` for the new bounds: it moves the line
between what the analysis observes and what the kernel enforces.

## Context

The analysis loop turned two detectors' findings straight into kernel rate
limits: any Neural Sentinel or Graph Intelligence finding scoring above 80 held
its addresses to 100 packets a second, on the pass it appeared, with no history,
and (until e44e8c6) no allowlist and no release. Neither detector worked. The
Neural Sentinel's isolation forest never scored anything; Graph Intelligence
called five visitors on one Chrome build a botnet, because a JA4+ value names a
browser class, not a client (`mem:reputation_identity`), and its graph never
forgot. The limits were listed nowhere.

The owner chose to fix both rather than remove them, with false positives the
priority. The populations that must never be limited were named: people
browsing, a dashboard polling every five seconds, a CI runner, an office's
egress carrying many users. Scanners and credential stuffing must be.

Calibrating the forest on those populations (300 runs each) showed what no
threshold alone can fix: a CI runner, an office egress and a tab polling into
401s after its session expired are isolated as readily as a credential stuffer.
They are unusual. They are not harmful.

## Decision

- **Harm is required, not just unusualness.** A finding that can end in a
  kernel limit needs harm evidence of each address it names
  (`IPStats.harmEvidence`): a scan (10 or more failed requests over 10 or more
  paths, at least half its requests), credential guessing (10 or more POSTs
  refused 401/403, at least 30% of its requests and half its POSTs), or attacks
  the request path itself caught (weight 3 or more of WAF blocks, traps,
  malware, brute-force or exploit-scan detections, at least 20% of its
  requests). Every rule has a count and a share of the address's own traffic,
  because a limit applies to the whole address; the shares are over the
  requests it really sent, correcting for trace sampling.
- **The Neural Sentinel's bar is absolute.** It reports a harmful client whose
  standard isolation score is at least 0.75 − 0.10 × Sensitivity (0.70 at the
  default); Sensitivity 0 turns it off. The library's labels, which mark a fixed
  share of any population, are not used.
- **Graph Intelligence clusters evidence, not browsers.** Only addresses with
  attack evidence in the last 30 minutes are linked to the class they
  presented; a link fades with a 10-minute half-life once unrenewed and is gone
  after 30 minutes; a class is a campaign when five or more such addresses are
  at least half of the addresses that presented it. The store is capped at 256
  classes of 128 addresses. Peers gossip the links they would count themselves.
- **One path from a finding to a limit: the RL limiter.** One observation per
  address per analysis pass; no limit before the third consecutive pass; the
  limit is set again on each pass that finds it, renewing its five-minute lease,
  and decays and lapses when the findings stop. The mitigation allowlist is
  never limited, and an operator's release clears the history as well as the
  limit. The analysis loop holds the limiter directly; the eBPF manager no
  longer relays scores to it.
- **Every kernel limit is listed.** Each carries its rate, the reason its writer
  gave and when it lapses, on the IP mitigation list, and is released there.

## Consequences

- Identical clients mask each other in an isolation forest: three identical
  scanners among forty browsers score 0.47. The Neural Sentinel finds lone
  outliers; a coordinated group is Graph Intelligence's, which reports it only
  when its addresses carry attack evidence and dominate their client class. A
  campaign run from a common browser build, among that build's ordinary users,
  is not reported as a campaign; each address remains subject to what the
  request path decides about it.
- An address carrying many users is not limited for one user's attacks.
- The request-header consistency check and the forest's header-entropy feature
  are removed rather than fed full trace reads (see
  `TestAnalysisReadsTraceSummariesOnly`).
- A new detector whose findings should limit addresses is added to
  `throttlingFindingTypes` and must meet the harm rule for every address it
  names.
