# 20. The kernel filters IPv6 too

Date: 2026-09-26

## Status

Accepted. `net` and `sec`, with `mem` for the new map bounds: it changes what
reaches the management port and the stack on every dual-stack host.

## Context

Both eBPF programs matched `ETH_P_IP` and passed everything else. On a
dual-stack host that made IPv6 a way around all of it: no shun, no rate limit,
no SYN-burst guard — and no management gate, so with the kernel allowlist on,
an IPv6 stranger reached the management port that the dashboard said no
unlisted address could reach. `ShunIP` refused IPv6 addresses outright.

Two constraints shape any fix. The programs must load for a process holding
only CAP_BPF and CAP_NET_ADMIN (ADR 0018), whose verifier refuses a register
added to a packet pointer — so an IPv6 extension-header chain, whose lengths
are data, cannot be walked. And an IPv6 client is given a whole /64 and can send
from any address in it.

## Decision

- **Blocking and rate limiting are keyed by the /64.** Per address, an IPv6 shun
  or limit is evaded by changing the last 64 bits. Shunning one address shuns
  its /64; `UnshunIP` of any address in it lifts it.
- **The allowlist, port knocking, telemetry and the SYN-burst guard are per
  address.** Knocking opens the port for the address that knocked, not its
  /64.
- **The transport header is found where it can be read without a walk:** right
  after the fixed header, after one Fragment header, or after one minimum-size
  Hop-by-Hop header — the shape of an MLD report. Later fragments carry no port.
- **A header chain the parser does not walk fails closed, but only at the
  gate.** While the allowlist or knocking is on, such a packet from an unlisted
  source is dropped, because it might be addressed to the management port.
  With no gate on it is ordinary traffic. MLD and neighbour discovery always
  pass: without them IPv6 stops working on the link.
- **One switch, both families.** The allowlist gate turns on when at least one
  address of either family is installed, and a family with nothing listed is
  then closed. Per-family switches would reopen the bypass for whichever family
  the operator forgot.
- **Separate IPv6 maps**, bounded: the blocked-/64 set 16,384, adaptive limits
  10,240 and the allowlist 1,024, allocated per entry because user space fills
  them and they stay nearly empty; rate-limit state and telemetry 10,240, SYN
  tracking 16,384 and knock state 1,024, LRU. The IPv4 maps are unchanged.
- Phantom ports and load balancing stay IPv4-only.

## Consequences

- **Behaviour change on upgrade.** A kernel allowlist that lists only IPv4
  addresses now closes the management port to IPv6. An operator reaching the
  dashboard over IPv6 must list that address before upgrading.
- IPv6 traffic now pays the program's per-packet cost, as IPv4 always has.
- A packet with an extension-header chain the parser does not walk — a routing
  header, destination options, IPsec — cannot reach the host from an unlisted
  source while the management gate is on. Such chains are rare on the Internet,
  and the rule applies only while the operator has asked for the gate.
- Verified with BPF_PROG_TEST_RUN on both programs and with real frames on a
  veth pair, as root and as a user holding only CAP_BPF and CAP_NET_ADMIN. Every
  IPv6 test fails against the previous programs, and mutations of the MLD rule,
  the fail-closed rule, the fragment rule and the /64 key each fail the test
  that owns them.

## Alternatives considered

- **One map per purpose keyed by 16 bytes, with IPv4 mapped into IPv6.** Fewer
  maps, but it rekeys every IPv4 map and the Go code, tests and dashboard that
  read them, for no gain in what is enforced.
- **Walk extension headers with `bpf_xdp_load_bytes`.** Needs kernel 5.18 for
  XDP, and would still need a bound on the chain.
- **Fail open on an unwalked chain.** That is the IPv4-options bypass again, in
  IPv6.
