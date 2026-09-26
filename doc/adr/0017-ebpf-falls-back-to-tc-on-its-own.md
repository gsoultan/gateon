# 17. eBPF falls back to the TC hook on its own, and the TC hook enforces what it claims

Date: 2026-09-26

## Status

Accepted. `net`, with `sec` co-signing: the fallback changes where packets are
dropped on every install that could not attach XDP, and the TC hook gains the
management-port check it was already advertised as having. Supersedes the TC
parts of [0007](./0007-xdp-attach-mode-and-the-tc-ingress-hook.md); its
refusal of silent generic XDP stands, and is tightened here.

## Context

ADR 0007 made a failed native XDP attach refuse rather than degrade to generic
mode, and added the TC ingress hook for NICs that cannot offer native XDP —
behind `tc_filtering`. Verification on real EC2 hardware (the `ena-verify`
workflow, 2026-09-02 and 2026-09-26) and the root test suite found four things
that kept it from working where it mattered:

1. **The fallback needed a setting nobody had a reason to set.** With an XDP
   feature on and `tc_filtering` off — the default — a refused native attach
   left nothing attached. EC2 refuses native XDP at its defaults (MTU 9001, every
   queue in use), so turning eBPF on there did nothing. The README already
   described the fallback as automatic.
2. **The interface defaulted to `eth0`**, a name no current EC2 host has.
3. **The TC hook did not enforce the management allowlist.** Its branch let
   listed sources through early and had no arm that dropped anyone, because the
   program never read a port. On TC, `enable_mgmt_whitelist` admitted every
   address while the dashboard said an unlisted one could not reach the
   management port at all.
4. **A NIC without native XDP ran generic XDP reported as native.** The attach
   passed no mode flag, and with none the kernel picks SKB mode for any driver
   without `ndo_bpf` (`dev_xdp_mode`). ENA was never affected — it implements
   native XDP and refuses the attach outright — but e1000, r8169, bridges and
   dummy devices ran exactly the mode 0007 exists to refuse, under the label
   "native".

The same code located the TCP header a fixed 20 bytes past the IPv4 header, so
one IP option, or a first fragment carrying only 8 bytes of TCP, moved every
port-based check off the real header and past the management-port gate.

## Decision

- **TC is the automatic fallback.** `Start` attaches the TC hook when XDP was
  wanted and did not attach (`tryTC`). `tc_filtering` keeps one meaning: attach
  at TC when no XDP feature is on. XDP and TC remain alternatives, never both.
- **Native means native.** The XDP attach asks for driver mode by name
  (`XDP_FLAGS_DRV_MODE`), so `allow_generic_xdp` stays the only way to generic
  mode.
- **The interface is the configured one, else the one carrying the IPv4 default
  route, else `eth0`** (`targetInterface`), resolved once per `Start`. The
  dashboard recommends that same interface.
- **The TC hook reads the transport header's destination port** — that and
  nothing more — to enforce the management allowlist as XDP does. It still does
  no port knocking, phantom ports or load balancing, and `tcUnsupported` names
  whichever of those is configured when it attaches.
- **Both programs find the transport header by IHL**, read it only from a first
  fragment, and require only the bytes a check reads (`l4_header`).

## Consequences

- **Behaviour change on upgrade** (see `doc/upgrading.md`). An install with eBPF
  on and an XDP feature on, on a NIC without native XDP, now attaches at TC and
  starts filtering there — shunned addresses, the rate limiter if on, the
  management allowlist if on — where before nothing was attached, or generic XDP
  was running unannounced. TC is strictly cheaper than generic XDP.
- On TC, `enable_mgmt_whitelist` now does what it says: unlisted addresses lose
  the management port. The rule that the flag is only written once an address
  is installed is unchanged, so this cannot lock out an operator whose list is
  empty.
- ADR 0007's "the TC hook decides on the IP header alone" no longer holds; it
  reads one transport-header field.
- An unconfigured install on a host whose default route is not on `eth0` now
  attaches where it previously failed with "no such network interface".

## Alternatives considered

- **Keep TC opt-in and correct the README.** Rejected. Turning eBPF on is the
  request for kernel filtering, and on EC2 TC is the only hook that can provide
  it; a second switch to receive it is a trap nobody is warned about.
- **Recommend TC in the diagnosis and leave the attach alone.** That was the
  state before this record, and the counters read zero on every EC2 install
  that did not find the setting.
