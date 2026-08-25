# 7. XDP attach mode and the TC ingress hook

Date: 2026-08-25

## Status

Accepted.

## Context

`internal/ebpf` attached its XDP program by asking the kernel for native driver
mode and, when that failed, silently retrying in generic (`XDP_FLAGS_SKB_MODE`)
mode behind a log warning. On the deployment target this fallback was not an
edge case — it was the normal path, and it made the gateway slower than running
no eBPF at all.

**Why the native attach fails on EC2.** The ENA driver enforces two constraints
and returns `EINVAL` ("create link: invalid argument") when either is unmet:

1. **MTU.** Native XDP needs the frame, `XDP_PACKET_HEADROOM` and the
   `skb_shared_info` tailroom to fit in one page, so the ceiling is roughly
   3498 bytes on a 4 KiB-page host. The EC2 VPC default is 9001.
2. **Queue count.** A dedicated TX queue is needed per RX queue to service
   `XDP_TX`/`XDP_REDIRECT`, so the driver requires `combined <= max/2`. It comes
   up using every queue the instance has, so the check fails by default.

**Why generic mode is worse than nothing.** Generic XDP runs in
`netif_receive_generic_xdp()`, *after* the skb has been allocated and the
driver's NAPI poll has completed. It therefore drops no earlier than an
nftables rule, while still charging every *passed* packet the full program cost
— and `bpf/xdp_rate_limit.c` performs up to fifteen map lookups per packet. On
top of that it demands 256 bytes of headroom, calling `pskb_expand_head()` (a
fresh allocation plus a full packet copy) when the skb lacks it, and calls
`skb_linearize()` on non-linear skbs, which at MTU 9001 with page-fragment
receive is most of them. The result on a default EC2 instance is two extra
allocations and two extra copies per packet in exchange for no earlier drop.

This is the shape the profile roster already forbids: a fast path that costs
more than the slow path it replaced. It went unnoticed because the degrade was
silent and the only signal was a log line.

A related defect made the whole subsystem's status ambiguous: `Makefile`
probed for `internal/ebpf/gateon_ebpf_bpfel.go`, a filename `bpf2go -target bpf`
never emits, so `HAS_EBPF` was always empty and `make build` / `make release`
compiled the `noebpf` stub — while the `Dockerfile`'s bare `go build` compiled
eBPF in. The two build paths shipped different binaries.

## Decision

**Generic XDP requires an explicit opt-in.** `EbpfConfig.allow_generic_xdp`
defaults to false. When the native attach fails and the flag is unset, the
loader refuses rather than degrading, and records why in `MapStats.LoadError`
so the dashboard can answer "why are the counters zero?".

**A failed native attach produces a diagnosis, not an errno.** The loader
probes the interface — MTU from `net.Interface`, RX queue count and bound
driver from sysfs, page size and CPU count from the runtime — and emits the
remediation commands (`ip link set dev … mtu …`, `ethtool -L … combined …`).
Every fact is best-effort: a fact it cannot determine narrows the explanation
rather than inventing one. sysfs was chosen over the ethtool ioctl because the
latter needs `unsafe`, which `sec` vetoes, for what is only a diagnostic; the
consequence is that the driver's true maximum queue count is not readable, so
the queue check compares against the CPU count and hands the operator the
command that shows the real numbers.

**TC (clsact) ingress is the supported hook on virtualized NICs.**
`tc_filtering` shipped in the proto and the UI while `loadTC` was a log line.
It is now implemented: a `SEC("tc")` program in the same object, reading the
same maps, attached via TCX on kernels ≥ 6.6 and via a clsact qdisc plus a
direct-action bpf filter otherwise (Amazon Linux 2023 ships the 6.1 line). The
clsact hook sits at the same point in the stack as generic XDP but has neither
its headroom requirement nor its linearization step, and no MTU ceiling.

**XDP and TC are alternatives, not layers.** Both make the same decisions from
the same maps and XDP sits strictly earlier, so loading both would only have TC
re-inspect what XDP already passed. TC loads when XDP is not wanted, or when
XDP was wanted and could not attach.

## Consequences

- An install that was silently running generic XDP now refuses to attach and
  says why. This is a **behaviour change on upgrade**: the eBPF counters stop
  moving where they were previously moving slowly and expensively. The fix is
  `tc_filtering = true`, one of the two remediation commands, or an explicit
  `allow_generic_xdp = true` to keep the old behaviour.
- `make build` now compiles eBPF in whenever codegen has run, matching what the
  Dockerfile has always shipped. Release binaries gain a subsystem that the
  Makefile was silently omitting.
- The TC hook enforces fewer checks than XDP: it decides on the IP header
  alone, so port knocking, JA4/JA3 blocklisting, phantom ports and load
  balancing are not in force there. The manager logs exactly which configured
  features are unenforced when it attaches via TC — the alternative is an
  operator whose `ShunJA4` call succeeds against nothing.
- `github.com/vishvananda/netlink` moves from an indirect to a direct
  dependency for the clsact fallback. It was already in the module graph.
- Teardown removes only the filter it installed, and removes the clsact qdisc
  only if it created it: deleting a borrowed clsact takes every filter on it,
  including egress filters belonging to a CNI.
- `BlockCountry` remains a no-op. `country_block_map` is keyed by a hashed
  country code, not an address, and neither program consults it; wiring it up
  needs an LPM trie of geo ranges and is out of scope here. This was found
  while porting the checks and is called out rather than papered over.
