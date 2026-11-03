# 83. The kernel is shielded from handshakes the WAF never sees

Date: 2026-11-03

## Status

Accepted.

## Context

CVE-2026-98432 (CVSS 9.8, Linux 4.4 onward) is a use-after-free in the IPv4
TCP handshake. A SYN's IP options are saved on the request socket and handed to
the child socket without a copy; a retransmitted SYN raced on another CPU then
builds a SYN-ACK from options already freed. The public exploit reached root on
a host with an MPTCP listener.

It fires before `accept()`. No request reaches the gateway, so gwaf, the CEL
policy and every HTTP middleware are structurally blind to it; there is no
detection rule to write in gwaf. Two parts of Gateon were in play anyway:

- **The eBPF hooks run in front of the TCP stack**, and read IHL correctly
  (`read_l4`), but nothing refused a SYN carrying options.
- **Gateon's own listeners were MPTCP.** Go 1.24 made `net.Listen("tcp")` open
  an MPTCP socket wherever the kernel allows, and the binary builds with Go
  1.27; `SO_PROTOCOL` on every entrypoint and the management listener read
  `IPPROTO_MPTCP` (262). Nobody chose that, and no Gateon feature uses MPTCP.

The real fix is a patched kernel. This ADR is about what the gateway does for a
host that is not patched yet, or will be patched late.

## Decision

**The XDP and TC programs drop every IPv4 TCP SYN (SYN without ACK) whose IHL
is above 5**, counted as drop reason `ip_options_syn` (6). It runs right after
the IP blocklist on XDP and first of all on TC, before the management
allowlist: a kernel bug is not a lockout, and a SYN needs no reply to land, so
a listed address can be spoofed. A TCP packet with options whose flags cannot
be read -- a first fragment cut short of them -- is dropped too, because
reassembly would hand the stack the whole SYN.

**Every option kind, not only Record Route and Timestamp.** The kernel saves
NOP padding just the same, and naming kinds would mean walking the option list,
which the unprivileged verifier will not take (see `read_l4`).

**No switch.** A SYN with IP options has no legitimate use on the open internet
and is commonly dropped by routers already; established traffic and SYN-ACKs
are untouched. A switch would be a setting that can only make a host less safe,
and the project has paid for settings that save and are never read.

**MPTCP is off for the binary**: `godebug multipathtcp=0` in `go.mod`, which
`go build` records as the binary's `DefaultGODEBUG` and which applies to tests.
One line covers every listener, including ones added later, where a per-site
`ListenConfig` would have to be remembered at each. `GODEBUG=multipathtcp=1` at
runtime restores it for an operator who wants it -- the env-var path.

## Consequences

- Detection: `gateon_ebpf_dropped_packets_total{reason="ip_options_syn"}` and
  the diagnostics API's `droppedPackets` show the trigger being refused; the
  dashboard's eBPF drop total includes it. One new label value; the label set
  stays bounded by the drop-reason table.
- Protection requires the eBPF hooks to be attached. Without them (non-Linux,
  no `CAP_BPF`, `noebpf` build) only the MPTCP change applies, and the host
  needs the nftables rule from the advisory or a patched kernel.
- IPv6 is not affected on the main path (`tcp_v6_syn_recv_sock` copies the
  options), so the IPv6 programs are unchanged.
- Proven in `internal/ebpf/ip_options_syn_linux_test.go` (kernel verdicts on
  both hooks, the counter, the allowlist, and the traffic that must still pass)
  and `internal/server/entrypoint/mptcp_off_linux_test.go` (every TCP listen
  path reads `IPPROTO_TCP`; skipped where the kernel cannot open MPTCP at all).
