# 18. eBPF privileges are capabilities, and a container gets them as uid 0

Date: 2026-09-26

## Status

Accepted. `arch` and `ops`, with `sec` co-signing: it moves a privilege
boundary — which processes may load programs into the kernel — and changes what
the container runs as in eBPF mode.

## Context

The supervisor started eBPF only when `os.Geteuid() == 0`, while its own error
said that granting CAP_BPF, CAP_NET_ADMIN and CAP_PERFMON would do. So:

- The image runs as `nonroot` (65532), and the Helm chart as 65532 with
  `runAsNonRoot`. Neither could ever start eBPF; the chart's `ebpf.enabled`
  granted NET_ADMIN and BPF and bought nothing.
- Root with every capability dropped passed the gate and failed at load.
- A systemd unit run as its own user with the capabilities was refused.

What the kernel needs was measured, on an arm64 7.1 kernel: a non-root process
holding CAP_BPF and CAP_NET_ADMIN — without CAP_PERFMON, without
CAP_SYS_RESOURCE — loads both programs, attaches them (native and generic XDP,
TCX, clsact), and passes the full suite. CAP_PERFMON is neither needed nor
wanted: alongside CAP_BPF it permits tracing programs that read kernel memory.
Without it the verifier's Spectre hardening refuses some program shapes — a
register added to a packet pointer, a packet pointer compared against NULL —
which the programs now avoid, and which CI checks by loading them that way.

In a container, an added capability reaches a process that is not uid 0 only
through the ambient set. Docker sets just the bounding set for a non-root user,
and Kubernetes has no ambient capability support. File capabilities on the
binary work only without `no_new_privs`, which `allowPrivilegeEscalation: false`
sets.

## Decision

- **The gate asks for capabilities.** CAP_BPF and CAP_NET_ADMIN, or
  CAP_SYS_ADMIN — the pre-5.8 way to load BPF — read from the process's
  effective set (`ebpf.MissingPrivileges`). The uid does not matter.
- **In a container, eBPF mode runs as uid 0 with every capability dropped except
  those two**, privilege escalation blocked and the root filesystem read-only.
  The image default stays `nonroot`; eBPF mode is an explicit opt-in —
  `ebpf.enabled` in the chart, `--user 0 --cap-drop ALL --cap-add BPF
  --cap-add NET_ADMIN` for `docker run`.
- **`ebpf.hostNetwork`** (default off) puts the pod on the node's network so the
  programs attach to the node's NIC. Off, they attach to the pod's interface and
  still filter before gateon sees the packet.

## Consequences

- The packaged systemd unit runs as root and is unaffected. A unit run as its
  own user with `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN` now works.
- The chart's eBPF mode works for the first time, as uid 0. An install that
  enabled it was running without eBPF; after upgrading it runs with it.
- Root without the capabilities is refused up front, naming what is missing,
  instead of failing at load.
- The programs have to keep loading without CAP_PERFMON. CI runs the suite as an
  ordinary user holding only the two capabilities.

## Alternatives considered

- **Keep uid 0 as the gate and call containers unsupported.** Rejected: it
  contradicted its own error message and refused a correctly configured service.
- **Non-root with file capabilities.** Needs `allowPrivilegeEscalation: true`,
  since `no_new_privs` disables file capabilities, and a build that preserves the
  xattr through `COPY`. That is a weaker posture than uid 0 with the other
  capabilities dropped and escalation blocked.
- **Require CAP_PERFMON.** Rejected: it permits reading kernel memory, and the
  programs do not need it.
