# 88. Listening sockets stay open across a restart

Date: 2026-11-13

## Status

Accepted. Third of three, after ADR 0085 and ADR 0087. It changes one thing
ADR 0087 decided: the helper's stop, swap and start is now a swap and a single
restart.

## Context

ADR 0087 lets a gateway install a release and restart into it. The restart
closed every listener and bound it again a few seconds later, and a client
that connected in between was refused. For a gateway that upgrades itself at
two in the morning, on a schedule nobody is watching, a refused connection is
the one visible cost of the feature.

A listening socket does not have to close because the process that opened it
exits. The kernel completes handshakes into the socket's accept queue whether
or not anything is calling `accept`. If something else holds the socket open
while the gateway is replaced, connections that arrive meanwhile wait in the
queue and the next process finds them there.

The gateway's listeners are not known ahead of time. Entrypoints are
configuration: an operator adds one on port 8443 from the dashboard. That
rules out systemd socket units, which would need a unit per port written by
something with root.

## Decision

**The gateway hands each listening socket to systemd's file-descriptor store
as it binds it.** `internal/server/sockets` sends the descriptor over the
notification socket (`FDSTORE=1`, `sd_notify(3)`), with the standard library
and no cgo. systemd keeps it across a restart and passes it to the next
process (`LISTEN_FDS`, `sd_listen_fds(3)`), which serves from it instead of
binding. `gateon.service` gains `NotifyAccess=main` and
`FileDescriptorStoreMax=64`.

**A socket is adopted for what it is.** The next process reads each passed
descriptor's type and bound address from the socket itself and matches it to
an entrypoint by those. The name systemd passes beside it is used only to ask
systemd to drop it. A descriptor that is not a listening TCP socket or a bound
UDP socket is closed. `0.0.0.0` does not match a socket bound to `::`, which
also takes IPv6.

**A socket nobody claims is closed and dropped** once every entrypoint has
started. An entrypoint that was removed or moved to another port leaves its
old socket in the store, and a socket nothing accepts from takes connections
and never answers them.

**Stopping the service closes the sockets.** `FileDescriptorStorePreserve` is
left at its default, so the store survives a restart and is emptied on a
stop. A stopped gateway that still accepted connections would be worse than
one that refused them.

**The helper restarts; it no longer stops and starts.** A stop empties the
store. The helper now renames the new binary into place while the old gateway
is still running from the old file, which does not disturb a running process,
and then asks systemd for one restart. A rollback is the same in reverse. A
rename that fails leaves the gateway running untouched, where it used to
leave it stopped and in need of a start.

**Every listener goes through the store**: HTTP and HTTPS, TCP, UDP, HTTP/3
and the management listener. A test fails if a listener in
`internal/server/entrypoint` is bound with the `net` package directly.

**One tunable.** `GATEON_SOCKET_HANDOFF=false` binds afresh at every start
and closes anything inherited. `TierDefaults.SocketHandoff` is on for every
tier: the cost is one descriptor per listener held by systemd, and nothing on
the request path.

## Consequences

- A connection made while the gateway restarts waits and is served. It waits
  as long as the restart takes: the drain of the old process and the start of
  the new one.
- A request in flight is finished by the old process's drain, as before.
- **A connection that outlives the drain is closed, as before**: a WebSocket,
  an SSE stream, a long TCP session. QUIC connections end with the process.
  This is not a seamless handover of live connections, and the dashboard does
  not say it is.
- A gateway that crashes and is restarted by `Restart=on-failure` keeps its
  sockets too. Clients wait out `RestartSec` and are served, where they were
  refused.
- A gateway that cannot start leaves its sockets open in systemd with nothing
  accepting. Clients then time out instead of being refused at once, until
  the service is stopped or hits its start limit. A load balancer's health
  check sees a timeout where it saw a refusal.
- The handoff needs the unit from this release. The helper replaces the
  binary only, so a host upgraded by the helper keeps its old unit and its
  old behaviour until the two lines are added. `doc/upgrading.md` says how.
- Docker, Kubernetes and Windows are unchanged. There is no service manager
  to hold a socket, and those platforms have their own rolling restart.
- Bounded: at most 64 sockets are handed over, the same number the unit lets
  systemd keep. A gateway with more listeners binds the rest afresh and logs
  it.

## Trust boundary

`sec` co-signs: the gateway now serves on descriptors it did not open. They
arrive from PID 1, addressed to this process by `LISTEN_PID`, and only root
or the gateway's own account can put one in the store. The gateway still
believes nothing but the socket: its type and its address. It does not gain a
capability; `CAP_NET_BIND_SERVICE` is still what binds a low port the first
time.

## Alternatives considered

- **`SO_REUSEPORT` and two processes side by side.** The new gateway binds
  the same ports while the old one drains. The kernel then splits new
  connections between both queues, and those in the old process's queue when
  it closes are reset. It also needs both versions running against one
  database at once, which ADR 0087's migration and rollback do not allow.
- **The old process passes its sockets to the new one directly**, by
  inheritance across `exec` or over a Unix socket. That makes the gateway its
  own supervisor: systemd would follow the wrong PID, and the helper, which
  runs as root and must not trust the gateway, would depend on it to start
  its successor.
- **`FileDescriptorStorePreserve=yes` and keep the stop and start.** It needs
  systemd 254. Debian 12 ships 252 and RHEL 9 ships 252. A single restart
  works on every systemd that has a descriptor store.
- **systemd socket units.** Static, one per port, written by root. Entrypoints
  are dynamic and written by an operator in a dashboard.
