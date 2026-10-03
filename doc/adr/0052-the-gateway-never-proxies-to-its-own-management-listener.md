# 52. The gateway never proxies to its own management listener

Date: 2026-10-04

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves a trust boundary -- what the
management listener may assume about a connection from this host -- and adds
a check to every backend connection the data plane opens. `perf` for the dial
path, `net` for the listener caps. Review findings MGMT-N2 (high) and MGMT-N4
(medium) of 2026-10-04.

## Context

**The data plane could hand the dashboard to the internet (MGMT-N2).** An
operator saved a service whose target was `127.0.0.1:<management port>` and a
`Host()` route to it on a public entrypoint. A request to that host was
proxied to the management listener, which saw the gateway's own loopback
connection: its bind (loopback by default), its allowlist (ADR 0040: loopback
by default, an administrator's to widen), its per-address connection cap
(loopback is exempt) and the per-source sign-in lockout (ADR 0050: every
attempt came from the same loopback source) all trusted it. The dashboard,
sign-in and the whole API were served publicly, and the operator had widened
nothing an administrator controls. The same was true of `::1`, `0.0.0.0`, the
host's own addresses, `localhost`, any name resolving to them, an `h2c://`,
`https://` or WebSocket target, and a TCP service on an L4 route -- which
carries no request the listener could tell apart at all.

**Two addresses could take the gateway's health probe down (MGMT-N4).** ADR
0042 gave the management listener a per-address connection cap so that one
address could not fill the management chain's 500 in-flight slots. Two could:
at the standard profile's 256 each, slow request bodies held every slot, and
`/healthz` -- from loopback, which no per-address cap applies to -- answered
503, so the Helm chart's liveness probe restarted a gateway that was only
busy. The cap also keyed an IPv6 client by its full address, so a client
holding a /64 (what one subscriber is handed) had 2^64 caps; the data-plane
entrypoints share that limiter (dataplane finding F5).

## Decision

### The gateway does not connect to its own management listener

"Reaches the management listener" is **the management port, on an address of
this host**: loopback (all of 127/8 and `::1`), the unspecified addresses (a
connect to which lands on this host), and every address of the host's
interfaces, IPv4-mapped forms included. That is wider than the listener's own
bind on purpose: it is what a wildcard bind answers on, it is one comparison
wherever the listener is bound, and a backend on this host that shares the
management port's number on another of its addresses is rare enough to be
told to move. The management listener registers its port with
`internal/mgmtaddr` as it binds and forgets it when it closes.

1. **Refused at save** (`mgmtaddr.CheckTarget`, from the domain
   `SaveService`). Every writer of a service -- REST, gRPC, config import, the
   canary controller -- saves through it, so this is the one place. A target is
   read the way the proxy reads it (a URL's host and port, its scheme's default
   port when it names none, or a bare `host:port`), a name is resolved (2 s
   bound), and the refusal is the service's ordinary client error -- `400`,
   `InvalidArgument`, an import error -- naming the target. UDP targets
   (`udp://`, `h3://`, a UDP service) are not checked: the listener is TCP only.
   A lookup that fails or times out is not a refusal; the dial check below
   still applies.

2. **Refused at dial** (`mgmtaddr.Control`, a `net.Dialer` Control hook). A
   save-time check reads a name once; a name can resolve somewhere else
   tomorrow, and services also arrive from configuration files, GitOps and
   discovery, which do not pass through the save. The hook runs after
   resolution on the address actually being connected to. It is installed on
   every dialer that carries data-plane traffic to a backend -- one
   `backendDialer` in `pkg/proxy` for the HTTP/1 and HTTPS transport, h2c,
   HTTP/2 over TLS (which now dials through it and checks the negotiated
   protocol itself, as `http2.Transport` did), the PROXY-protocol path, the
   WebSocket upgrade and the health checks; one in `pkg/l4` for TCP services
   and their health checks. A refused request is answered 502; the health
   check counts the target down, so a service whose only target is refused
   answers 503. The refusal is logged at WARN at most once a minute.

   Its cost is on a connection, never a request: a parse of the address and
   one comparison against the registered port, **0 allocations**; an interface
   lookup only for a connection to the management port's number, cached for
   30 s.

3. **Not done: marking proxied requests for the management listener to
   refuse.** It was considered as defence in depth and rejected. It would add a
   header write -- an allocation -- to every proxied request, to defend against
   a dial path that skips (2); and it cannot cover the L4 path, which carries no
   request to mark, while (2) covers both. Completeness of (2) is held instead
   by tests that build each transport and the L4 pool against a registered
   listener and fail if a connection reaches it, each mutation-checked per dial
   site.

### The gateway's probes answer whoever holds the management chain

Both in-flight limits on the management path -- the listener's chain and the
base handler's -- serve a **bodiless `GET` or `HEAD` of `/healthz` or
`/readyz`** without taking a slot (`traffic.ManagementInflight`). The limit
bounds work held in flight, and a probe holds none: no body (one that declares
any is not a probe), no credential, answered from memory at once. Every other
method, path or a probe with a body is limited as before, and connections stay
bounded by the per-address cap. It is never used on a data-plane route, where
`/healthz` is the backend's path.

### One per-address key, and IPv6 is a /64

Every per-address connection cap -- the HTTP, HTTP/3 and TCP entrypoints' (ADR
0036) and the management listener's (ADR 0042) -- keys on `connKey`: an IPv4
address (a v4-mapped one included) as itself, an IPv6 address as its /64, the
unit the eBPF limits, the honeypot and reputation already use. The map is keyed
by `netip.Addr`, so the key allocates nothing and is 16 bytes; the
loopback/allowlist exemption is still decided on the exact address.

## Consequences

- **A service targeting the management listener can no longer be saved**, on
  any transport; an existing one (from before the upgrade, a file, GitOps, or a
  name that now resolves here) answers 502/503 and logs why. To reach the
  dashboard through an entrypoint, an administrator enables public management
  (ADR 0040), which keeps authentication, the allowlist and the lockout.
- A backend on this host on the management port's number at a different
  address of the host is refused too. Move one of them.
- **`/healthz` and `/readyz` answer while the management chain is saturated.**
- **An IPv6 client's connections are counted per /64**: a provider that puts
  several customers in one /64 shares one cap among them, as it already shares
  a ban.
- Measured: `BenchmarkControl` 20 ns/op, 0 allocs per connection to another
  port; 47 ns/op, 0 allocs to the management port's number on another host.
  The proxy's request path is unchanged (benchstat in the commit).
- **Residue.** A transport configured with `HTTP_PROXY` connects to the proxy,
  not the target, and Go never proxies a loopback target; a forward proxy on
  this host asked to reach the host's own address on the management port is not
  seen.
- **Residue, recorded for a decision.** Middleware that calls a URL of the
  operator's choosing -- forward auth and OAuth2 introspection -- uses its own
  HTTP client, not `backendDialer`, and is not covered. Forward auth sends the
  client's request to its URL and returns a non-2xx answer, body included, to
  the client, so a forward-auth URL on the management listener is a smaller
  form of the same path (an anonymous caller can reach the public sign-in
  endpoints as loopback). The fix is the same hook on those clients' dialers;
  it was out of this change's files and is left to the owner of those
  middlewares.
