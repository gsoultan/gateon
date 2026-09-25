# Secure Management Entrypoint

Gateon features a dedicated **Secure Management Entrypoint** that ensures the dashboard and internal API are always accessible, even when you are configuring complex proxy rules or custom entrypoints.

## Overview

In many reverse proxies, adding a new entrypoint (e.g., for port 443) might disable the default management port if not configured carefully. Gateon prevents this by separating the **Management Control Plane** from the **Data Plane (Proxy Entrypoints)**.

The management entrypoint is:
1. **Dedicated**: It only serves the Gateon Dashboard and the internal API. It never handles proxy traffic for your user-defined routes.
2. **Persistent**: It starts automatically on the port specified at launch (default `8080`) and remains active regardless of any custom entrypoints you add or remove in the UI.
3. **Hardened**: It includes built-in security layers to prevent unauthorized access.

## Security Features

The management entrypoint is secured by multiple layers:

- **IP Whitelisting**: It includes a mandatory IP filter. You can specify exactly which IPs or CIDR blocks are allowed to access the management interface. **Read [Network exposure](#network-exposure) below before relying on this** — the shipped default does not restrict anything.
- **Route Isolation**: It skips the routing logic for user-defined proxy rules. Even if a proxy route matches a request on the management port, it will be ignored, reducing the attack surface.
- **Enforced Authentication**: API access on this port always requires Paseto authentication, even if you have disabled authentication for certain proxy routes.
- **Closed Before Setup**: Until an administrator account exists, the management API answers `503` for everything except the setup and health endpoints. A gateway that has not been configured yet cannot be configured by a stranger who reaches it first.
- **Bounded Sessions**: Session tokens last 8 hours and are bound to the account they were issued for. Disabling, deleting, demoting or re-passwording a user ends that user's live sessions on the next request. See [security-posture.md](./security-posture.md#session-lifecycle).

## Network exposure

**The shipped default binds to `0.0.0.0` and allows every source address.** A
fresh install is reachable on port 8080 from every network the host is attached
to, protected by the login form and nothing else.

This is deliberate, and it is the right default in a container: a process bound
to `127.0.0.1` inside a container is unreachable through a published port, so a
loopback default would break every Docker and Kubernetes deployment. It is the
wrong posture on a host with a public address.

Gateon cannot tell which situation it is in, so it does not guess — it logs a
warning at startup whenever the bind is a wildcard *and* the allowlist
constrains nothing:

```
WARN management entrypoint is reachable from any address
     bind=0.0.0.0 port=8080 allowed_ips=0.0.0.0/0,::/0
     action="restrict management.allowed_ips to your admin network, or set GATEON_MANAGEMENT_ALLOWED_IPS"
```

If you see that line on anything other than a container whose network is
already your boundary, restrict it.

### Which value actually applies

Three layers set the bind address and allowlist. Later entries win:

1. **Built-in fallback** — `127.0.0.1` and `127.0.0.1,::1`. These apply only
   when `global.json` has no `management` block, i.e. before first setup.
2. **`global.json`** — `management.bind` and `management.allowed_ips`. A fresh
   install writes `0.0.0.0` and `["0.0.0.0/0", "::/0"]` here, which is why the
   effective default is open rather than loopback.
3. **Environment** — `GATEON_MANAGEMENT_BIND` and
   `GATEON_MANAGEMENT_ALLOWED_IPS` override both.

So setting only the environment variables is enough to lock the port down, and
editing `global.json` is enough to lock it down persistently — but leaving both
alone does **not** give you a loopback-only listener.

## Configuration

These environment variables override whatever is in `global.json`. The "effective default" column is
what you get on a fresh install with the variable unset — which is **not** the
same as the built-in fallback, because setup writes a wider value into
`global.json` (see [Which value actually applies](#which-value-actually-applies)).

| Variable | Effective default | Description |
|----------|-------------------|-------------|
| `GATEON_MANAGEMENT_BIND` | `0.0.0.0` | The IP address the management server binds to. Set to `127.0.0.1` to restrict it to the local machine. |
| `GATEON_MANAGEMENT_ALLOWED_IPS` | `0.0.0.0/0,::/0` (unrestricted) | A comma-separated list of IP addresses or CIDR blocks allowed to connect to the management port. Set this to your admin network. |
| `GATEON_MANAGEMENT_HOST` | unset | Restrict the management entrypoint to a specific `Host` header, e.g. `gateon.example.com`. |
| `PORT` | `8080` | The port used by the management entrypoint (shared with the default startup configuration). |

## Recommended Setup with Cloudflare Tunnel

If you are using Cloudflare Tunnel to access your dashboard (e.g., at `gateon.example.com`):

1. Set `GATEON_MANAGEMENT_BIND=127.0.0.1` if the tunnel runs on the same machine — this is the main reason to bother with a tunnel, and it is not the default, so you have to set it. If the tunnel is on a different machine, bind to the interface it reaches, not `0.0.0.0`.
2. Point your Cloudflare Tunnel configuration to `http://<gateon-ip>:8080`.
3. Decide which address the management allowlist should judge. `cloudflared` connects from your own network, not from a Cloudflare range, so by default Gateon sees the tunnel's address and never looks at `CF-Connecting-IP`.
   - **The tunnel's address** (simplest): set `GATEON_MANAGEMENT_ALLOWED_IPS` to it, and let Cloudflare Access decide who may use the tunnel.
   - **Your browser's address**: set `GATEON_TRUSTED_PROXIES` to the tunnel's address and `GATEON_TRUST_CLOUDFLARE_HEADERS=true`. Gateon then attributes each request to `CF-Connecting-IP`, and `GATEON_MANAGEMENT_ALLOWED_IPS` must list your admin addresses, not the tunnel's.
4. Either way, do not leave `GATEON_MANAGEMENT_ALLOWED_IPS` at the unrestricted default. That makes the tunnel decorative: anyone who can route to the port bypasses it entirely.

## Common Issues: 502 Bad Gateway

If you encounter a **502 Bad Gateway** when accessing the dashboard via Cloudflare:
- **IP Mismatch**: If you have set `GATEON_MANAGEMENT_ALLOWED_IPS` or `management.allowed_ips` (which you should — the default restricts nothing), the address Gateon attributes the request to must be in it. That is the tunnel's address, unless the tunnel is in `GATEON_TRUSTED_PROXIES` and `GATEON_TRUST_CLOUDFLARE_HEADERS=true`, in which case it is your browser's.
- **Bind Address**: Ensure `GATEON_MANAGEMENT_BIND` allows connections from the tunnel's IP.
- **Header Trust**: `GATEON_TRUST_CLOUDFLARE_HEADERS=true` alone does not make Gateon believe `CF-Connecting-IP` from a tunnel, because the tunnel does not connect from a Cloudflare range. Before 2026-09-25 the variable was ignored entirely whenever the config file had a WAF section, which it always does; an allowlist written against the tunnel's address still works after the fix, for the same reason.
