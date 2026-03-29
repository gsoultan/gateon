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

- **Network Isolation**: By default, it binds only to `127.0.0.1` (localhost). This means it is not reachable from the public internet unless you explicitly change the bind address or use a secure tunnel (like Cloudflare Tunnel).
- **IP Whitelisting**: It includes a mandatory IP filter. You can specify exactly which IPs or CIDR blocks are allowed to access the management interface.
- **Route Isolation**: It skips the routing logic for user-defined proxy rules. Even if a proxy route matches a request on the management port, it will be ignored, reducing the attack surface.
- **Enforced Authentication**: API access on this port always requires Paseto authentication, even if you have disabled authentication for certain proxy routes.

## Configuration

You can configure the management entrypoint using the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEON_MANAGEMENT_BIND` | `127.0.0.1` | The IP address the management server binds to. Use `0.0.0.0` to allow external access (e.g. from a container host). |
| `GATEON_MANAGEMENT_ALLOWED_IPS` | `127.0.0.1,::1` | A comma-separated list of IP addresses or CIDR blocks allowed to connect to the management port. Use `0.0.0.0/0` to allow all (not recommended). |
| `PORT` | `8080` | The port used by the management entrypoint (shared with the default startup configuration). |

## Recommended Setup with Cloudflare Tunnel

If you are using Cloudflare Tunnel to access your dashboard (e.g., at `gateon.example.com`):

1. Keep `GATEON_MANAGEMENT_BIND` at its default (`127.0.0.1`).
2. Point your Cloudflare Tunnel configuration to `http://localhost:8080`.
3. This ensures your dashboard is never exposed directly to the internet, but remains accessible through your secure Zero Trust tunnel.
