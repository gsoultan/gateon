# Proxy Protocol in Gateon

This guide explains what **PROXY protocol** is, why it matters, and how to use it safely with Gateon.

## What is PROXY protocol?

`PROXY protocol` is a small header added at the start of a TCP connection by a trusted proxy or load balancer.

Its purpose is to preserve the **original client connection metadata** when traffic passes through one or more proxies.

Without PROXY protocol, your backend usually sees only Gateon (or the last proxy) as the source IP.

With PROXY protocol, your backend can receive:

- Original client source IP and port
- Destination IP and port
- Address family (`TCP4` / `TCP6`)
- Optional extra metadata (for v2 via TLVs)

## Why it matters

In many real deployments, correct client identity is required for:

- Security policies and access controls
- Accurate logs and audit trails
- Rate limiting and abuse prevention
- Geolocation and reputation checks
- Mail workflows where SPF depends on source IP

If your backend only sees proxy IPs, these systems can produce wrong results.

## Versions: v1 vs v2

| Version | Format | Pros | Notes |
|---------|--------|------|-------|
| `v1` | Text (human-readable) | Easy to inspect and debug | Slightly larger header |
| `v2` | Binary | More compact, richer metadata (TLVs) | Harder to read manually |

Gateon supports both versions (depending on service configuration and backend support).

## How it works with Gateon

When PROXY protocol is enabled for a TCP service, Gateon prepends a PROXY header before forwarding the stream to the backend.

Example v1 line:

```
PROXY TCP4 <client_ip> <server_ip> <client_port> <server_port>\r\n
```

Your backend must be configured to **expect and parse** this header.

## Configuration requirements

PROXY protocol is not auto-negotiated. Sender and receiver must match.

You need all of the following:

1. Gateon service with PROXY protocol enabled
2. Matching PROXY protocol version (`v1` or `v2`) expected by backend
3. Backend listener configured for PROXY protocol on that port
4. Trusted network path (do not accept untrusted direct clients on a PROXY-enabled listener)

If any of these are missing, connections may fail or traffic may look malformed.

## Security considerations

Treat PROXY headers as trusted data only when they come from trusted proxies.

Recommended practices:

- Restrict backend listener access to Gateon (firewall / private network)
- Do not expose PROXY-enabled backend ports directly to the internet
- Keep trust boundaries explicit in multi-proxy deployments
- Verify backend logs show expected source addresses after enablement

## Common failure modes and troubleshooting

### 1) Version mismatch (v1 vs v2)

Symptoms:

- Immediate connection close/reset
- Backend errors about invalid protocol bytes

Fix:

- Ensure Gateon and backend use the same PROXY protocol version.

### 2) Backend not configured for PROXY protocol

Symptoms:

- Backend treats PROXY header as application payload
- Protocol parse errors at the start of sessions

Fix:

- Enable PROXY protocol parsing on the backend listener.

### 3) Untrusted clients can reach PROXY-enabled listener

Symptoms:

- Spoofed client IPs in logs/policies

Fix:

- Restrict listener access to trusted proxy IPs only.

## When to choose v1 or v2

- Choose **v1** when simplicity and easy packet/log inspection are more important.
- Choose **v2** when you want compact binary framing and possible extra metadata support.

If unsure, start with what your backend documentation recommends and keep both sides aligned.

## Related Gateon docs

- [Email Backend Setup (SMTP, IMAP, POP3)](./email-backend-setup.md)
- [Running Gateon as a Service](./services.md)
