# Email Backend Setup (SMTP, IMAP, POP3)

Gateon can proxy email servers (SMTP, IMAP, POP3) using its **L4 TCP proxy**. This guide explains how to configure Gateon for email backends and enable correct **SPF** and **DKIM** behavior.

## Overview

| Protocol | Ports (standard/TLS) | Gateon support |
|----------|----------------------|----------------|
| **SMTP** | 25, 587, 465         | L4 TCP         |
| **IMAP** | 143, 993             | L4 TCP         |
| **POP3** | 110, 995             | L4 TCP         |

Once a connection is routed, Gateon’s L4 proxy forwards raw TCP bytes. It does not interpret the mail protocol, so SMTP, IMAP, POP3 and their STARTTLS upgrades pass through unchanged.

## The mail server speaks first

In SMTP, IMAP and POP3 the server greets first (`220 ...`, `* OK ...`, `+OK ...`) and the client waits for the greeting. A plaintext TCP entrypoint chooses a route by reading what the client sends first, because one port can serve HTTP, SSH, RDP and TCP routes together. Set the entrypoints up so it knows there is nothing to read:

1. **Give each mail port an entrypoint of its own, whose only route is its `tcp` route**: one entrypoint for 25, one for 587, one for 143, and so on. Gateon then hands each connection to the route as soon as it is accepted, and the greeting arrives at once. Everything sent to that port, HTTP included, goes to the mail server.
2. **List entrypoints on every HTTP, gRPC and GraphQL route.** A route of one of those types that lists no entrypoints is served on every entrypoint, the mail ports included, and a port serving it is no longer a mail-only port. An `ssh` or `rdp` route on the port has the same effect; a `udp` route does not.
3. **On a port that also serves other routes, the greeting takes half a second.** Gateon gives the client 500 ms to speak, then connects to the mail server and lets whichever speaks first decide: the server's greeting takes the connection to the `tcp` route, and a client's request is routed by what it says. Mail still works, it only starts later. A client of another protocol that says nothing for more than 500 ms after connecting reaches the mail server instead of its own route.
4. **A TLS-terminating entrypoint never waits**: the client starts the handshake. See *TLS and STARTTLS* below for where its targets must point.
5. **A TCP entrypoint holds at most `max_connections` connections.** At 0 it holds the resource profile's default: 1000 on `minimal`, 10000 on `standard`, 50000 on `enterprise`.

## DKIM

**DKIM works as-is.** Gateon does not modify message headers. Your backend signs (outbound) and verifies (inbound); no extra configuration is needed.

## SPF

SPF checks the connecting IP. With a proxy, the backend sees Gateon’s IP, not the original client. To keep SPF correct for **inbound** mail, Gateon can send the **HAProxy PROXY protocol v1** header so the backend uses the real client IP.

### Enable PROXY Protocol in Gateon

1. Create a **Service** with `backend_type: "tcp"`.
2. Add targets like `mail.internal:25`, `mail.internal:587`, `mail.internal:993`.
3. Enable **Send PROXY protocol (TCP)** for that service.
4. Create a **Route** with `type: "tcp"`, using a TCP entrypoint and this service.

Gateon will prepend the PROXY header before forwarding data:

```
PROXY TCP4 <client_ip> <server_ip> <client_port> <server_port>\r\n
```

### Backend Configuration

Configure your mail server to accept PROXY protocol and use the real client IP.

**Postfix** (typical):

- Use a Postfix build with PROXY protocol support, or put HAProxy/another proxy in front that terminates PROXY and forwards.
- Add Gateon’s IP to `mynetworks` (or equivalent “trusted relay” list).
- If using `postfix-forward` or similar, follow its docs for PROXY protocol.

**Dovecot / other MTAs**:

- Check whether they support PROXY protocol.
- Configure them to read the PROXY header and use the client IP for SPF and logging.

## Step-by-Step Setup

### 1. Create a Service

- **Name:** e.g. `email-smtp`, `email-imap`
- **Backend type:** `TCP (L4)`
- **Targets:** `mail.internal:25` (or `mail.internal:587`, `mail.internal:993`, etc.)
- **Load balancer:** Round Robin or Least Connections
- **Send PROXY protocol (TCP):** On (recommended for SMTP/IMAP/POP3)

### 2. Create Entrypoints

Create one TCP entrypoint per port you want to expose, for example:

| Entrypoint   | Port | TLS on the entrypoint | Use case                           |
|--------------|------|-----------------------|------------------------------------|
| `smtp`       | 25   | No                    | SMTP relay, upgraded with STARTTLS |
| `submission` | 587  | No                    | SMTP submission, with STARTTLS     |
| `smtps`      | 465  | Yes, or No            | SMTP submission over implicit TLS  |
| `imap`       | 143  | No                    | IMAP, with STARTTLS                |
| `imaps`      | 993  | Yes, or No            | IMAP over implicit TLS             |
| `pop3`       | 110  | No                    | POP3, with STARTTLS                |
| `pop3s`      | 995  | Yes, or No            | POP3 over implicit TLS             |

Leave TLS off on the STARTTLS ports (25, 587, 143, 110). Their clients connect in plaintext, read the greeting and then ask the mail server to upgrade; a TLS-terminating entrypoint on one of them would wait for a handshake the client never starts. For the implicit-TLS ports, *TLS and STARTTLS* below explains both choices.

### 3. Create Routes

- **Type:** `tcp`
- **Entrypoints:** the mail entrypoints this service answers on
- **Service:** the service created above
- **Rule:** `L4()` (automatic for L4 routes)

Serve nothing else on the mail entrypoints, and give every HTTP route its own entrypoints, so the greeting is not delayed (see *The mail server speaks first*).

### 4. Configure Backend Mail Server

- Ensure the mail server listens on the correct interfaces/ports.
- If using PROXY protocol, configure it to read the PROXY header.
- Add Gateon’s IP to any “trusted relay” lists so connections from Gateon are accepted.

## SPF for Outbound Mail

When your server sends mail, it typically connects directly to recipient MTAs. Your SPF record should list the IP(s) that actually connect (your server’s public IP or Gateon’s, depending on your topology).

## TLS and STARTTLS

- **Implicit TLS (465, 993, 995):** choose who terminates TLS.
  - *The mail server:* a TCP entrypoint **without** TLS, with targets on the server's TLS
    ports (`mail.internal:993`). Gateon relays the encrypted bytes untouched.
  - *Gateon:* enable TLS on the entrypoint and point the targets at the server's
    **plaintext** ports (`mail.internal:143` for IMAPS, `:110` for POP3S, `:25` or `:587`
    for SMTPS). A TLS-terminating entrypoint forwards plaintext, so a target on the
    server's TLS port would receive plaintext on a TLS listener and fail.
- **STARTTLS (25, 587, 143, 110):** Gateon relays the bytes, so the upgrade happens
  between the client and the mail server without extra config.

## Summary

| Item                  | Action                                   |
|-----------------------|------------------------------------------|
| **DKIM**              | No changes; backend signs and verifies   |
| **Inbound SPF**       | Enable PROXY protocol in the service     |
| **Backend**           | Configure PROXY protocol and trusted IPs |
| **Outbound SPF**      | List correct IPs in your SPF record      |
