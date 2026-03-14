# Email Backend Setup (SMTP, IMAP, POP3)

Gateon can proxy email servers (SMTP, IMAP, POP3) using its **L4 TCP proxy**. This guide explains how to configure Gateon for email backends and enable correct **SPF** and **DKIM** behavior.

## Overview

| Protocol | Ports (standard/TLS) | Gateon support |
|----------|----------------------|----------------|
| **SMTP** | 25, 587, 465         | L4 TCP         |
| **IMAP** | 143, 993             | L4 TCP         |
| **POP3** | 110, 995             | L4 TCP         |

Gateon’s L4 proxy forwards raw TCP bytes. It does not inspect the application protocol, so any TCP service works.

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

| Entrypoint        | Port | TLS         | Use case        |
|-------------------|------|-------------|-----------------|
| `smtp-submission` | 587  | Yes (recommended) | SMTP submission |
| `smtps`           | 465  | Yes         | SMTPS           |
| `imaps`           | 993  | Yes         | IMAP over TLS   |
| `pop3s`           | 995  | Yes         | POP3 over TLS   |
| `smtp`            | 25   | Optional    | SMTP relay      |

### 3. Create Routes

- **Type:** `tcp`
- **Entrypoints:** select the TCP entrypoint(s) you use
- **Service:** the service created above
- **Rule:** `L4()` (automatic for L4 routes)

### 4. Configure Backend Mail Server

- Ensure the mail server listens on the correct interfaces/ports.
- If using PROXY protocol, configure it to read the PROXY header.
- Add Gateon’s IP to any “trusted relay” lists so connections from Gateon are accepted.

## SPF for Outbound Mail

When your server sends mail, it typically connects directly to recipient MTAs. Your SPF record should list the IP(s) that actually connect (your server’s public IP or Gateon’s, depending on your topology).

## TLS and STARTTLS

- **Ports 465, 993, 995:** Enable TLS on the Gateon entrypoint and point targets to the backend’s TLS ports.
- **STARTTLS (e.g. 25, 587):** Gateon passes bytes through; STARTTLS upgrades work without extra config.

## Summary

| Item                  | Action                                   |
|-----------------------|------------------------------------------|
| **DKIM**              | No changes; backend signs and verifies   |
| **Inbound SPF**       | Enable PROXY protocol in the service     |
| **Backend**           | Configure PROXY protocol and trusted IPs |
| **Outbound SPF**      | List correct IPs in your SPF record      |
