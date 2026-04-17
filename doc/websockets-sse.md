# WebSockets and Server-Sent Events (SSE) Support

Gateon provides native, high-performance support for both **WebSockets** and **Server-Sent Events (SSE)**, enabling real-time bidirectional communication and server-to-client streaming for your applications.

## Overview

Modern applications often require long-lived connections for real-time updates (e.g., chat apps, live dashboards, or streaming AI responses). Gateon handles these connection types automatically without requiring complex manual configuration.

- **WebSockets**: Full-duplex communication over a single TCP connection.
- **Server-Sent Events (SSE)**: Unidirectional server-to-client streaming over HTTP.

## WebSockets Support

Gateon automatically detects WebSocket handshake requests and handles them using a dedicated high-performance tunneling mechanism.

### How it Works

1. Gateon inspects incoming HTTP requests for the `Upgrade: websocket` and `Connection: Upgrade` headers.
2. If detected, Gateon establishes a connection to the backend target.
3. Upon a successful `101 Switching Protocols` response from the backend, Gateon hijacks the client connection.
4. It then creates a bidirectional byte-level tunnel between the client and the backend, ensuring minimal overhead and maximum throughput.

### Configuration

No special configuration is required on your routes or services. To proxy WebSocket traffic:
1. Create a standard **HTTP Route**.
2. Point it to an **HTTP Service**.
3. Ensure your backend application is configured to handle WebSocket upgrades on that path.

## Server-Sent Events (SSE) Support

Gateon is optimized for streaming responses like SSE by disabling response buffering for all proxy traffic.

### How it Works

By default, Gateon's reverse proxy is configured with a `FlushInterval` of `-1`. This ensures that:
- Response headers are sent to the client immediately.
- Each chunk of data from the backend is flushed to the client as soon as it is received.
- There is no internal buffering that could delay or break SSE streams.

### Configuration

To use SSE with Gateon:
1. Create a standard **HTTP Route**.
2. Point it to an **HTTP Service**.
3. In your backend application, set the `Content-Type` header to `text/event-stream`.
4. Keep the connection open and send data using the standard SSE format (`data: ...\n\n`).

## Important Considerations

### Timeouts

For long-lived connections like WebSockets and SSE, you must ensure that Gateon's entrypoint timeouts are not too aggressive. 

If your connections are being dropped prematurely, check the `read_timeout_ms` and `write_timeout_ms` settings for your entrypoint in `entrypoints.json` or the UI.

- **Recommendation**: Use application-level heartbeats (pings/pongs) to keep connections active and detect dead peers, even with long timeouts.

### Connection Limits

Since WebSockets and SSE keep connections open for long periods, they contribute to the `Active Connections` count. Monitor your server's file descriptor limits (`ulimit -n`) and Gateon's active connection metrics to ensure your infrastructure can handle the expected concurrency.
