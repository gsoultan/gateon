package siem

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// transport delivers an already-formatted event payload to a sink. Transports
// are used by a single shipper worker goroutine, so they need not be
// concurrency-safe beyond protecting their own reconnect state.
type transport interface {
	send(ctx context.Context, payload []byte) error
	Close() error
}

// httpTransport POSTs payloads to an HTTP(S) collector (Elastic/OpenSearch
// bulk, Splunk HEC, Wazuh, or a generic webhook).
type httpTransport struct {
	endpoint    string
	token       string
	contentType string
	client      *http.Client
}

func newHTTPTransport(endpoint, token, contentType string, timeout time.Duration) *httpTransport {
	return &httpTransport{
		endpoint:    endpoint,
		token:       token,
		contentType: contentType,
		client:      &http.Client{Timeout: timeout},
	}
}

func (t *httpTransport) send(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", t.contentType)
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem: collector returned status %d", resp.StatusCode)
	}
	return nil
}

func (t *httpTransport) Close() error { return nil }

// netTransport writes payloads to a UDP or TCP syslog endpoint, reconnecting
// lazily on failure.
type netTransport struct {
	network string // "udp" or "tcp"
	address string
	timeout time.Duration

	mu   sync.Mutex
	conn net.Conn
}

func newNetTransport(network, address string, timeout time.Duration) *netTransport {
	return &netTransport{network: network, address: address, timeout: timeout}
}

func (t *netTransport) send(ctx context.Context, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		if err := t.dialLocked(ctx); err != nil {
			return err
		}
	}
	if t.timeout > 0 {
		_ = t.conn.SetWriteDeadline(time.Now().Add(t.timeout))
	}
	if _, err := t.conn.Write(payload); err != nil {
		// Drop the connection so the next send reconnects.
		_ = t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}

func (t *netTransport) dialLocked(ctx context.Context) error {
	d := net.Dialer{Timeout: t.timeout}
	conn, err := d.DialContext(ctx, t.network, t.address)
	if err != nil {
		return err
	}
	t.conn = conn
	return nil
}

func (t *netTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}
