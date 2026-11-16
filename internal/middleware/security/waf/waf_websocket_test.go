// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	dto "github.com/prometheus/client_model/go"
)

// A WebSocket upgrade is one request and then a connection. These tests run a
// real connection through the WAF middleware into a handler that takes it the
// way the proxy does, and look at what that handler -- the backend -- received.

const (
	wsAttack = `{"op":"search","q":"1' UNION SELECT password FROM users--"}`
	wsClean  = `{"op":"search","q":"blue shoes"}`
)

// wsFrame is one masked client frame.
func wsFrame(fin bool, opcode byte, payload string) []byte {
	key := [4]byte{0xA1, 0xB2, 0xC3, 0xD4}
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	out := []byte{b0}
	if n := len(payload); n <= 125 {
		out = append(out, 0x80|byte(n))
	} else {
		out = append(out, 0x80|126, byte(n>>8), byte(n))
	}
	out = append(out, key[:]...)
	for i := range len(payload) {
		out = append(out, payload[i]^key[i&3])
	}
	return out
}

func wsText(payload string) []byte { return wsFrame(true, 0x1, payload) }

// wsExchange is what one connection produced.
type wsExchange struct {
	toBackend  []byte      // the client bytes the backend received after the upgrade
	toClient   []byte      // what the client was sent after the 101
	extensions string      // the extension offer the backend saw
	status     int         // the answer to the upgrade request
	header     http.Header // and its headers
}

// wsRun opens a WebSocket through a WAF built from cfg, sends frames and
// returns what each side saw.
func wsRun(t *testing.T, cfg map[string]string, path string, frames ...[]byte) wsExchange {
	t.Helper()
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	wafCfg := parseWAFConfig(cfg)
	wafCfg.WafRules = store
	mw, err := WAF(wafCfg)
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	var ex wsExchange
	backendDone := make(chan struct{})
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(backendDone)
		ex.extensions = r.Header.Get("Sec-WebSocket-Extensions")
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		// Early bytes first, as the proxy reads them, then the connection.
		ex.toBackend, _ = io.ReadAll(io.MultiReader(io.LimitReader(rw.Reader, int64(rw.Reader.Buffered())), conn))
	})))
	t.Cleanup(srv.Close)

	client, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(client, "GET "+path+" HTTP/1.1\r\nHost: shop.example\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read the answer to the upgrade: %v", err)
	}
	// A 101 has no body; this closes the Body only, and the connection stays.
	defer func() { _ = resp.Body.Close() }()
	ex.status, ex.header = resp.StatusCode, resp.Header
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return ex
	}
	for _, f := range frames {
		if _, err := client.Write(f); err != nil {
			break // the gateway has already closed on an earlier frame
		}
	}
	_ = client.(*net.TCPConn).CloseWrite()
	ex.toClient, _ = io.ReadAll(br)
	<-backendDone
	return ex
}

var wsClosePolicy = []byte{0x88, 2, 0x03, 0xF0} // close, code 1008

// wsClosed reads the counter of connections closed for a reason.
func wsClosed(t *testing.T, reason string) float64 {
	t.Helper()
	c, err := telemetry.MiddlewareWAFWebSocketClosedTotal.GetMetricWithLabelValues("unknown", reason)
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestWebSocket_AttackInAMessageIsRefused(t *testing.T) {
	clean, attack := wsText(wsClean), wsText(wsAttack)
	before := wsClosed(t, "refused")
	ex := wsRun(t, map[string]string{keyWebSocketInspection: "true"}, "/ws", clean, attack, clean)

	if got := wsClosed(t, "refused") - before; got != 1 {
		t.Errorf("the closed-connection counter moved by %v, want 1", got)
	}

	if !bytes.Equal(ex.toBackend, clean) {
		t.Errorf("the backend received %d bytes, want only the first message (%d): %q", len(ex.toBackend), len(clean), ex.toBackend)
	}
	if !bytes.Equal(ex.toClient, wsClosePolicy) {
		t.Errorf("the client got %x, want a close frame with code 1008", ex.toClient)
	}
}

// The default, and the reason for the setting: without it the same message is
// relayed unread. If this test starts failing because the default changed,
// the upgrade notes and the blind-spot panel have to change with it.
func TestWebSocket_OffByDefault(t *testing.T) {
	attack := wsText(wsAttack)
	ex := wsRun(t, map[string]string{}, "/ws", attack)

	if !bytes.Equal(ex.toBackend, attack) {
		t.Errorf("with inspection off the backend received %q, want the message relayed", ex.toBackend)
	}
	if ex.extensions == "" {
		t.Error("with inspection off the client's extension offer was removed")
	}
}

// Split across frames the payload is still one message to the backend.
func TestWebSocket_FragmentedAttackIsRefused(t *testing.T) {
	half := len(wsAttack) / 2
	ex := wsRun(t, map[string]string{keyWebSocketInspection: "true"}, "/ws",
		wsFrame(false, 0x1, wsAttack[:half]), wsFrame(true, 0x0, wsAttack[half:]))

	if len(ex.toBackend) != 0 {
		t.Errorf("fragments of an attack reached the backend: %q", ex.toBackend)
	}
	if !bytes.Equal(ex.toClient, wsClosePolicy) {
		t.Errorf("the client got %x, want close 1008", ex.toClient)
	}
}

// A binary opcode is the client's choice and buys nothing.
func TestWebSocket_BinaryOpcodeIsJudgedToo(t *testing.T) {
	ex := wsRun(t, map[string]string{keyWebSocketInspection: "true"}, "/ws", wsFrame(true, 0x2, wsAttack))
	if len(ex.toBackend) != 0 {
		t.Errorf("an attack in a binary frame reached the backend: %q", ex.toBackend)
	}
}

func TestWebSocket_AuditOnlyRecordsAndRelays(t *testing.T) {
	attack := wsText(wsAttack)
	ex := wsRun(t, map[string]string{keyWebSocketInspection: "true", "audit_only": "true"}, "/ws", attack)

	if !bytes.Equal(ex.toBackend, attack) {
		t.Errorf("an audit-only route did not relay the message: backend got %q", ex.toBackend)
	}
	if len(ex.toClient) != 0 {
		t.Errorf("an audit-only route closed the connection: %x", ex.toClient)
	}
}

// A compressed message cannot be read, so the offer never reaches the backend.
func TestWebSocket_CompressionIsNotOffered(t *testing.T) {
	ex := wsRun(t, map[string]string{keyWebSocketInspection: "true"}, "/ws", wsText(wsClean))
	if ex.extensions != "" {
		t.Errorf("the backend was offered %q; an inspected connection must not negotiate an extension", ex.extensions)
	}
}

func TestWebSocket_MessagePastTheLimitClosesTheConnection(t *testing.T) {
	big := wsText(`{"pad":"` + strings.Repeat("a", 300) + `","q":"1' UNION SELECT password FROM users--"}`)
	ex := wsRun(t, map[string]string{keyWebSocketInspection: "true", keyWebSocketMessageLimit: "256"}, "/ws", big)

	if len(ex.toBackend) != 0 {
		t.Errorf("%d bytes of a message past the limit reached the backend", len(ex.toBackend))
	}
	if want := []byte{0x88, 2, 0x03, 0xF1}; !bytes.Equal(ex.toClient, want) {
		t.Errorf("the client got %x, want close 1009", ex.toClient)
	}
}

// A route with an OpenAPI document that is enforced: a message is not a
// request to the operation the document describes. It carries none of that
// operation's query parameters, and must not be refused for lacking a
// required one. This holds today because the engine requires only body
// members; the test is here for the day it requires query parameters too.
func TestWebSocket_MessagesAreNotHeldToTheRouteDocument(t *testing.T) {
	doc := `
openapi: 3.0.3
info: {title: Feed, version: "1"}
paths:
  /ws:
    get:
      parameters:
        - {name: room, in: query, required: true, schema: {type: integer}}
`
	cfg := map[string]string{keyWebSocketInspection: "true", keyOpenAPISpec: doc, keyOpenAPIMode: "enforce"}
	clean, attack := wsText(wsClean), wsText(wsAttack)

	ex := wsRun(t, cfg, "/ws?room=7", clean, attack)
	if ex.status != http.StatusSwitchingProtocols {
		t.Fatalf("the upgrade was answered %d", ex.status)
	}
	if !bytes.Equal(ex.toBackend, clean) {
		t.Errorf("the backend received %q, want the clean message and not the attack", ex.toBackend)
	}

	if refused := wsRun(t, cfg, "/ws?room=x"); refused.status != http.StatusForbidden {
		t.Errorf("the upgrade itself is still held to the document: got %d, want 403", refused.status)
	}
}

func TestWebSocketSettingChangesTheEngineKey(t *testing.T) {
	off := parseWAFConfig(map[string]string{})
	on := parseWAFConfig(map[string]string{keyWebSocketInspection: "true"})
	limited := parseWAFConfig(map[string]string{keyWebSocketInspection: "true", keyWebSocketMessageLimit: strconv.Itoa(1 << 10)})
	if off.Fingerprint() == on.Fingerprint() || on.Fingerprint() == limited.Fingerprint() {
		t.Error("two configs that differ in WebSocket inspection share a cached engine")
	}
	t.Setenv(webSocketInspectionEnv, "true")
	if !parseWAFConfig(map[string]string{}).InspectWebSocket {
		t.Errorf("%s did not turn inspection on for a route that sets nothing", webSocketInspectionEnv)
	}
	if !globalWAFConfig(&gateonv1.WafConfig{Enabled: true}, config.TierStandard, security.Deps{}).InspectWebSocket {
		t.Errorf("%s did not turn inspection on for the gateway-wide WAF, which has no other way to ask", webSocketInspectionEnv)
	}
	if parseWAFConfig(map[string]string{keyWebSocketInspection: "false"}).InspectWebSocket {
		t.Error("a route that says false was overridden by the environment")
	}
}
