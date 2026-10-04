// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// redactSecret is in every credential these requests carry and in nothing
// else, so "did a credential survive?" is one substring search per record.
const redactSecret = "S3CRET"

// redactVisible are values that are not credentials, one from each place a
// credential was sent alongside them. Each must still be readable where it was
// recorded, or the redaction proved nothing but that the record is empty.
var redactVisible = []string{"visible-page", "visible-ref", "visible-user", "visible-json", "visible-response", "visible-waf"}

// lockedBuffer collects what several goroutines write.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestNoCredentialLeavesTheGatewayInWhatItRecords is ADR 0060 end to end, on
// the built binary: requests carrying credentials in headers, the query string
// and the body go through a route with the debugger on and a WAF that matches
// some of them, with alerts posted to a local webhook. No stored trace, stored
// threat, WAF audit line, webhook payload or log line may hold a credential
// value; the values around them must stay readable.
func TestNoCredentialLeavesTheGatewayInWhatItRecords(t *testing.T) {
	env := SetupTestEnv(t)
	sink, payloads := webhookSink(t)
	backend := redactBackend(t)
	writeRedactConfig(t, env, backend.URL, sink.URL)
	logs := startRedactGateway(t, env)

	sendCredentialedTraffic(t, fmt.Sprintf("http://127.0.0.1:%d", env.Ports["http_plain"]))

	client, ctx := redactAPIClient(t, env)
	traces := storedTraces(t, client, ctx)
	threats := storedThreats(t, client, ctx)
	if !waitFor(30*time.Second, func() bool { return strings.Contains(payloads.String(), "visible-waf") }) {
		t.Fatalf("no alert reached the webhook; payloads:\n%s", payloads.String())
	}
	audit := auditLog(t, env.Dir)

	for what, text := range map[string]string{
		"a stored trace": traces, "a stored threat": threats, "the WAF audit log": audit,
		"a webhook payload": payloads.String(), "the gateway's log": logs.String(),
	} {
		if i := strings.Index(text, redactSecret); i >= 0 {
			t.Errorf("%s carries a credential: ...%s...", what, text[max(0, i-200):min(len(text), i+100)])
		}
	}
	everything := traces + threats + audit + payloads.String()
	for _, v := range redactVisible {
		if !strings.Contains(everything, v) {
			t.Errorf("%q, which is not a credential, is recorded nowhere", v)
		}
	}
	if !strings.Contains(audit, `"matched_bytes_withheld":true`) {
		t.Errorf("no audit line says it withheld a match; the WAF never matched inside a credential:\n%s", audit)
	}
}

// webhookSink collects every alert posted to it.
func webhookSink(t *testing.T) (*httptest.Server, *lockedBuffer) {
	t.Helper()
	got := &lockedBuffer{}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = got.Write(append(body, '\n'))
	}))
	t.Cleanup(sink.Close)
	return sink, got
}

// redactBackend answers like a login API: a session cookie, a token in the
// body, and for /app/redirect an OAuth-style redirect carrying a code.
func redactBackend(t *testing.T) *httptest.Server {
	t.Helper()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/app/redirect" {
			http.Redirect(w, r, "/cb?code=LOC-S3CRET-0001&next=visible-page", http.StatusFound)
			return
		}
		w.Header().Set("Set-Cookie", "app_session=SETCK-S3CRET-0001; HttpOnly")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"RESPBODY-S3CRET-0001","note":"visible-response"}`)
	}))
	t.Cleanup(b.Close)
	return b
}

// writeRedactConfig replaces the shared e2e configuration with one route to
// the backend behind a WAF, the debugger on, and every alert to the sink.
func writeRedactConfig(t *testing.T, env *TestEnv, backendURL, sinkURL string) {
	t.Helper()
	files := map[string]string{
		"entrypoints.json": fmt.Sprintf(`[{"id":"http-plain","address":"127.0.0.1:%d","type":0,"protocol":0}]`, env.Ports["http_plain"]),
		"services.json": fmt.Sprintf(`[{"id":"redact-backend","name":"Redact Backend","weighted_targets":[{"url":%q}],`+
			`"load_balancer_policy":"round_robin","backend_type":"http"}]`, backendURL),
		"middlewares.json": `[{"id":"redact-waf","type":"waf","config":{"anomaly_threshold":"5","audit_only":"false","sqli":"true","xss":"true"}}]`,
		"routes.json": "[{\"id\":\"redact-route\",\"name\":\"Redaction\",\"type\":\"http\",\"rule\":\"PathPrefix(`/app`)\"," +
			"\"middlewares\":[\"redact-waf\"],\"service_id\":\"redact-backend\"}]",
		"global.json": fmt.Sprintf(`{
  "log": {"level": "info", "format": "text"},
  "auth": {"paseto_secret": "12345678901234567890123456789012", "database_url": %q},
  "management": {"bind": "127.0.0.1", "port": "%d", "allowed_ips": ["0.0.0.0/0", "::/0"]},
  "debugger": {"enabled": true, "max_body_size": 65536},
  "alerting": {"enabled": true,
    "dispatchers": [{"id": "sink", "name": "sink", "type": "webhook", "webhook_url": %q}],
    "playbooks": [{"id": "every", "name": "every threat", "event_type": "all", "threshold": 0, "dispatcher_ids": ["sink"], "action": "notify"}]},
  "anomaly_detection": {"check_interval_seconds": 3600, "sensitivity": 0.5, "security_threat_threshold": 999999},
  "profile": "standard"
}`, filepath.Join(env.Dir, "gateon_test.db"), env.Ports["mgmt"], sinkURL+"/hook"),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(env.Dir, "config", name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	authMgr, err := auth.NewManager(filepath.Join(env.Dir, "gateon_test.db"), "12345678901234567890123456789012", logger.Default())
	if err != nil {
		t.Fatalf("init auth: %v", err)
	}
	defer authMgr.Close()
	if err := authMgr.UpsertUser(&gateonv1.User{Username: "admin", Password: "e2e-horse-battery-42", Role: "admin"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
}

// startRedactGateway runs the built gateway and returns what it logs.
func startRedactGateway(t *testing.T, env *TestEnv) *lockedBuffer {
	t.Helper()
	projectRoot, _ := filepath.Abs("../..")
	cmd := exec.Command(env.BinaryPath)
	cmd.Dir = projectRoot
	cmd.Env = env.GatewayEnv(
		"GLOBAL_CONFIG_FILE="+filepath.Join(env.Dir, "config/global.json"),
		"ROUTES_FILE="+filepath.Join(env.Dir, "config/routes.json"),
		"SERVICES_FILE="+filepath.Join(env.Dir, "config/services.json"),
		"ENTRYPOINTS_FILE="+filepath.Join(env.Dir, "config/entrypoints.json"),
		"MIDDLEWARES_FILE="+filepath.Join(env.Dir, "config/middlewares.json"),
		"TLS_OPTIONS_FILE="+filepath.Join(env.Dir, "config/tls_options.json"),
		fmt.Sprintf("GATEON_MANAGEMENT_PORT=%d", env.Ports["mgmt"]),
	)
	logs := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	waitForPort(t, env.Ports["http_plain"])
	waitForPort(t, env.Ports["mgmt"])
	return logs
}

// sendCredentialedTraffic sends the requests whose records the test reads.
func sendCredentialedTraffic(t *testing.T, base string) {
	t.Helper()
	sqli := url.QueryEscape("' UNION SELECT password FROM users--")
	reqs := []*http.Request{
		redactReq(t, http.MethodGet, base+"/app/profile?api_key=QRY-S3CRET-0001&access_token=QRY-S3CRET-0002"+
			"&code=QRY-S3CRET-0003&state=QRY-S3CRET-0004&password=QRY-S3CRET-0005&page=visible-page", "", "",
			"Authorization", "Bearer HDR-S3CRET-0001", "Cookie", "sid=HDR-S3CRET-0002", "X-Api-Key", "HDR-S3CRET-0003",
			"Referer", "http://ref.example/?token=REF-S3CRET-0001&from=visible-ref"),
		redactReq(t, http.MethodPost, base+"/app/login", "application/x-www-form-urlencoded",
			"user=visible-user&password=BODY-S3CRET-0001"),
		redactReq(t, http.MethodPost, base+"/app/login", "application/json",
			`{"username":"visible-json","password":"BODY-S3CRET-0002","api_key":"BODY-S3CRET-0003"}`),
		redactReq(t, http.MethodGet, base+"/app/redirect?page=visible-page", "", ""),
		// The WAF matches inside a cookie, a bearer token and a token parameter.
		redactReq(t, http.MethodGet, base+"/app/search?page=visible-waf", "", "",
			"Cookie", "sid=WAFC-S3CRET-0001"+"' UNION SELECT password FROM users--"),
		redactReq(t, http.MethodGet, base+"/app/search?page=visible-waf", "", "",
			"Authorization", "Bearer WAFA-S3CRET-0001' UNION SELECT password FROM users--"),
		redactReq(t, http.MethodGet, base+"/app/search?page=visible-waf&token=WAFQ-S3CRET-0001"+sqli, "", ""),
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for _, r := range reqs {
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("%s %s: %v", r.Method, r.URL.Path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// redactReq builds a request with a body and header pairs.
func redactReq(t *testing.T, method, target, contentType, body string, header ...string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36")
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	return r
}

// redactAPIClient signs in to the management API.
func redactAPIClient(t *testing.T, env *TestEnv) (gateonv1.ApiServiceClient, context.Context) {
	t.Helper()
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", env.Ports["mgmt"]), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := gateonv1.NewApiServiceClient(conn)
	login, err := client.Login(t.Context(), &gateonv1.LoginRequest{Username: "admin", Password: "e2e-horse-battery-42"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return client, metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+login.Token))
}

// storedTraces returns every stored trace in full, as the API serves it,
// once the debugger-captured login bodies are among them.
func storedTraces(t *testing.T, client gateonv1.ApiServiceClient, ctx context.Context) string {
	t.Helper()
	var all string
	ok := waitFor(30*time.Second, func() bool {
		list, err := client.ListTraces(ctx, &gateonv1.ListTracesRequest{Limit: 100})
		if err != nil {
			return false
		}
		var b strings.Builder
		for _, tr := range list.Traces {
			full, err := client.GetTrace(ctx, &gateonv1.GetTraceRequest{Id: tr.Id, Timestamp: tr.Timestamp})
			if err != nil {
				return false
			}
			b.WriteString(protojson.Format(full) + "\n")
		}
		all = b.String()
		return strings.Contains(all, "visible-user") && strings.Contains(all, "visible-json") && strings.Contains(all, "visible-ref")
	})
	if !ok {
		t.Fatalf("the traces of the credentialed requests were not stored:\n%s", all)
	}
	return all
}

// storedThreats returns every stored threat in full once the WAF's are there.
func storedThreats(t *testing.T, client gateonv1.ApiServiceClient, ctx context.Context) string {
	t.Helper()
	var all string
	ok := waitFor(30*time.Second, func() bool {
		list, err := client.ListSecurityThreats(ctx, &gateonv1.ListSecurityThreatsRequest{Limit: 100})
		if err != nil {
			return false
		}
		var b strings.Builder
		for _, th := range list.Threats {
			full, err := client.GetSecurityThreat(ctx, &gateonv1.GetSecurityThreatRequest{Id: th.Id})
			if err != nil {
				return false
			}
			b.WriteString(protojson.Format(full) + "\n")
		}
		all = b.String()
		return strings.Count(all, "visible-waf") >= 3
	})
	if !ok {
		t.Fatalf("the WAF's threats were not stored:\n%s", all)
	}
	return all
}

// auditLog returns every WAF audit line the gateway wrote.
func auditLog(t *testing.T, dataDir string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dataDir, "audit", "waf", "*.log"))
	var b strings.Builder
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		b.Write(raw)
	}
	if b.Len() == 0 {
		t.Fatalf("no WAF audit log under %s", dataDir)
	}
	return b.String()
}
