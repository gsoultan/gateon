package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func sampleEvent() Event {
	return Event{
		Time:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Kind:     KindIncident,
		Name:     "correlated_incident",
		Severity: "high",
		SourceIP: "203.0.113.7",
		Message:  "3 correlated signals",
		Fields:   map[string]string{"mitre": "T1110,T1190", "signal_count": "3"},
	}
}

func TestJSONFormatter(t *testing.T) {
	out := jsonFormatter{}.format(sampleEvent())
	if len(out) == 0 || out[len(out)-1] != '\n' {
		t.Fatal("json output must be newline-terminated")
	}
	var decoded Event
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("json output not parseable: %v", err)
	}
	if decoded.SourceIP != "203.0.113.7" || decoded.Severity != "high" {
		t.Fatalf("unexpected decoded event: %+v", decoded)
	}
}

func TestCEFFormatter(t *testing.T) {
	out := string(cefFormatter{version: "1.2.3"}.format(sampleEvent()))
	if !strings.HasPrefix(out, "CEF:0|JetBrains|Gateon|1.2.3|incident|correlated_incident|8|") {
		t.Fatalf("unexpected CEF header: %q", out)
	}
	if !strings.Contains(out, "src=203.0.113.7") {
		t.Fatalf("CEF should contain source IP: %q", out)
	}
	if !strings.Contains(out, "cs_mitre=T1110,T1190") {
		t.Fatalf("CEF should carry mitre field: %q", out)
	}
}

func TestCEFEscaping(t *testing.T) {
	e := Event{Kind: KindThreat, Name: "pipe|name", Severity: "low",
		Fields: map[string]string{"k": "a=b"}}
	out := string(cefFormatter{}.format(e))
	if !strings.Contains(out, `pipe\|name`) {
		t.Fatalf("pipe in header not escaped: %q", out)
	}
	if !strings.Contains(out, `cs_k=a\=b`) {
		t.Fatalf("equals in value not escaped: %q", out)
	}
}

func TestSyslogFormatter(t *testing.T) {
	out := string(syslogFormatter{version: "1.0", hostname: "host1"}.format(sampleEvent()))
	// high severity -> facility local0 (16)*8 + 3 = 131
	if !strings.HasPrefix(out, "<131>1 ") {
		t.Fatalf("unexpected syslog PRI: %q", out)
	}
	if !strings.Contains(out, "host1 Gateon") {
		t.Fatalf("syslog should contain host and app: %q", out)
	}
	if !strings.Contains(out, `[gateon@0 `) || !strings.Contains(out, `severity="high"`) {
		t.Fatalf("syslog structured data malformed: %q", out)
	}
	if out[len(out)-1] != '\n' {
		t.Fatal("syslog output must be newline-terminated")
	}
}

func TestSeverityMaps(t *testing.T) {
	tests := []struct {
		sev    string
		cef    int
		syslog int
	}{
		{"critical", 10, 2},
		{"high", 8, 3},
		{"medium", 5, 4},
		{"low", 2, 5},
		{"", 3, 6},
	}
	for _, tc := range tests {
		t.Run(tc.sev, func(t *testing.T) {
			if got := cefSeverity(tc.sev); got != tc.cef {
				t.Errorf("cefSeverity(%q)=%d want %d", tc.sev, got, tc.cef)
			}
			if got := syslogSeverity(tc.sev); got != tc.syslog {
				t.Errorf("syslogSeverity(%q)=%d want %d", tc.sev, got, tc.syslog)
			}
		})
	}
}

func TestNewDisabled(t *testing.T) {
	if _, err := New(Config{Enabled: false}); err != ErrDisabled {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
	if _, err := New(Config{Enabled: true, Endpoint: ""}); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
	if _, err := New(Config{Enabled: true, Endpoint: "x", Transport: "carrier-pigeon"}); err == nil {
		t.Fatal("expected error for unsupported transport")
	}
}

func TestShipperHTTPDelivery(t *testing.T) {
	var (
		mu       sync.Mutex
		received []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, string(body))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := New(Config{
		Enabled:   true,
		Format:    FormatJSON,
		Transport: "http",
		Endpoint:  srv.URL,
		Token:     "secret",
		QueueSize: 64,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Ship(sampleEvent())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().Shipped >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stats := s.Stats()
	if stats.Shipped != 1 {
		t.Fatalf("Shipped = %d, want 1 (stats=%+v)", stats.Shipped, stats)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || !strings.Contains(received[0], "203.0.113.7") {
		t.Fatalf("collector received %v", received)
	}
}

func TestShipperDropsOnOverflow(t *testing.T) {
	// No Run goroutine, tiny queue: enqueues beyond capacity must be dropped.
	s, err := New(Config{Enabled: true, Endpoint: "http://127.0.0.1:0", QueueSize: minQueueSize})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for range minQueueSize + 50 {
		s.Ship(sampleEvent())
	}
	stats := s.Stats()
	if stats.Dropped == 0 {
		t.Fatalf("expected some dropped events, got %+v", stats)
	}
	if stats.Enqueued+stats.Dropped != int64(minQueueSize+50) {
		t.Fatalf("enqueued+dropped mismatch: %+v", stats)
	}
}

func TestNilShipperSafe(t *testing.T) {
	var s *Shipper
	s.Ship(sampleEvent()) // must not panic
	if got := s.Stats(); got != (Stats{}) {
		t.Fatalf("nil shipper stats = %+v, want zero", got)
	}
}
