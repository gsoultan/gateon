package kind

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
)

func TestIsInternalPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"v1 api", "/v1/routes", true},
		{"metrics", "/metrics", true},
		{"healthz", "/healthz", true},
		{"readyz", "/readyz", true},
		{"grpc health", "/grpc.health.v1.Health/Check", true},
		{"dashboard api", "/gateon.v1.ApiService/ListRoutes", true},
		{"dashboard ai", "/gateon.v1.AIService/Chat", true},
		{"user app api", "/v1/apps/documents", false},
		{"user employee api", "/v1/employees/home", false},
		{"proxied path", "/api/users", false},
		{"root", "/", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsInternalPath(tc.path); got != tc.want {
				t.Errorf("IsInternalPath(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestIsCorsPreflight(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		origin  string
		reqMeth string
		want    bool
	}{
		{"valid preflight", http.MethodOptions, "https://x.test", "POST", true},
		{"options no origin", http.MethodOptions, "", "POST", false},
		{"options no req method", http.MethodOptions, "https://x.test", "", false},
		{"get with headers", http.MethodGet, "https://x.test", "POST", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.reqMeth != "" {
				r.Header.Set("Access-Control-Request-Method", tc.reqMeth)
			}
			if got := IsCorsPreflight(r); got != tc.want {
				t.Errorf("IsCorsPreflight() = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestShouldSkipMetrics(t *testing.T) {
	tests := []struct {
		name    string
		mgmt    bool
		routeID string
		path    string
		want    bool
	}{
		{"management entrypoint", true, "", "/anything", true},
		{"gateon route internal path", false, "gateon-mgmt", "/v1/routes", true},
		{"gateon route proxy path", false, "gateon-mgmt", "/api/users", false},
		{"regular route", false, "my-route", "/v1/routes", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rs := &request.RequestState{
				IsManagement: tc.mgmt,
				RouteName:    tc.routeID,
			}
			ctx := context.WithValue(context.Background(), request.RequestStateContextKey{}, rs)
			r := httptest.NewRequest(http.MethodGet, tc.path, nil).WithContext(ctx)
			if got := ShouldSkipMetrics(r); got != tc.want {
				t.Errorf("ShouldSkipMetrics() = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestChainOrder(t *testing.T) {
	var order []string
	mk := func(label string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, label)
				next.ServeHTTP(w, r)
			})
		}
	}
	final := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "handler")
	})
	Chain(mk("a"), mk("b"), mk("c"))(final).ServeHTTP(
		httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"a", "b", "c", "handler"}
	if len(order) != len(want) {
		t.Fatalf("order = %v; want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v; want %v", order, want)
		}
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{200, "200"},
		{404, "404"},
		{599, "599"},
		{700, "700"}, // outside cached range, still correct
	}
	for _, tc := range tests {
		if got := StatusString(tc.code); got != tc.want {
			t.Errorf("StatusString(%d) = %q; want %q", tc.code, got, tc.want)
		}
	}
}

func TestStatusResponseWriterCapturesStatusAndBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := GetStatusResponseWriter(rec)
	defer PutStatusResponseWriter(sw)

	// Ensure a measurable, non-zero gap between writer creation (start) and the
	// first write so TTFB is deterministically > 0 regardless of monotonic-clock
	// resolution on fast machines.
	time.Sleep(time.Millisecond)
	sw.WriteHeader(http.StatusTeapot)
	n, err := sw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Fatalf("Write n = %d; want 5", n)
	}
	if sw.Status != http.StatusTeapot {
		t.Errorf("Status = %d; want %d", sw.Status, http.StatusTeapot)
	}
	if sw.BytesWritten != 5 {
		t.Errorf("BytesWritten = %d; want 5", sw.BytesWritten)
	}
	if sw.TTFB() <= 0 {
		t.Errorf("TTFB = %v; want > 0", sw.TTFB())
	}
}

func TestRecovery(t *testing.T) {
	t.Run("normal panic", func(t *testing.T) {
		h := Recovery()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		}))
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		// We expect Recovery to catch it and not crash the test
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("abort handler panic", func(t *testing.T) {
		h := Recovery()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(http.ErrAbortHandler)
		}))
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		defer func() {
			err := recover()
			if err != http.ErrAbortHandler {
				t.Errorf("expected http.ErrAbortHandler to be re-panicked, got %v", err)
			}
		}()

		h.ServeHTTP(rec, r)
	})

	t.Run("panic after header sent", func(t *testing.T) {
		h := Recovery()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := GetStatusResponseWriter(w)
			defer PutStatusResponseWriter(sw)
			sw.WriteHeader(http.StatusOK)
			panic("test panic after write")
		}))
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		// Should not panic, but also should not change status code because it's already sent
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})
}
