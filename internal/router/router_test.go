package router

import (
	"context"
	"net/http"
	"testing"

	"github.com/gateon/gateon/internal/middleware"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

func TestHostMatches(t *testing.T) {
	tests := []struct {
		name      string
		routeHost string
		reqHost   string
		want      bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"case insensitive", "Example.Com", "example.com", true},
		{"strip port", "example.com", "example.com:8080", true},
		{"wildcard match", "*.example.com", "api.example.com", true},
		{"wildcard no match", "*.example.com", "example.com", false},
		{"wildcard mismatch", "*.example.com", "other.com", false},
		{"empty route host", "", "anything.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HostMatches(tt.routeHost, tt.reqHost); got != tt.want {
				t.Errorf("HostMatches(%s, %s) = %v, want %v", tt.routeHost, tt.reqHost, got, tt.want)
			}
		})
	}
}

func TestSelectRoute_RuleBased(t *testing.T) {
	routes := []*gateonv1.Route{
		{
			Id:       "low-prio",
			Rule:     "Host(`example.com`)",
			Priority: 1,
		},
		{
			Id:       "high-prio",
			Rule:     "Host(`example.com`)",
			Priority: 10,
		},
		{
			Id:       "specific-rule",
			Rule:     "Host(`example.com`) && PathPrefix(`/api`)",
			Priority: 10, // Same priority as high-prio, but longer/more specific rule
		},
		{
			Id:       "exact-path",
			Rule:     "Path(`/health`)",
			Priority: 20,
		},
	}

	tests := []struct {
		name     string
		host     string
		path     string
		expected string
	}{
		{"priority wins", "example.com", "/", "high-prio"},
		{"longest rule wins on tie", "example.com", "/api/v1", "specific-rule"},
		{"exact path matching", "any.com", "/health", "exact-path"},
		{"no match", "other.com", "/unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://"+tt.host+tt.path, nil)
			got := SelectRoute(req, routes)
			if tt.expected == "" {
				if got != nil {
					t.Errorf("expected nil, got %s", got.Id)
				}
			} else {
				if got == nil || got.Id != tt.expected {
					gotId := "nil"
					if got != nil {
						gotId = got.Id
					}
					t.Errorf("expected %s, got %s", tt.expected, gotId)
				}
			}
		})
	}
}

func TestSelectRoute_EntryPoints(t *testing.T) {
	routes := []*gateonv1.Route{
		{
			Id:          "web-only",
			Rule:        "Host(`example.com`)",
			Entrypoints: []string{"http-80"},
		},
		{
			Id:          "secure-only",
			Rule:        "Host(`example.com`)",
			Entrypoints: []string{"https-443"},
		},
		{
			Id:          "global",
			Rule:        "Path(`/ping`)",
			Entrypoints: []string{}, // Available on all
		},
	}

	t.Run("match web entrypoint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "http-80")
		got := SelectRoute(req.WithContext(ctx), routes)
		if got == nil || got.Id != "web-only" {
			t.Errorf("expected web-only, got %v", got)
		}
	})

	t.Run("match secure entrypoint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "https-443")
		got := SelectRoute(req.WithContext(ctx), routes)
		if got == nil || got.Id != "secure-only" {
			t.Errorf("expected secure-only, got %v", got)
		}
	})

	t.Run("global route matches any entrypoint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://any.com/ping", nil)
		ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "random-ep")
		got := SelectRoute(req.WithContext(ctx), routes)
		if got == nil || got.Id != "global" {
			t.Errorf("expected global, got %v", got)
		}
	})

	t.Run("no match on mismatched entrypoint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "internal-ep")
		got := SelectRoute(req.WithContext(ctx), routes)
		if got != nil {
			t.Errorf("expected nil, got %s", got.Id)
		}
	})
}
