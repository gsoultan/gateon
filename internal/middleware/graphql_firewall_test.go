package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGraphQLFirewall_Depth(t *testing.T) {
	cfg := GraphQLFirewallConfig{
		MaxDepth: 2,
	}
	mw := GraphQLFirewall(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Valid Depth", func(t *testing.T) {
		query := `{"query": "{ user { name } }"}`
		req := httptest.NewRequest("POST", "/graphql", bytes.NewBufferString(query))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected OK, got %d", rec.Code)
		}
	})

	t.Run("Invalid Depth", func(t *testing.T) {
		query := `{"query": "{ user { profile { bio } } }"}`
		req := httptest.NewRequest("POST", "/graphql", bytes.NewBufferString(query))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected Forbidden, got %d", rec.Code)
		}
	})
}
