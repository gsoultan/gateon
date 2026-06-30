package api

import (
	"context"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/stretchr/testify/assert"
)

type mockRouteStore struct {
	config.RouteStore
	routes []*gateonv1.Route
}

func (m *mockRouteStore) List(ctx context.Context) []*gateonv1.Route {
	return m.routes
}

type mockMiddlewareStore struct {
	config.MiddlewareStore
	middlewares map[string]*gateonv1.Middleware
}

func (m *mockMiddlewareStore) Get(ctx context.Context, id string) (*gateonv1.Middleware, bool) {
	mw, ok := m.middlewares[id]
	return mw, ok
}

func TestValidateCORS(t *testing.T) {
	ctx := context.Background()

	mw := &gateonv1.Middleware{
		Id:   "mw1",
		Name: "cors-mw",
		Type: "cors",
		Config: map[string]string{
			"allowed_origins": "https://example.com",
			"allowed_methods": "GET,POST",
			"allowed_headers": "Content-Type,X-Allowed",
		},
	}

	rt := &gateonv1.Route{
		Id:          "rt1",
		Name:        "test-route",
		Rule:        "Path(`/api/test`)",
		Middlewares: []string{"mw1"},
	}

	rtHost := &gateonv1.Route{
		Id:          "rt2",
		Name:        "host-route",
		Rule:        "Host(`api.example.com`)",
		Middlewares: []string{"mw1"},
		Entrypoints: []string{"http"},
	}

	mwAuth := &gateonv1.Middleware{
		Id:   "mwAuth",
		Name: "auth-mw",
		Type: "auth",
		Config: map[string]string{
			"type": "jwt",
		},
	}

	apiSvc := &ApiService{
		Routes:      &mockRouteStore{routes: []*gateonv1.Route{rt, rtHost}},
		Middlewares: &mockMiddlewareStore{middlewares: map[string]*gateonv1.Middleware{"mw1": mw, "mwAuth": mwAuth}},
	}

	tests := []struct {
		name     string
		req      *gateonv1.ValidateCORSRequest
		expected bool
		message  string
	}{
		{
			name: "Allowed Origin and Method",
			req: &gateonv1.ValidateCORSRequest{
				Url:    "http://gateon/api/test",
				Origin: "https://example.com",
				Method: "POST",
			},
			expected: true,
		},
		{
			name: "Blocked Origin",
			req: &gateonv1.ValidateCORSRequest{
				Url:    "http://gateon/api/test",
				Origin: "https://evil.com",
				Method: "POST",
			},
			expected: false,
			message:  "Origin 'https://evil.com' is not allowed",
		},
		{
			name: "Preflight Allowed",
			req: &gateonv1.ValidateCORSRequest{
				Url:    "http://gateon/api/test",
				Origin: "https://example.com",
				Method: "OPTIONS",
				Headers: map[string]string{
					"Access-Control-Request-Method":  "POST",
					"Access-Control-Request-Headers": "Content-Type",
				},
			},
			expected: true,
		},
		{
			name: "Preflight Blocked Method",
			req: &gateonv1.ValidateCORSRequest{
				Url:    "http://gateon/api/test",
				Origin: "https://example.com",
				Method: "OPTIONS",
				Headers: map[string]string{
					"Access-Control-Request-Method": "DELETE",
				},
			},
			expected: false,
			message:  "Method 'DELETE' is not allowed",
		},
		{
			name: "Exposed Headers and Max Age",
			req: &gateonv1.ValidateCORSRequest{
				Url:    "http://gateon/api/test",
				Origin: "https://example.com",
				Method: "OPTIONS",
				Headers: map[string]string{
					"Access-Control-Request-Method": "POST",
				},
			},
			expected: true,
		},
		{
			name: "Host Route with Entrypoints",
			req: &gateonv1.ValidateCORSRequest{
				Url:    "http://api.example.com/some/path",
				Origin: "https://example.com",
				Method: "GET",
			},
			expected: true,
		},
		{
			name: "Bearer Token and Suggestions",
			req: &gateonv1.ValidateCORSRequest{
				Url:             "http://gateon/api/test",
				Origin:          "https://example.com",
				Method:          "GET",
				AuthBearerToken: "my-token",
			},
			expected: true,
		},
		{
			name: "Missing Bearer Token Suggestion",
			req: &gateonv1.ValidateCORSRequest{
				Url:    "http://gateon/api/test",
				Origin: "https://example.com",
				Method: "GET",
			},
			expected: true,
		},
	}

	// Attach auth middleware to rt
	rt.Middlewares = append(rt.Middlewares, "mwAuth")

	// Update mw with exposed headers and max age for the last test case
	mw.Config["exposed_headers"] = "X-Custom-Response"
	mw.Config["max_age"] = "3600"

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := apiSvc.ValidateCORS(ctx, tc.req)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, resp.IsAllowed)
			if tc.message != "" {
				assert.Contains(t, resp.Message, tc.message)
			}
			if tc.name == "Exposed Headers and Max Age" {
				assert.Equal(t, "X-Custom-Response", resp.ResponseHeaders["Access-Control-Expose-Headers"])
				assert.Equal(t, "3600", resp.ResponseHeaders["Access-Control-Max-Age"])
			}
			if tc.name == "Bearer Token and Suggestions" {
				// Should not have the suggestion if token provided
				for _, s := range resp.Suggestions {
					assert.NotContains(t, s, "Authorization")
				}
			}
			if tc.name == "Missing Bearer Token Suggestion" {
				assert.NotEmpty(t, resp.Suggestions)
				assert.Contains(t, resp.Suggestions[0], "Bearer Token")
			}
		})
	}
}
