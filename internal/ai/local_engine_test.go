package ai

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestLocalInsightEngine(t *testing.T) {
	globals := &gateonv1.GlobalConfig{
		Management: &gateonv1.ManagementConfig{
			Bind: "0.0.0.0",
		},
		Waf: &gateonv1.WafConfig{
			Enabled: false,
		},
		Tls: &gateonv1.TlsConfig{
			Enabled:       true,
			MinTlsVersion: "TLS1.0",
		},
	}

	routes := []*gateonv1.Route{
		{Id: "r1", Middlewares: []string{}},
	}

	services := []*gateonv1.Service{
		{
			Id:   "s1",
			Name: "test-service",
			WeightedTargets: []*gateonv1.Target{
				{Url: "http://localhost:8080"},
			},
		},
	}

	middlewares := []*gateonv1.Middleware{}

	engine := NewLocalInsightEngine(globals, routes, services, middlewares, nil)
	insights, _ := engine.Analyze(t.Context())

	// Expecting:
	// 1. Management bind 0.0.0.0
	// 2. Unprotected routes
	// 3. WAF disabled
	// 4. Insecure TLS
	// 5. Redis disabled
	// 6. Single point of failure
	// 7. Missing health checks
	// 8. No compression

	expectedInsights := 8
	if len(insights) < expectedInsights {
		t.Errorf("expected at least %d insights, got %d", expectedInsights, len(insights))
	}

	foundManagement := false
	for _, insight := range insights {
		if insight.Title == "Management API exposed on all interfaces" {
			foundManagement = true
			break
		}
	}

	if !foundManagement {
		t.Error("expected management API insight not found")
	}
}

func TestLocalInsightEngine_Logs(t *testing.T) {
	engine := NewLocalInsightEngine(nil, nil, nil, nil, nil)
	logs := []string{
		"ERROR: failed to connect to upstream",
		"WAF: blocked request from 1.2.3.4",
		"INFO: request processed",
	}

	analysis, insights := engine.AnalyzeLogs(logs)

	if len(insights) == 0 {
		t.Error("expected insights for logs, got none")
	}

	foundWaf := false
	for _, insight := range insights {
		if insight.Title == "Active WAF blocking" {
			foundWaf = true
			break
		}
	}

	if !foundWaf {
		t.Error("expected WAF log insight not found")
	}

	if analysis == "" {
		t.Error("expected analysis text, got empty")
	}
}
