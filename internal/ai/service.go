package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// AIService implements the gateon.v1.AIServiceServer interface.
type AIService struct {
	gateonv1.UnimplementedAIServiceServer
	globalStore  config.GlobalConfigStore
	routeStore   config.RouteStore
	serviceStore config.ServiceStore
	httpClient   *http.Client
}

// NewAIService creates a new AI service.
func NewAIService(globals config.GlobalConfigStore, routes config.RouteStore, services config.ServiceStore) *AIService {
	return &AIService{
		globalStore:  globals,
		routeStore:   routes,
		serviceStore: services,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// AnalyzeConfig analyzes the current configuration and provides insights.
func (s *AIService) AnalyzeConfig(ctx context.Context, req *gateonv1.AnalyzeConfigRequest) (*gateonv1.AnalyzeConfigResponse, error) {
	conf := s.globalStore.Get(ctx)
	if conf.Ai == nil || !conf.Ai.Enabled {
		return nil, errors.New("AI service is not enabled in global configuration")
	}

	// Redact sensitive configuration before sending to AI provider.
	redactedGlobal := redactConfig(conf)

	// Gather configuration context.
	routes, _ := s.routeStore.ListPaginated(ctx, 0, 100, "", nil)
	services, _ := s.serviceStore.ListPaginated(ctx, 0, 100, "")

	configJSON, _ := json.MarshalIndent(map[string]any{
		"global":   redactedGlobal,
		"routes":   routes,
		"services": services,
	}, "", "  ")

	prompt := fmt.Sprintf(`You are an expert API Gateway administrator for Gateon. 
Analyze the following configuration and provide performance, security, and availability insights.
Format your response as a JSON object with "summary" (string) and "insights" (array of objects with "title", "description", "severity", "category", "recommendation").
Severity must be "info", "warning", or "critical". Category must be "security", "performance", or "availability".

Configuration:
%s`, string(configJSON))

	return s.callLLM(ctx, prompt)
}

func redactConfig(conf *gateonv1.GlobalConfig) *gateonv1.GlobalConfig {
	if conf == nil {
		return nil
	}
	redacted := proto.Clone(conf).(*gateonv1.GlobalConfig)
	if redacted.Auth != nil {
		redacted.Auth.PasetoSecret = "[REDACTED]"
		redacted.Auth.DatabaseUrl = "[REDACTED]"
		if redacted.Auth.DatabaseConfig != nil {
			redacted.Auth.DatabaseConfig.Password = "[REDACTED]"
		}
	}
	if redacted.Ai != nil {
		redacted.Ai.ApiKey = "[REDACTED]"
	}
	if redacted.Redis != nil {
		redacted.Redis.Password = "[REDACTED]"
	}
	if redacted.Ha != nil {
		redacted.Ha.AuthPass = "[REDACTED]"
	}
	if redacted.Tls != nil && redacted.Tls.Acme != nil {
		redacted.Tls.Acme.DnsConfig = nil
	}
	return redacted
}

// ChatWithAI allows interactive chat with the AI about the gateway.
func (s *AIService) ChatWithAI(ctx context.Context, req *gateonv1.ChatWithAIRequest) (*gateonv1.ChatWithAIResponse, error) {
	conf := s.globalStore.Get(ctx)
	if conf.Ai == nil || !conf.Ai.Enabled {
		return nil, errors.New("AI service is not enabled")
	}

	prompt := fmt.Sprintf("User Question: %s\n\nProvide a helpful answer based on Gateon gateway best practices.", req.Message)
	resp, err := s.callLLM(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return &gateonv1.ChatWithAIResponse{
		Reply: resp.Summary,
	}, nil
}

func (s *AIService) callLLM(ctx context.Context, prompt string) (*gateonv1.AnalyzeConfigResponse, error) {
	conf := s.globalStore.Get(ctx).Ai

	switch conf.Provider {
	case "openai":
		return s.callOpenAI(ctx, conf, prompt)
	case "anthropic":
		return s.callAnthropic(ctx, conf, prompt)
	default:
		// Fallback for demonstration if no key is provided.
		if conf.ApiKey == "" {
			resp, _ := s.mockResponse()
			return resp, nil
		}
		return nil, fmt.Errorf("unsupported AI provider: %s", conf.Provider)
	}
}

func (s *AIService) callOpenAI(ctx context.Context, conf *gateonv1.AIConfig, prompt string) (*gateonv1.AnalyzeConfigResponse, error) {
	url := "https://api.openai.com/v1/chat/completions"
	if conf.BaseUrl != "" {
		url = conf.BaseUrl
	}

	model := "gpt-4o"
	if conf.Model != "" {
		model = conf.Model
	}

	payload := map[string]any{
		"model": model,
		"messages": []any{
			map[string]string{"role": "system", "content": "You are a Gateon API Gateway expert."},
			map[string]string{"role": "user", "content": prompt},
		},
		"response_format": map[string]string{"type": "json_object"},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+conf.ApiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call OpenAI: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API returned status %d", resp.StatusCode)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Choices) == 0 {
		return nil, errors.New("no response from OpenAI")
	}

	var aiResp gateonv1.AnalyzeConfigResponse
	if err := json.Unmarshal([]byte(result.Choices[0].Message.Content), &aiResp); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	return &aiResp, nil
}

func (s *AIService) callAnthropic(ctx context.Context, conf *gateonv1.AIConfig, prompt string) (*gateonv1.AnalyzeConfigResponse, error) {
	// Implementation for Anthropic...
	return nil, errors.New("Anthropic provider not yet implemented")
}

func (s *AIService) mockResponse() (*gateonv1.AnalyzeConfigResponse, error) {
	return &gateonv1.AnalyzeConfigResponse{
		Summary: "Configuration looks good, but there are some areas for improvement in security and performance.",
		Insights: []*gateonv1.AIInsight{
			{
				Title:          "Enable mTLS for sensitive backends",
				Description:    "Some of your services are using plain HTTP. For production, mutual TLS is recommended.",
				Severity:       "warning",
				Category:       "security",
				Recommendation: "Update your Service configurations to include client certificates.",
			},
			{
				Title:          "Optimize Rate Limiting",
				Description:    "Your default rate limits might be too high for the current backend capacity.",
				Severity:       "info",
				Category:       "performance",
				Recommendation: "Consider reducing the 'requests_per_second' in your global or route-specific rate limiters.",
			},
		},
	}, nil
}
