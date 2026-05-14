package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
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
	mwStore      config.MiddlewareStore
	epStore      config.EntryPointStore
	httpClient   *http.Client
}

// NewAIService creates a new AI service.
func NewAIService(globals config.GlobalConfigStore, routes config.RouteStore, services config.ServiceStore, mws config.MiddlewareStore, eps config.EntryPointStore) *AIService {
	return &AIService{
		globalStore:  globals,
		routeStore:   routes,
		serviceStore: services,
		mwStore:      mws,
		epStore:      eps,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// AnalyzeConfig analyzes the current configuration and provides insights.
func (s *AIService) AnalyzeConfig(ctx context.Context, req *gateonv1.AnalyzeConfigRequest) (*gateonv1.AnalyzeConfigResponse, error) {
	conf := s.globalStore.Get(ctx)

	// Gather configuration context.
	routes, _ := s.routeStore.ListPaginated(ctx, 0, 100, "", nil)
	services, _ := s.serviceStore.ListPaginated(ctx, 0, 100, "")
	middlewares, _ := s.mwStore.ListPaginated(ctx, 0, 100, "")
	entrypoints, _ := s.epStore.ListPaginated(ctx, 0, 100, "")

	// Gateon uses a deterministic Smart Engine for security analysis.
	// This provides instant, reliable insights without external dependencies.
	engine := NewLocalInsightEngine(conf, routes, services, middlewares, entrypoints)
	insights, summary := engine.Analyze(ctx)
	return &gateonv1.AnalyzeConfigResponse{
		Insights: insights,
		Summary:  summary,
	}, nil
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
	return &gateonv1.ChatWithAIResponse{
		Reply: "Interactive AI Chat is currently disabled. Gateon uses a local deterministic Smart Engine for security and configuration analysis to ensure maximum privacy and performance.",
	}, nil
}

// AnalyzeLogs analyzes gateway logs for issues.
func (s *AIService) AnalyzeLogs(ctx context.Context, req *gateonv1.AnalyzeLogsRequest) (*gateonv1.AnalyzeLogsResponse, error) {
	conf := s.globalStore.Get(ctx)

	// Gateon uses a deterministic Smart Engine for log analysis.
	engine := NewLocalInsightEngine(conf, nil, nil, nil, nil)
	analysis, insights := engine.AnalyzeLogs(req.Logs)
	return &gateonv1.AnalyzeLogsResponse{
		Analysis: analysis,
		Insights: insights,
	}, nil
}

func (s *AIService) callLLM(ctx context.Context, prompt string, target any) error {
	conf := s.globalStore.Get(ctx).Ai

	switch conf.Provider {
	case "openai":
		return s.callOpenAI(ctx, conf, prompt, target)
	case "anthropic":
		return s.callAnthropic(ctx, conf, prompt, target)
	default:
		// Fallback for demonstration if no key is provided.
		if conf.ApiKey == "" {
			mock, _ := s.mockResponse()
			if ar, ok := target.(*gateonv1.AnalyzeConfigResponse); ok {
				*ar = *mock
				return nil
			}
			if al, ok := target.(*gateonv1.AnalyzeLogsResponse); ok {
				al.Analysis = "Mock analysis: Everything looks normal in the logs."
				al.Insights = mock.Insights
				return nil
			}
			// For ChatWithAI local struct
			val := reflect.ValueOf(target)
			if val.Kind() == reflect.Ptr && val.Elem().Kind() == reflect.Struct {
				f := val.Elem().FieldByName("Summary")
				if f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
					f.SetString("I am currently in mock mode. Please configure an AI API key to get real answers.")
				}
			}
			return nil
		}
		return fmt.Errorf("unsupported AI provider: %s", conf.Provider)
	}
}

func (s *AIService) callOpenAI(ctx context.Context, conf *gateonv1.AIConfig, prompt string, target any) error {
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
		return fmt.Errorf("failed to call OpenAI at %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("OpenAI API at %s returned status %d: %v", url, resp.StatusCode, errResp)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if len(result.Choices) == 0 {
		return errors.New("no response from OpenAI")
	}

	if err := json.Unmarshal([]byte(result.Choices[0].Message.Content), target); err != nil {
		return fmt.Errorf("failed to parse AI response: %w", err)
	}

	return nil
}

func (s *AIService) callAnthropic(ctx context.Context, conf *gateonv1.AIConfig, prompt string, target any) error {
	// Simple implementation for Anthropic Claude 3
	url := "https://api.anthropic.com/v1/messages"
	if conf.BaseUrl != "" {
		url = conf.BaseUrl
	}

	model := "claude-3-5-sonnet-20240620"
	if conf.Model != "" {
		model = conf.Model
	}

	payload := map[string]any{
		"model":      model,
		"max_tokens": 4096,
		"system":     "You are a Gateon API Gateway expert. Always respond with valid JSON.",
		"messages": []any{
			map[string]string{"role": "user", "content": prompt},
		},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", conf.ApiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call Anthropic at %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("Anthropic API at %s returned status %d: %v", url, resp.StatusCode, errResp)
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
			Type string `json:"type"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if len(result.Content) == 0 {
		return errors.New("no response from Anthropic")
	}

	if err := json.Unmarshal([]byte(result.Content[0].Text), target); err != nil {
		return fmt.Errorf("failed to parse Anthropic response: %w", err)
	}

	return nil
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
