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
	if conf.Ai == nil || !conf.Ai.Enabled {
		return nil, errors.New("AI service is not enabled in global configuration")
	}

	// Redact sensitive configuration before sending to AI provider.
	redactedGlobal := redactConfig(conf)

	// Gather configuration context.
	routes, _ := s.routeStore.ListPaginated(ctx, 0, 100, "", nil)
	services, _ := s.serviceStore.ListPaginated(ctx, 0, 100, "")
	middlewares, _ := s.mwStore.ListPaginated(ctx, 0, 100, "")
	entrypoints, _ := s.epStore.ListPaginated(ctx, 0, 100, "")

	configJSON, _ := json.MarshalIndent(map[string]any{
		"global":      redactedGlobal,
		"routes":      routes,
		"services":    services,
		"middlewares": middlewares,
		"entrypoints": entrypoints,
	}, "", "  ")

	prompt := fmt.Sprintf(`You are an expert API Gateway administrator for Gateon. 
Analyze the following configuration and provide performance, security, and availability insights.
Format your response as a JSON object with "summary" (string) and "insights" (array of objects with "title", "description", "severity", "category", "recommendation", "suggested_config").
Severity must be "info", "warning", or "critical". Category must be "security", "performance", or "availability".
If you suggest a configuration change, provide the JSON snippet in "suggested_config".

Configuration:
%s`, string(configJSON))

	var resp gateonv1.AnalyzeConfigResponse
	err := s.callLLM(ctx, prompt, &resp)
	return &resp, err
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

	// Redact sensitive configuration before sending to AI provider.
	redactedGlobal := redactConfig(conf)
	routes, _ := s.routeStore.ListPaginated(ctx, 0, 50, "", nil)
	services, _ := s.serviceStore.ListPaginated(ctx, 0, 50, "")

	configContext, _ := json.Marshal(map[string]any{
		"global":   redactedGlobal,
		"routes":   routes,
		"services": services,
	})

	prompt := fmt.Sprintf(`Current Gateon Configuration: %s

User Question: %s

Provide a helpful answer based on Gateon gateway best practices and the current configuration.
Format your response as a JSON object with a "summary" field containing your answer.`, string(configContext), req.Message)

	var resp struct {
		Summary string `json:"summary"`
	}
	err := s.callLLM(ctx, prompt, &resp)
	if err != nil {
		return nil, err
	}

	return &gateonv1.ChatWithAIResponse{
		Reply: resp.Summary,
	}, nil
}

// AnalyzeLogs analyzes gateway logs for issues.
func (s *AIService) AnalyzeLogs(ctx context.Context, req *gateonv1.AnalyzeLogsRequest) (*gateonv1.AnalyzeLogsResponse, error) {
	conf := s.globalStore.Get(ctx)
	if conf.Ai == nil || !conf.Ai.Enabled {
		return nil, errors.New("AI service is not enabled")
	}

	logsJSON, _ := json.Marshal(req.Logs)
	prompt := fmt.Sprintf(`Analyze the following Gateon gateway logs and provide insights on potential issues, security threats, or performance bottlenecks.
Format your response as a JSON object with "analysis" (string) and "insights" (array of objects with "title", "description", "severity", "category", "recommendation").

Logs:
%s`, string(logsJSON))

	var resp gateonv1.AnalyzeLogsResponse
	err := s.callLLM(ctx, prompt, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
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
		return fmt.Errorf("failed to call OpenAI: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OpenAI API returned status %d", resp.StatusCode)
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
		return fmt.Errorf("failed to call Anthropic: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Anthropic API returned status %d", resp.StatusCode)
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
