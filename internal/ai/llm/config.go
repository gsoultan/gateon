// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package llm

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Defaults and ceilings. Every one is explicit: a call the operator did not
// size is still bounded in time and in what it may cost.
const (
	DefaultTimeout         = 30 * time.Second
	MaxTimeout             = 120 * time.Second
	DefaultMaxOutputTokens = 4096
	MaxOutputTokens        = 16000

	defaultAnthropicBaseURL = "https://api.anthropic.com"
	defaultOpenAIBaseURL    = "https://api.openai.com/v1"
	defaultAnthropicModel   = "claude-opus-5-5"
	defaultOpenAIModel      = "gpt-5"

	maxModelLen   = 128
	maxBaseURLLen = 2048
	maxAPIKeyLen  = 4096
)

// Settings is an AIConfig with every default applied and every value checked.
type Settings struct {
	Provider        string
	Model           string
	BaseURL         string // no trailing slash
	APIKey          string
	Timeout         time.Duration
	MaxOutputTokens int
	ShareLogLines   bool
}

// FromConfig turns a stored AIConfig into Settings. It returns ErrDisabled
// when the feature is off, and an error wrapping ErrConfig naming the field
// when it is on but unusable.
func FromConfig(c *gateonv1.AIConfig) (Settings, error) {
	if !c.GetEnabled() {
		return Settings{}, ErrDisabled
	}
	if err := Validate(c); err != nil {
		return Settings{}, err
	}
	s := Settings{
		Provider:        c.GetProvider(),
		Model:           strings.TrimSpace(c.GetModel()),
		BaseURL:         strings.TrimRight(strings.TrimSpace(c.GetBaseUrl()), "/"),
		APIKey:          strings.TrimSpace(c.GetApiKey()),
		Timeout:         DefaultTimeout,
		MaxOutputTokens: DefaultMaxOutputTokens,
		ShareLogLines:   c.GetShareLogLines(),
	}
	if t := c.GetTimeoutSeconds(); t > 0 {
		s.Timeout = min(time.Duration(t)*time.Second, MaxTimeout)
	}
	if n := c.GetMaxOutputTokens(); n > 0 {
		s.MaxOutputTokens = min(int(n), MaxOutputTokens)
	}
	if s.BaseURL == "" {
		s.BaseURL = defaultBaseURL(s.Provider)
	}
	if s.Model == "" {
		s.Model = defaultModel(s.Provider)
	}
	return s, nil
}

// Validate refuses an enabled AIConfig the gateway could not use, naming the
// field and the fix. A disabled one is accepted as it stands, so an operator
// can stage a configuration before switching it on.
func Validate(c *gateonv1.AIConfig) error {
	if !c.GetEnabled() {
		return nil
	}
	switch c.GetProvider() {
	case ProviderAnthropic, ProviderOpenAI, ProviderOpenAICompatible:
	default:
		return fmt.Errorf("%w: ai.provider must be %q, %q or %q, not %q", ErrConfig,
			ProviderAnthropic, ProviderOpenAI, ProviderOpenAICompatible, c.GetProvider())
	}
	model := strings.TrimSpace(c.GetModel())
	if len(model) > maxModelLen || strings.ContainsAny(model, " \t\r\n") {
		return fmt.Errorf("%w: ai.model must be a model id of at most %d characters with no spaces", ErrConfig, maxModelLen)
	}
	if model == "" && c.GetProvider() == ProviderOpenAICompatible {
		return fmt.Errorf("%w: ai.model is required for an OpenAI-compatible server", ErrConfig)
	}
	if err := validateBaseURL(c.GetProvider(), strings.TrimSpace(c.GetBaseUrl())); err != nil {
		return err
	}
	if k := c.GetApiKey(); len(k) > maxAPIKeyLen || strings.ContainsAny(k, "\r\n") {
		return fmt.Errorf("%w: ai.api_key is not a usable key", ErrConfig)
	}
	if strings.TrimSpace(c.GetApiKey()) == "" && c.GetProvider() != ProviderOpenAICompatible {
		return fmt.Errorf("%w: ai.api_key is required for %s", ErrConfig, c.GetProvider())
	}
	if c.GetTimeoutSeconds() < 0 || c.GetMaxOutputTokens() < 0 {
		return fmt.Errorf("%w: ai.timeout_seconds and ai.max_output_tokens cannot be negative", ErrConfig)
	}
	return nil
}

// validateBaseURL admits https:// anywhere, and http:// only to an address
// that does not leave this host or its private network: the key travels in a
// header, and on plain http to the internet anyone on the path reads it.
func validateBaseURL(provider, raw string) error {
	if raw == "" {
		if provider == ProviderOpenAICompatible {
			return fmt.Errorf("%w: ai.base_url is required for an OpenAI-compatible server", ErrConfig)
		}
		return nil
	}
	if len(raw) > maxBaseURLLen {
		return fmt.Errorf("%w: ai.base_url is longer than %d characters", ErrConfig, maxBaseURLLen)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("%w: ai.base_url must be an absolute URL such as https://api.example.com/v1", ErrConfig)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: ai.base_url must not carry credentials, a query or a fragment; put the key in ai.api_key", ErrConfig)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if localHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: ai.base_url must use https:// unless it names a loopback or private address", ErrConfig)
	default:
		return fmt.Errorf("%w: ai.base_url must use https://", ErrConfig)
	}
}

// localHost reports whether host is localhost or a loopback or private
// address literal. A name other than localhost is not trusted to stay local:
// it resolves wherever its DNS says.
func localHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip := net.IP(addr.Unmap().AsSlice())
	return ip.IsLoopback() || ip.IsPrivate()
}

func defaultBaseURL(provider string) string {
	if provider == ProviderAnthropic {
		return defaultAnthropicBaseURL
	}
	return defaultOpenAIBaseURL
}

func defaultModel(provider string) string {
	switch provider {
	case ProviderAnthropic:
		return defaultAnthropicModel
	case ProviderOpenAI:
		return defaultOpenAIModel
	default:
		return ""
	}
}
