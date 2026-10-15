// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package advisory is the AI Advisory and Log Assistant: Gateon's own,
// deterministic analysis of its configuration and logs, which a configured
// language model may narrate and never replace (ADR 0070).
//
// It serves every transport. ApiService exposes it as the AnalyzeConfig,
// AnalyzeLogs and TestAIProvider RPCs, which REST, Connect and gRPC all call.
package advisory

import (
	"context"
	"errors"
	"strings"

	"github.com/gsoultan/gateon/internal/ai/llm"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/security/posture"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Insight is one advisory recommendation.
type Insight struct {
	Title           string
	Description     string
	Severity        string // "critical" | "warning" | "info"
	Category        string // "security" | "performance" | "availability"
	Recommendation  string
	SuggestedConfig string
}

// Insight severities and categories: the vocabulary AIAdvisoryTab.tsx colours
// and picks icons by.
const (
	insightCritical      = "critical"
	insightWarning       = "warning"
	insightInfo          = "info"
	categorySecurity     = "security"
	categoryAvailability = "availability"
)

// EngineLocal is the engine an analysis names when Gateon's own analysis
// wrote it. A provider's answer names "provider:model" (llm.Engine).
const EngineLocal = "local"

// ConfigAnalysis is the result of analyzing the gateway's configuration.
//
// Engine says what wrote Summary: "local", or the provider and model. Notice
// is set when a provider is configured and did not answer, saying why in
// words that carry no key, prompt or reply; Summary is then the local one.
// Insights are always the local analysis -- a model narrates them and cannot
// add, drop or reword one.
type ConfigAnalysis struct {
	Summary  string
	Insights []Insight
	Engine   string
	Notice   string
}

// LogAnalysis is the result of analyzing a batch of log lines.
// Local is the deterministic tally, returned beside a provider's analysis so
// the operator always sees what the lines actually say.
type LogAnalysis struct {
	Analysis string
	Local    string
	Engine   string
	Notice   string
}

// TestResult is the outcome of one test call to the configured provider.
type TestResult struct {
	OK      bool
	Engine  string
	Message string
}

// Coverage counts the enabled HTTP routes by the mode of the WAF that
// inspects each one, and by the middlewares that bound them.
type Coverage = posture.RouteCoverage

// Service runs the analysis and asks the configured provider to narrate it.
// One Service serves the whole gateway, so the provider's concurrency bound
// and summary cache are gateway-wide.
//
// A Service is safe for concurrent use. The zero value is not usable; call New.
type Service struct {
	advisor *llm.Advisor
}

// New returns a Service with its own provider client.
func New() *Service { return &Service{advisor: llm.NewAdvisor()} }

// Gateway is what the configuration analysis reads.
type Gateway struct {
	Config *gateonv1.GlobalConfig
	// Routes counts the enabled routes by what inspects and bounds them.
	Routes Coverage
	// ManagementWorldOpen is true when the dedicated management listener
	// admits any address. The caller asks the listener code, so this package
	// needs none.
	ManagementWorldOpen bool
}

// AnalyzeConfig analyzes g, and has the provider in its ai settings, when one
// is enabled and answers, write the summary.
func (s *Service) AnalyzeConfig(ctx context.Context, g Gateway) ConfigAnalysis {
	resp := analyzeConfig(ctx, g)
	narrateConfig(ctx, s.advisor, g.Config.GetAi(), &resp)
	return resp
}

// AnalyzeLogs tallies lines, and has the provider in c, when one is enabled
// and answers, explain them.
func (s *Service) AnalyzeLogs(ctx context.Context, c *gateonv1.AIConfig, lines []string) LogAnalysis {
	local := analyzeLogs(lines)
	resp := LogAnalysis{Analysis: local, Local: local, Engine: EngineLocal}
	if len(lines) > 0 {
		narrateLogs(ctx, s.advisor, c, lines, &resp)
	}
	return resp
}

// Test makes one call with the provider settings in c.
func (s *Service) Test(ctx context.Context, c *gateonv1.AIConfig) TestResult {
	return testAIProvider(ctx, s.advisor, c)
}

// narrateConfig replaces the local summary with the provider's, when one is
// enabled and answers.
func narrateConfig(ctx context.Context, a *llm.Advisor, c *gateonv1.AIConfig, resp *ConfigAnalysis) {
	resp.Engine = EngineLocal
	if !c.GetEnabled() {
		return
	}
	findings := make([]llm.Finding, 0, len(resp.Insights))
	for _, in := range resp.Insights {
		findings = append(findings, llm.Finding{Title: in.Title, Severity: in.Severity,
			Description: in.Description, Recommendation: in.Recommendation})
	}
	text, s, err := a.Summarize(ctx, c, findings)
	if err != nil {
		resp.Notice = aiFallbackNotice(err)
		return
	}
	resp.Summary, resp.Engine = text, llm.Engine(s)
}

// narrateLogs replaces the local analysis with the provider's, when one is
// enabled and answers; the local tally stays in Local either way.
func narrateLogs(ctx context.Context, a *llm.Advisor, c *gateonv1.AIConfig, lines []string, resp *LogAnalysis) {
	if !c.GetEnabled() {
		return
	}
	text, s, err := a.AnalyzeLogs(ctx, c, resp.Local, lines)
	if err != nil {
		resp.Notice = aiFallbackNotice(err)
		return
	}
	resp.Analysis, resp.Engine = text, llm.Engine(s)
}

func testAIProvider(ctx context.Context, a *llm.Advisor, c *gateonv1.AIConfig) TestResult {
	s, err := a.Test(ctx, c)
	if err != nil {
		return TestResult{Message: aiFailure(err)}
	}
	return TestResult{OK: true, Engine: llm.Engine(s), Message: "The provider answered."}
}

// aiFallbackNotice is what the dashboard shows above the local analysis when
// the provider did not answer.
func aiFallbackNotice(err error) string {
	return aiFailure(err) + " Showing the local analysis."
}

// aiFailure logs why a provider call failed and returns a sentence for the
// dashboard. Only the package's sentinels are named: their text carries no
// key, prompt or reply, and a transport error (which can name an internal
// address) stays in the server log.
func aiFailure(err error) string {
	for _, known := range []error{llm.ErrDisabled, llm.ErrConfig, llm.ErrAuth, llm.ErrRateLimited,
		llm.ErrRejected, llm.ErrRefused, llm.ErrBusy, llm.ErrUpstream} {
		if errors.Is(err, known) {
			if !errors.Is(known, llm.ErrDisabled) && !errors.Is(known, llm.ErrBusy) {
				logger.L.LogWarn("AI provider call failed; serving the local analysis", "error", err)
			}
			return capitalize(known.Error()) + "."
		}
	}
	logger.L.LogWarn("AI provider call failed; serving the local analysis", "error", err)
	return "The AI provider could not answer."
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
