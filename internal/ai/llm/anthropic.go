// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package llm

import (
	"context"
	"net/http"
	"strings"
)

// anthropicVersion is the Messages API version header the request shape
// below is written against.
const anthropicVersion = "2023-06-01"

// anthropic calls Claude through the Messages API (POST /v1/messages).
type anthropic struct {
	s      Settings
	client *http.Client
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
}

// Complete asks Claude for one answer. Thinking is left to the model's own
// default (adaptive on current models), which counts against max_tokens; the
// answer is the concatenated text blocks, and a refusal or an empty answer is
// ErrRefused.
func (a *anthropic) Complete(ctx context.Context, p Prompt) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, a.s.Timeout)
	defer cancel()
	req := anthropicRequest{
		Model:     a.s.Model,
		MaxTokens: a.s.MaxOutputTokens,
		System:    p.System,
		Messages:  []anthropicMessage{{Role: "user", Content: p.User}},
	}
	headers := map[string]string{"anthropic-version": anthropicVersion, "x-api-key": a.s.APIKey}
	var resp anthropicResponse
	if err := postJSON(ctx, a.client, a.s.BaseURL+"/v1/messages", headers, req, &resp); err != nil {
		return "", err
	}
	if resp.StopReason == "refusal" {
		return "", ErrRefused
	}
	var b strings.Builder
	for _, c := range resp.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	return answer(b.String())
}
