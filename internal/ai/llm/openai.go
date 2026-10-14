// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package llm

import (
	"context"
	"net/http"
)

// openAI calls the chat-completions API (POST {base}/chat/completions):
// OpenAI itself, and the servers that copy its shape -- Azure OpenAI's v1
// endpoint, Ollama, vLLM, LM Studio, Groq, Mistral, OpenRouter and others.
type openAI struct {
	s      Settings
	client *http.Client
	// compatible sends the output budget as max_tokens, which every
	// compatible server reads, instead of OpenAI's max_completion_tokens,
	// which its current models require and most copies do not know.
	compatible bool
}

type openAIRequest struct {
	Model               string          `json:"model"`
	Messages            []openAIMessage `json:"messages"`
	MaxCompletionTokens int             `json:"max_completion_tokens,omitempty"`
	MaxTokens           int             `json:"max_tokens,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
			Refusal string `json:"refusal"`
		} `json:"message"`
	} `json:"choices"`
}

// Complete asks the model for one answer: the first choice's content. A
// refusal or an empty answer is ErrRefused.
func (o *openAI) Complete(ctx context.Context, p Prompt) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, o.s.Timeout)
	defer cancel()
	req := openAIRequest{Model: o.s.Model, Messages: make([]openAIMessage, 0, 2)}
	if p.System != "" {
		req.Messages = append(req.Messages, openAIMessage{Role: "system", Content: p.System})
	}
	req.Messages = append(req.Messages, openAIMessage{Role: "user", Content: p.User})
	if o.compatible {
		req.MaxTokens = o.s.MaxOutputTokens
	} else {
		req.MaxCompletionTokens = o.s.MaxOutputTokens
	}
	headers := map[string]string{}
	if o.s.APIKey != "" {
		headers["Authorization"] = "Bearer " + o.s.APIKey
	}
	var resp openAIResponse
	if err := postJSON(ctx, o.client, o.s.BaseURL+"/chat/completions", headers, req, &resp); err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 || resp.Choices[0].Message.Refusal != "" {
		return "", ErrRefused
	}
	return answer(resp.Choices[0].Message.Content)
}
