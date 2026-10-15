// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package llm lets the dashboard's AI Advisory and Log Assistant ask a
// third-party language model -- Anthropic's Claude, OpenAI, or any server that
// speaks OpenAI's chat-completions API -- to narrate what Gateon's own
// deterministic analysis found. See ADR 0070.
//
// The model is never on the request path and never decides anything. It is
// asked only from two management endpoints, its answer is shown to an
// administrator as text, and every failure -- no key, a timeout, a refusal, a
// rate limit, too many calls at once -- leaves the local analysis in place.
package llm

import (
	"context"
	"errors"
)

// The providers a gateway can be configured with.
const (
	ProviderAnthropic        = "anthropic"
	ProviderOpenAI           = "openai"
	ProviderOpenAICompatible = "openai_compatible"
)

// Prompt is one request to a model: the operator's instructions, and the
// material to work on.
type Prompt struct {
	System string
	User   string
}

// Provider completes a prompt with a third-party model.
//
// A Provider is safe for concurrent use.
type Provider interface {
	Complete(ctx context.Context, p Prompt) (string, error)
}

// The ways a call fails. Each is safe to log and to name to an
// administrator: none carries the key, the prompt or the provider's reply.
var (
	// ErrDisabled: no AI provider is configured, or it is switched off.
	ErrDisabled = errors.New("no AI provider is enabled")
	// ErrConfig: the configuration cannot be used as it stands.
	ErrConfig = errors.New("the AI provider configuration is invalid")
	// ErrAuth: the provider refused the API key (401/403).
	ErrAuth = errors.New("the AI provider refused the API key")
	// ErrRateLimited: the provider is throttling this key (429).
	ErrRateLimited = errors.New("the AI provider is rate limiting this key")
	// ErrUpstream: the provider failed (5xx), or could not be reached in time.
	ErrUpstream = errors.New("the AI provider could not answer")
	// ErrRejected: the provider refused the request itself (another 4xx) --
	// usually an unknown model name.
	ErrRejected = errors.New("the AI provider rejected the request; check the model name")
	// ErrRefused: the model declined to answer, or answered with nothing.
	ErrRefused = errors.New("the AI model returned no answer")
	// ErrBusy: as many calls as the gateway allows are already in flight.
	ErrBusy = errors.New("the AI provider is busy with other requests")
)
