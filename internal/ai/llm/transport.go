// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// maxResponseBytes caps what is read of a provider's reply. An answer within
// MaxOutputTokens is a small fraction of it; anything larger is not an answer.
const maxResponseBytes = 1 << 20

// newHTTPClient is the client every provider call goes through.
//
// Redirects are refused: Go strips Authorization on a redirect to another
// host, but not x-api-key, so following one would hand Anthropic's key to
// whatever host the redirect names. A provider API does not redirect a POST.
func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: MaxTimeout,
			MaxIdleConns:          4,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// postJSON sends body as JSON to url with headers and decodes the reply into
// out. Its errors are the package's sentinels, wrapped with the status code
// at most: never the reply body, which can quote the request back.
func postJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: encode request: %w", ErrConfig, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("%w: build request", ErrConfig)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		// The error names the URL, never a header, so it carries no key.
		if errors.Is(err, context.Canceled) {
			return err
		}
		return fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := statusError(resp.StatusCode); err != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read reply: %w", ErrUpstream, err)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("%w: reply larger than %d bytes", ErrUpstream, maxResponseBytes)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: reply is not the expected JSON", ErrUpstream)
	}
	return nil
}

// statusError maps a provider's HTTP status to the package's sentinels.
func statusError(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return fmt.Errorf("%w (HTTP %d)", ErrAuth, code)
	case code == http.StatusTooManyRequests:
		return fmt.Errorf("%w (HTTP %d)", ErrRateLimited, code)
	case code >= 500 || code == http.StatusRequestTimeout:
		return fmt.Errorf("%w (HTTP %d)", ErrUpstream, code)
	default:
		return fmt.Errorf("%w (HTTP %d)", ErrRejected, code)
	}
}
