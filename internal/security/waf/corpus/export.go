// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package corpus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Path is where the management API serves the sample.
const Path = "/v1/waf/corpus"

// maxExport bounds what Export reads: the largest sample the gateway can hold,
// with room for JSON's own overhead. A response past it is not this API.
const maxExport = maxEntries * MaxEntryBytes * 2

// ErrEmpty is Export's answer when the gateway holds no sample. It is an
// error, not an empty file, because an empty corpus tunes nothing and the
// reason is nearly always that no route has a sample rate set.
var ErrEmpty = errors.New("the gateway holds no sampled requests: set a sample rate on a route's WAF " +
	"(or GATEON_WAF_CORPUS_SAMPLE_RATE), let it take traffic, and export again")

// Export writes the running gateway's sample to out, for `gateon
// export-waf-corpus`. token, when set, is sent as a Bearer credential.
func Export(ctx context.Context, apiURL, token string, out io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+Path, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return errors.New("the management API refused the request (401): pass --token, " +
			"or set GATEON_TOKEN, with a token from POST /v1/login")
	case http.StatusForbidden:
		return errors.New("this account may not export the sample (403): it needs write on the WAF rules")
	default:
		return fmt.Errorf("the management API answered %s", resp.Status)
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, maxExport))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrEmpty
	}
	return nil
}
