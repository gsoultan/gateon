// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Path is where a worker takes batches, under the address it is given at.
const Path = "/v1/advise"

// Batch is what the gateway posts.
type Batch struct {
	Samples []*Sample `json:"samples"`
}

// Answer is what the worker returns: a verdict for each sample it has
// something against, and nothing for the rest.
type Answer struct {
	Verdicts []Verdict `json:"verdicts"`
}

// Verdict is the worker's opinion of one sample.
type Verdict struct {
	// ID is the sample's.
	ID string `json:"id"`
	// Label is the kind of attack, in the worker's words: "sqli".
	Label string `json:"label"`
	// Score is how sure the worker is, 1 to 100.
	Score int `json:"score"`
	// Reason is a sentence for whoever reads the Security Hub.
	Reason string `json:"reason"`
}

// Finding is a verdict matched to the sample it answers.
type Finding struct {
	Sample  *Sample
	Verdict Verdict
	Mode    Mode
}

const (
	maxLabel  = 32
	maxReason = 240
	noLabel   = "unlabelled"
)

// send posts one batch and hands each verdict that answers a sample in it to
// the sink.
func (q *Queue) send(ctx context.Context, batch []*Sample) error {
	body, err := json.Marshal(Batch{Samples: batch})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, q.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, q.endpoint+Path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if q.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+q.cfg.Token)
	}
	resp, err := q.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errors.New("the worker answered " + strconv.Itoa(resp.StatusCode))
	}
	var answer Answer
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&answer); err != nil {
		return errors.New("the worker's answer could not be read")
	}
	q.sent.Add(uint64(len(batch)))
	q.lastError.Store(nil)
	q.lastContact.Store(time.Now().Unix())
	q.take(batch, answer.Verdicts)
	return nil
}

// take matches verdicts to the batch they answer.
//
// The worker is another host and is not believed past what it was asked: a
// verdict for a number that was not in this batch is counted and dropped, a
// sample is judged once however many times it is named, and every field is
// cut to what the Security Hub can show.
func (q *Queue) take(batch []*Sample, verdicts []Verdict) {
	byID := make(map[string]*Sample, len(batch))
	for _, s := range batch {
		byID[s.ID] = s
	}
	findings := make([]Finding, 0, min(len(verdicts), len(batch)))
	unmatched := 0
	for _, v := range verdicts {
		s, ok := byID[v.ID]
		if !ok {
			unmatched++
			continue
		}
		delete(byID, v.ID)
		findings = append(findings, Finding{Sample: s, Verdict: clean(v), Mode: q.cfg.Mode})
	}
	// Counted before anything is told, so whoever is told reads counts that
	// already include the batch.
	q.unmatched.Add(uint64(unmatched))
	q.flagged.Add(uint64(len(findings)))
	sink := q.sink.Load()
	if sink == nil {
		return
	}
	for _, f := range findings {
		(*sink)(f)
	}
}

// clean cuts a verdict to what may be stored and shown.
func clean(v Verdict) Verdict {
	v.Score = min(max(v.Score, 1), 100)
	if !isLabel(v.Label) {
		v.Label = noLabel
	}
	v.Reason = printable(v.Reason, maxReason)
	return v
}

func isLabel(s string) bool {
	if s == "" || len(s) > maxLabel {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// printable keeps the printable text of s, at most limit bytes of it, cut
// between characters.
func printable(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
