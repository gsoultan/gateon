// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/security/waf/features"
)

// MimirKeyEnv holds the mimir-server API key the worker asks with. It is
// environment only, as the worker's own token is, so it never sits in a
// process listing.
const MimirKeyEnv = "GATEON_MIMIR_API_KEY" // #nosec G101 -- the name of a variable, not its value

// The bounds on asking mimir (ADR 0108). The gateway gives a batch ten
// seconds; the worker spends at most batchBudget of it on the model, and a
// sample still unanswered then is judged by the rules alone.
const (
	mimirCallTimeout   = 2 * time.Second
	mimirBatchBudget   = 7 * time.Second
	mimirInFlight      = 4
	mimirMaxExplained  = 8
	mimirMaxAnswer     = 64 << 10
	mimirLabel         = "learned"
	mimirReasonColumns = 3
	predictPath        = "/mimir.v1.PredictService/Predict"
	explainPath        = "/mimir.v1.PredictService/Explain"
)

// MimirConfig is where the learned model is and when its score is a verdict.
type MimirConfig struct {
	// URL is the mimir-server's address: https, or http on this host.
	URL string
	// Model is the id of a table model taught on export-waf-features rows.
	Model string
	// Key is an API key of a viewer limited to that model.
	Key string
	// Threshold is the score, 1 to 100, at or above which a sample is
	// flagged.
	Threshold int
}

// mimirJudge asks a model on mimir-server for the chance that a sample is
// an attack, from the row features.Extract builds of it.
//
// The model is another host's word, so it is believed no further than the
// rules' own verdicts are: a verdict is an entry in the Security Hub, in the
// mode the gateway was given, and never refuses anything. When mimir does
// not answer, the sample is judged as the reference worker judges it, so a
// model that is down costs a second opinion its precision and nothing else.
type mimirJudge struct {
	endpoint, model, key string
	threshold            int
	client               *http.Client
	scanner              *features.Scanner
	failing              atomic.Bool
}

func newMimirJudge(cfg MimirConfig, paranoia int) (*mimirJudge, error) {
	endpoint, err := checkURL(cfg.URL)
	if err != nil {
		return nil, errors.New(strings.ReplaceAll(err.Error(), "advisory worker", "mimir"))
	}
	switch {
	case strings.TrimSpace(cfg.Model) == "":
		return nil, errors.New("the mimir judge needs --mimir-model, the id of the model to ask")
	case cfg.Key == "":
		return nil, errors.New("the mimir judge needs an API key: set " + MimirKeyEnv)
	case cfg.Threshold < 1 || cfg.Threshold > 100:
		return nil, errors.New("--threshold is a score from 1 to 100")
	}
	scanner, err := features.NewScanner(paranoia)
	if err != nil {
		return nil, err
	}
	return &mimirJudge{
		endpoint: endpoint, model: strings.TrimSpace(cfg.Model), key: cfg.Key,
		threshold: cfg.Threshold, client: newMimirClient(), scanner: scanner,
	}, nil
}

// newMimirClient sets every limit and follows no redirect: one would carry
// the key and the rows wherever it pointed.
func newMimirClient() *http.Client {
	return &http.Client{
		Timeout: mimirCallTimeout,
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            (&net.Dialer{Timeout: mimirCallTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:    mimirCallTimeout,
			ResponseHeaderTimeout:  mimirCallTimeout,
			IdleConnTimeout:        90 * time.Second,
			MaxIdleConns:           mimirInFlight,
			MaxIdleConnsPerHost:    mimirInFlight,
			MaxConnsPerHost:        mimirInFlight,
			MaxResponseHeaderBytes: 16 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// judgeBatch answers a batch, mimirInFlight samples at a time. fallback is
// the rules' own judgement, for a sample mimir did not answer.
func (m *mimirJudge) judgeBatch(ctx context.Context, batch []*Sample, fallback func(*Sample) (Verdict, bool)) []Verdict {
	ctx, cancel := context.WithTimeout(ctx, mimirBatchBudget)
	defer cancel()
	var (
		mu        sync.Mutex
		verdicts  = make([]Verdict, 0, len(batch))
		explained atomic.Int32
		wg        sync.WaitGroup
		slots     = make(chan struct{}, mimirInFlight)
	)
	for _, s := range batch {
		if s == nil || s.Entry == nil || s.Target == "" {
			continue
		}
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			v, ok := m.judge(ctx, s, &explained)
			if !ok {
				return
			}
			mu.Lock()
			verdicts = append(verdicts, v)
			mu.Unlock()
		})
	}
	wg.Wait()
	return m.withFallback(batch, verdicts, fallback)
}

func (m *mimirJudge) judge(ctx context.Context, s *Sample, explained *atomic.Int32) (Verdict, bool) {
	row := features.Extract(features.Input{Entry: s.Entry, Why: s.Why, Rules: s.Rules}, m.scanner.Scan(s.Entry))
	score, err := m.predict(ctx, row)
	if err != nil {
		m.noteFailure(err)
		return Verdict{ID: s.ID, Label: unanswered}, true
	}
	m.noteAnswer()
	if score < m.threshold {
		return Verdict{}, false
	}
	reason := "the learned model scores this " + strconv.Itoa(score) + " of 100"
	if explained.Add(1) <= mimirMaxExplained {
		if cols := m.explain(ctx, row); len(cols) > 0 {
			reason += "; it turns most on " + strings.Join(cols, ", ")
		}
	}
	return Verdict{ID: s.ID, Label: mimirLabel, Score: score, Reason: reason}, true
}

// unanswered marks, inside judgeBatch only, a sample mimir did not answer.
// It is not a label clean() accepts, so it can never reach the gateway.
const unanswered = "\x00unanswered"

// withFallback replaces every unanswered mark with the rules' verdict.
func (m *mimirJudge) withFallback(batch []*Sample, verdicts []Verdict, fallback func(*Sample) (Verdict, bool)) []Verdict {
	byID := make(map[string]*Sample, len(batch))
	for _, s := range batch {
		if s != nil {
			byID[s.ID] = s
		}
	}
	out := verdicts[:0]
	for _, v := range verdicts {
		if v.Label != unanswered {
			out = append(out, v)
			continue
		}
		if fv, ok := fallback(byID[v.ID]); ok {
			out = append(out, fv)
		}
	}
	return out
}

func (m *mimirJudge) noteFailure(err error) {
	if !m.failing.Swap(true) {
		logger.L.LogWarn("mimir did not answer; samples are judged by the rules alone until it does",
			"mimir", m.endpoint, "error", err.Error())
	}
}

func (m *mimirJudge) noteAnswer() {
	if m.failing.Swap(false) {
		logger.L.LogInfo("mimir is answering again", "mimir", m.endpoint)
	}
}

type predictAnswer struct {
	Guesses []struct {
		Label       string  `json:"label"`
		Probability float64 `json:"probability"`
	} `json:"guesses"`
}

// predict returns the model's chance that row is an attack, 0 to 100.
func (m *mimirJudge) predict(ctx context.Context, row features.Row) (int, error) {
	var a predictAnswer
	req := map[string]any{"modelId": m.model, "fields": row.Fields(), "topK": 2}
	if err := m.call(ctx, predictPath, req, &a); err != nil {
		return 0, err
	}
	if len(a.Guesses) == 0 {
		return 0, errors.New("mimir answered with no guess: is the model one taught on export-waf-features rows?")
	}
	for _, g := range a.Guesses {
		if g.Label == features.LabelAttack {
			return scoreOf(g.Probability), nil
		}
	}
	return 0, nil
}

func scoreOf(p float64) int {
	if math.IsNaN(p) {
		return 0
	}
	return int(math.Round(min(max(p, 0), 1) * 100))
}

type explainAnswer struct {
	Contributions []struct {
		Column string  `json:"column"`
		Effect float64 `json:"effect"`
	} `json:"contributions"`
}

// explain names the columns that moved the answer towards "attack" most. A
// column is named only if it is one of ours: the answer is another host's.
func (m *mimirJudge) explain(ctx context.Context, row features.Row) []string {
	var a explainAnswer
	req := map[string]any{"modelId": m.model, "fields": row.Fields(), "label": features.LabelAttack}
	if err := m.call(ctx, explainPath, req, &a); err != nil {
		return nil
	}
	known := make(map[string]bool, len(features.Columns))
	for _, c := range features.Columns {
		known[c] = true
	}
	var cols []string
	for _, c := range a.Contributions {
		if c.Effect > 0 && known[c.Column] && len(cols) < mimirReasonColumns {
			cols = append(cols, c.Column)
			known[c.Column] = false
		}
	}
	return cols
}

// call posts one Connect JSON request and decodes at most mimirMaxAnswer of
// the answer into out.
func (m *mimirJudge) call(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.key)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, mimirMaxAnswer))
		return errors.New("mimir answered " + strconv.Itoa(resp.StatusCode))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, mimirMaxAnswer)).Decode(out); err != nil {
		return errors.New("mimir's answer could not be read")
	}
	return nil
}
