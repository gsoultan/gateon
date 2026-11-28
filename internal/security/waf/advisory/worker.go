// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	secwaf "github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/security/waf/features"
	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

// The bounds on what the reference worker reads. A gateway posts at most
// defaultBatch samples of about 6 KiB.
const (
	maxBatchBytes   = 1 << 20
	maxBatchSamples = 256
)

// Worker is the reference advisory worker: the gateway's own rules, run again
// on each sample with nothing turned off.
//
// A route's WAF runs at the paranoia level, with the rule families and the
// exceptions, that its traffic can live with. The worker runs every family at
// the highest level with no exception, which would refuse too much to stand
// in front of anything and is exactly what a second opinion is for. What it
// says names a rule, so a verdict can be read and checked.
//
// It is one implementation of the exchange. Anything that answers Path with
// an Answer can stand in its place, and a worker that judges by other means
// is the reason the exchange exists.
type Worker struct {
	engine *gwaf.WAF
	token  string
	// mimir, when set, judges each sample by a learned model and falls back
	// to the rules when the model does not answer (ADR 0108).
	mimir *mimirJudge
}

// NewWorker returns a worker that takes batches bearing token. A worker with
// no token would judge for anyone who can reach it, so there is none.
func NewWorker(token string, paranoia int) (*Worker, error) {
	if token == "" {
		return nil, errors.New("the advisory worker needs a token: set " + TokenEnv +
			" to the value the gateway is given")
	}
	engine, err := secwaf.Policy{ParanoiaLevel: paranoia, FailOpen: true}.NewEngine()
	if err != nil {
		return nil, err
	}
	return &Worker{engine: engine, token: token}, nil
}

func (w *Worker) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != Path {
		http.NotFound(rw, r)
		return
	}
	given, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(given), []byte(w.token)) != 1 {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	var batch Batch
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxBatchBytes)).Decode(&batch); err != nil {
		http.Error(rw, "the batch could not be read", http.StatusBadRequest)
		return
	}
	if len(batch.Samples) > maxBatchSamples {
		http.Error(rw, "the batch holds too many samples", http.StatusRequestEntityTooLarge)
		return
	}
	answer := Answer{Verdicts: []Verdict{}}
	if w.mimir != nil {
		answer.Verdicts = w.mimir.judgeBatch(r.Context(), batch.Samples, w.Judge)
	} else {
		for _, s := range batch.Samples {
			if v, flagged := w.Judge(s); flagged {
				answer.Verdicts = append(answer.Verdicts, v)
			}
		}
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(answer)
}

// UseMimir has the worker judge by a model on mimir-server, scanning each
// sample at the paranoia level the model's rows were exported at.
func (w *Worker) UseMimir(cfg MimirConfig, paranoia int) error {
	m, err := newMimirJudge(cfg, paranoia)
	if err != nil {
		return err
	}
	w.mimir = m
	return nil
}

// Judge runs the strict rules over one sample and reports what they found.
//
// A sample the gateway's own rules already matched on the same rule is not
// flagged: that match is in the Security Hub already, and saying it twice is
// noise. A rule that refuses on reputation is not either, because the worker
// is told nothing about the client.
func (w *Worker) Judge(s *Sample) (Verdict, bool) {
	if s == nil || s.Entry == nil || s.Target == "" {
		return Verdict{}, false
	}
	tx := w.engine.NewTransaction()
	defer tx.Close()
	tx.AddResolver(secwaf.ReputationResolver{Score: 100})

	tx.SetRequestLine(s.Method, features.RequestURI(s.Target, s.Args), "HTTP/1.1")
	for name, value := range s.Headers {
		tx.AddRequestHeader(name, value)
	}
	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		d = tx.ProcessRequestBody()
	}
	if !d.Blocked() {
		return Verdict{}, false
	}
	id := uint32(d.RuleID())
	if slices.Contains(s.Rules, id) || secwaf.RepeatsEarlierDecision(id) {
		return Verdict{}, false
	}
	label := "waf_rule"
	if info, ok := secwaf.LookupRule(id); ok && isLabel(info.Category) {
		label = info.Category
	}
	reason := "rule " + strconv.FormatUint(uint64(id), 10) + " refuses this with every rule family on"
	if msg := d.Message(); msg != "" {
		reason += ": " + msg
	}
	if key := d.Key(); key != "" {
		reason += " (in " + key + ")"
	}
	return Verdict{ID: s.ID, Label: label, Score: severityScore(d.Severity()), Reason: reason}, true
}

func severityScore(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 90
	case types.SeverityError:
		return 70
	case types.SeverityWarning:
		return 50
	}
	return 30
}

// WorkerCLI is `gateon advisory-worker`: it serves the reference worker until
// ctx is done and returns the process's exit status.
func WorkerCLI(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("advisory-worker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8787", "address to listen on")
	cert := fs.String("cert", "", "TLS certificate file; with --key, serves HTTPS")
	key := fs.String("key", "", "TLS private key file")
	paranoia := fs.Int("paranoia", 4, "paranoia level the samples are judged at, 1 to 4")
	judge := fs.String("judge", "rules", "rules, or mimir to judge by a learned model on mimir-server (ADR 0108)")
	mimir := MimirConfig{}
	fs.StringVar(&mimir.URL, "mimir-url", "", "mimir-server address, for --judge mimir")
	fs.StringVar(&mimir.Model, "mimir-model", "", "id of the model taught on export-waf-features rows")
	fs.IntVar(&mimir.Threshold, "threshold", 80, "score from 1 to 100 at or above which the model's answer is a verdict")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*cert == "") != (*key == "") {
		fmt.Fprintln(stderr, "advisory-worker: --cert and --key go together")
		return 2
	}
	w, err := NewWorker(strings.TrimSpace(os.Getenv(TokenEnv)), *paranoia)
	if err == nil {
		err = useJudge(w, *judge, mimir, *paranoia)
	}
	if err != nil {
		fmt.Fprintf(stderr, "advisory-worker: %v\n", err)
		return 1
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           w,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		// Not ctx: ctx is what just ended, and the drain outlives it.
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(stop)
	}()
	fmt.Fprintf(stderr, "advisory-worker: judging by %s at paranoia %d on %s\n", *judge, *paranoia, *listen)
	if *cert != "" {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "advisory-worker: %v\n", err)
		return 1
	}
	return 0
}

// useJudge sets the worker's judge by name.
func useJudge(w *Worker, judge string, cfg MimirConfig, paranoia int) error {
	switch judge {
	case "rules":
		return nil
	case "mimir":
		cfg.Key = strings.TrimSpace(os.Getenv(MimirKeyEnv))
		return w.UseMimir(cfg, paranoia)
	}
	return errors.New("--judge is rules or mimir")
}
