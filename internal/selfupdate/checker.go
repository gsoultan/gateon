// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// CheckState is where the release check stands.
type CheckState uint8

const (
	// StatePending: no check has finished since the gateway started.
	StatePending CheckState = iota
	// StateOK: the last check read a release the gateway accepts.
	StateOK
	// StateFailed: the last check failed; Status.Failure says how.
	StateFailed
	// StateDisabled: checking is switched off.
	StateDisabled
)

// SignatureState is what could be established about the release list.
type SignatureState uint8

const (
	// SignatureUnknown: no list has been read.
	SignatureUnknown SignatureState = iota
	// SignatureVerified: signed by a release key compiled into this binary.
	SignatureVerified
	// SignatureNoKey: this binary has no release key, so nothing was verified.
	SignatureNoKey
)

// Failure is why a check failed.
type Failure uint8

const (
	FailureNone Failure = iota
	// FailureUnreachable: the source did not answer, or answered an error.
	FailureUnreachable
	// FailureSignature: the list has no signature from a trusted key.
	FailureSignature
	// FailureMalformed: the list is not one the gateway can read.
	FailureMalformed
	// FailureSource: the configured source is not one the gateway will fetch.
	FailureSource
)

// Status is what the gateway knows about newer releases.
type Status struct {
	Current string
	// ReleaseBuild: Current is a release version and can be compared.
	ReleaseBuild bool
	// Latest is the newest release the source lists; empty when unknown.
	Latest          string
	UpdateAvailable bool
	Signature       SignatureState
	CheckedAt       time.Time
	State           CheckState
	Failure         Failure
	NotesURL        string
	Source          string
	InstallKind     InstallKind
	DisabledByEnv   bool
}

// The pacing of the background loop and of "Check now".
const (
	// firstCheckDelay keeps the first check out of the gateway's start.
	firstCheckDelay = time.Minute
	// manualSpacing is the least time between two fetches, however often
	// CheckForUpdate is called: the button must not become a way to make the
	// gateway hammer its release source.
	manualSpacing = 30 * time.Second
)

// updateAvailable is 1 while the last check found a release newer than the
// running one. No labels: the version is in the log line and the dashboard.
var updateAvailable = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "gateon_update_available",
	Help: "1 while a gateon release newer than the running version is known, 0 otherwise.",
})

// result is the outcome of one check.
type result struct {
	at        time.Time
	source    string
	failure   Failure
	release   Version
	known     bool // release holds a version this or an earlier check accepted
	signature SignatureState
}

// Checker looks for newer releases. It is safe for concurrent use.
type Checker struct {
	current        string
	currentVersion Version
	releaseBuild   bool
	env            Env
	config         func() *gateonv1.UpdateConfig
	fetch          fetcher
	keys           []ed25519.PublicKey
	kind           InstallKind
	now            func() time.Time

	checking sync.Mutex // one fetch at a time
	last     atomic.Pointer[result]
	kick     chan struct{}
}

// New builds a Checker for the running version. config returns the saved
// settings each time it is asked, so a change takes effect at the next check.
func New(current string, config func() *gateonv1.UpdateConfig) *Checker {
	v, ok := ParseVersion(current)
	return &Checker{
		current:        current,
		currentVersion: v,
		releaseBuild:   ok,
		env:            ReadEnv(),
		config:         config,
		fetch:          httpFetcher{client: newClient(), userAgent: "gateon/" + current},
		keys:           ReleaseKeys(),
		kind:           DetectInstallKind(),
		now:            time.Now,
		kick:           make(chan struct{}, 1),
	}
}

// Run checks once shortly after start and then every interval, until ctx is
// done. Kick brings the next check forward.
func (c *Checker) Run(ctx context.Context) {
	timer := time.NewTimer(jittered(firstCheckDelay))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-c.kick:
		}
		c.Check(ctx)
		timer.Reset(jittered(c.env.Interval))
	}
}

// jittered spreads d by up to a tenth, so gateways started together do not
// all ask the release source in the same second of every day.
func jittered(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	// #nosec G404 -- spreads load; nothing depends on the delay being unguessable.
	return d + rand.N(d/10+1)
}

// Kick asks Run to check now: the settings changed. It never blocks.
func (c *Checker) Kick() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// Check asks the release source now and returns what is then known. It does
// nothing while checking is switched off, and nothing when a check finished
// within manualSpacing.
func (c *Checker) Check(ctx context.Context) Status {
	c.checking.Lock()
	defer c.checking.Unlock()
	s := c.env.Settings(c.config())
	if !s.Enabled {
		updateAvailable.Set(0)
		return c.status(s)
	}
	if prev := c.last.Load(); prev != nil && prev.source == s.Source && c.now().Sub(prev.at) < manualSpacing {
		return c.status(s)
	}
	fetchCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	c.record(s, c.check(fetchCtx, s.Source))
	return c.status(s)
}

// check reads and judges the release list at rawSource.
func (c *Checker) check(ctx context.Context, rawSource string) result {
	res := result{at: c.now(), source: rawSource}
	src, err := newSource(rawSource)
	if err != nil {
		return c.failed(res, FailureSource, err)
	}
	sums, err := c.fetch.fetch(ctx, src.checksumsURL(), MaxChecksumsBytes)
	if err != nil {
		return c.failed(res, fetchFailure(err), err)
	}
	if res.signature, err = c.verify(ctx, src, sums); err != nil {
		return c.failed(res, signatureFailure(err), err)
	}
	rel, err := ParseChecksums(sums)
	if err != nil {
		return c.failed(res, FailureMalformed, err)
	}
	res.release, res.known = rel.Version, true
	return res
}

// verify checks the list's signature. A build with no release key verifies
// nothing and says so; a build with one refuses a list that is unsigned.
func (c *Checker) verify(ctx context.Context, src source, sums []byte) (SignatureState, error) {
	if len(c.keys) == 0 {
		return SignatureNoKey, nil
	}
	sig, err := c.fetch.fetch(ctx, src.signatureURL(), MaxSignatureBytes)
	if errors.Is(err, errNotFound) {
		return SignatureUnknown, ErrSignature
	}
	if err != nil {
		return SignatureUnknown, err
	}
	if err := Verify(c.keys, sums, sig); err != nil {
		return SignatureUnknown, err
	}
	return SignatureVerified, nil
}

func fetchFailure(err error) Failure {
	if errors.Is(err, ErrMalformed) {
		return FailureMalformed
	}
	return FailureUnreachable
}

func signatureFailure(err error) Failure {
	if errors.Is(err, ErrSignature) || errors.Is(err, ErrMalformed) {
		return FailureSignature
	}
	return FailureUnreachable
}

func (c *Checker) failed(res result, f Failure, err error) result {
	res.failure = f
	logger.L.LogWarn("the release check failed; the dashboard shows what was last known",
		"source", res.source, "error", err)
	return res
}

// record stores a check's outcome. A source that merely did not answer does
// not un-know the release an earlier check of the same source accepted; a
// list refused on its signature or its content does.
func (c *Checker) record(s Settings, res result) {
	prev := c.last.Load()
	if res.failure == FailureUnreachable && prev != nil && prev.known && prev.source == res.source {
		res.release, res.known, res.signature = prev.release, true, prev.signature
	}
	newer := res.known && c.releaseBuild && res.release.Newer(c.currentVersion)
	if newer && (prev == nil || !prev.known || prev.release != res.release) {
		logger.L.LogInfo("a newer gateon release is available",
			"running", c.current, "latest", res.release.String(), "source", s.Source)
	}
	if newer {
		updateAvailable.Set(1)
	} else {
		updateAvailable.Set(0)
	}
	c.last.Store(&res)
}

// Status reports what is known without asking the release source.
func (c *Checker) Status() Status {
	return c.status(c.env.Settings(c.config()))
}

func (c *Checker) status(s Settings) Status {
	st := Status{
		Current:       c.current,
		ReleaseBuild:  c.releaseBuild,
		Source:        s.Source,
		InstallKind:   c.kind,
		DisabledByEnv: s.DisabledByEnv,
		State:         StatePending,
	}
	if !s.Enabled {
		st.State = StateDisabled
		return st
	}
	res := c.last.Load()
	if res == nil || res.source != s.Source {
		return st
	}
	st.CheckedAt, st.Failure, st.State = res.at, res.failure, StateOK
	if res.failure != FailureNone {
		st.State = StateFailed
	}
	if !res.known {
		return st
	}
	st.Latest, st.Signature = res.release.String(), res.signature
	st.UpdateAvailable = c.releaseBuild && res.release.Newer(c.currentVersion)
	if src, err := newSource(s.Source); err == nil {
		st.NotesURL = src.notesURL(res.release)
	}
	return st
}
