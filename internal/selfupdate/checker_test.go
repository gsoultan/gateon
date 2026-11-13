// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	dto "github.com/prometheus/client_model/go"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fakeSource is a release source held in memory: the files it serves by URL
// suffix, and how many times each was asked for.
type fakeSource struct {
	mu    sync.Mutex
	files map[string][]byte
	err   error
	asked []string
}

func (f *fakeSource) fetch(_ context.Context, url string, limit int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, url)
	if f.err != nil {
		return nil, f.err
	}
	for suffix, body := range f.files {
		if strings.HasSuffix(url, "/"+suffix) {
			if int64(len(body)) > limit {
				return nil, ErrMalformed
			}
			return body, nil
		}
	}
	return nil, errNotFound
}

func (f *fakeSource) set(name string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if body == nil {
		delete(f.files, name)
		return
	}
	f.files[name] = body
}

func (f *fakeSource) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeSource) fetches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

// gaugeValue reads gateon_update_available.
func gaugeValue(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	if err := updateAvailable.Write(&m); err != nil {
		t.Fatalf("read gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

// harness is a Checker over a fakeSource, with a clock the test moves.
type harness struct {
	*Checker
	src  *fakeSource
	conf *gateonv1.UpdateConfig
	at   time.Time
}

func newHarness(current string, keys ...ed25519.PublicKey) *harness {
	h := &harness{
		src:  &fakeSource{files: map[string][]byte{}},
		conf: &gateonv1.UpdateConfig{},
		at:   time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC),
	}
	h.Checker = New(current, func() *gateonv1.UpdateConfig { return h.conf })
	h.env = Env{Interval: 24 * time.Hour}
	h.fetch = h.src
	h.keys = keys
	h.kind = InstallSystemd
	h.now = func() time.Time { return h.at }
	return h
}

// publish puts a release on the source, signed when key is not nil.
func (h *harness) publish(version string, key ed25519.PrivateKey) {
	list := checksumsFor(version)
	h.src.set(checksumsFile, list)
	h.src.set(signatureFile, nil)
	if key != nil {
		h.src.set(signatureFile, Sign(key, list))
	}
}

// later moves the clock past the spacing between two fetches.
func (h *harness) later() { h.at = h.at.Add(manualSpacing + time.Second) }

func TestCheckFindsANewerSignedRelease(t *testing.T) {
	pub, priv := testKey(t)
	h := newHarness("v1.8.2", pub)
	if st := h.Status(); st.State != StatePending || st.Latest != "" || st.UpdateAvailable {
		t.Fatalf("before any check: %+v, want pending and nothing known", st)
	}
	h.publish("1.8.3", priv)

	st := h.Check(t.Context())
	want := Status{
		Current: "v1.8.2", ReleaseBuild: true, Latest: "1.8.3", UpdateAvailable: true,
		Signature: SignatureVerified, CheckedAt: h.at, State: StateOK,
		NotesURL: DefaultSource + "/tag/v1.8.3", Source: DefaultSource, InstallKind: InstallSystemd,
	}
	if st != want {
		t.Fatalf("Check = %+v\n       want %+v", st, want)
	}
	if h.Status() != want {
		t.Errorf("Status after the check = %+v, want the same", h.Status())
	}
	if got := gaugeValue(t); got != 1 {
		t.Errorf("gateon_update_available = %v, want 1", got)
	}
}

// The release list is the only thing that says which version exists. With a
// release key compiled in, a list that key did not sign is not believed.
func TestCheckRefusesAListItCannotVerify(t *testing.T) {
	pub, priv := testKey(t)
	_, stranger := testKey(t)
	cases := map[string]func(h *harness){
		"no signature file":                   func(h *harness) { h.publish("9.9.9", nil) },
		"signed by a key that is not trusted": func(h *harness) { h.publish("9.9.9", stranger) },
		"the signature of another release's list": func(h *harness) {
			h.publish("9.9.9", priv)
			h.src.set(signatureFile, Sign(priv, checksumsFor("1.8.3")))
		},
		"a list changed after it was signed": func(h *harness) {
			h.publish("1.8.3", priv)
			h.src.set(checksumsFile, checksumsFor("9.9.9"))
		},
		"a signature file that is an error page": func(h *harness) {
			h.publish("9.9.9", priv)
			h.src.set(signatureFile, []byte("<html>not found</html>"))
		},
	}
	for name, tamper := range cases {
		h := newHarness("1.8.2", pub)
		tamper(h)
		st := h.Check(t.Context())
		if st.State != StateFailed || st.Failure != FailureSignature {
			t.Errorf("%s: state %d failure %d, want failed on its signature", name, st.State, st.Failure)
		}
		if st.Latest != "" || st.UpdateAvailable || st.NotesURL != "" || st.Signature != SignatureUnknown {
			t.Errorf("%s: an unverified release was reported: %+v", name, st)
		}
		if got := gaugeValue(t); got != 0 {
			t.Errorf("%s: gateon_update_available = %v, want 0", name, got)
		}
	}
}

// A release accepted yesterday is un-known the moment the same source serves
// a list that fails its signature: the source is no longer one to believe.
func TestASignatureFailureForgetsTheReleaseKnownBefore(t *testing.T) {
	pub, priv := testKey(t)
	h := newHarness("1.8.2", pub)
	h.publish("1.8.3", priv)
	if st := h.Check(t.Context()); !st.UpdateAvailable {
		t.Fatalf("setup: %+v", st)
	}
	h.later()
	h.publish("1.8.4", nil)
	if st := h.Check(t.Context()); st.Latest != "" || st.UpdateAvailable || st.Failure != FailureSignature {
		t.Fatalf("after an unsigned list: %+v, want nothing known", st)
	}
}

func TestABuildWithNoReleaseKeySaysItVerifiedNothing(t *testing.T) {
	h := newHarness("1.8.2")
	h.publish("1.8.3", nil)
	st := h.Check(t.Context())
	if st.State != StateOK || st.Latest != "1.8.3" || !st.UpdateAvailable || st.Signature != SignatureNoKey {
		t.Fatalf("Check = %+v, want 1.8.3 reported with no key to verify it", st)
	}
	for _, url := range h.src.asked {
		if strings.HasSuffix(url, signatureFile) {
			t.Errorf("a build with no key fetched %s", url)
		}
	}
}

func TestCheckReportsOnlyANewerRelease(t *testing.T) {
	cases := []struct {
		current, latest string
		release, newer  bool
	}{
		{"1.8.2", "1.8.3", true, true},
		{"1.8.3", "1.8.3", true, false},
		{"1.9.0", "1.8.3", true, false}, // an older "latest" is not an update
		{"dev", "1.8.3", false, false},  // a development build cannot be compared
		{"v1.8.2-next", "1.8.3", false, false},
	}
	for _, c := range cases {
		h := newHarness(c.current)
		h.publish(c.latest, nil)
		st := h.Check(t.Context())
		if st.Latest != c.latest || st.ReleaseBuild != c.release || st.UpdateAvailable != c.newer {
			t.Errorf("running %s, latest %s: %+v", c.current, c.latest, st)
		}
	}
}

func TestCheckFailures(t *testing.T) {
	down := errors.New("dial tcp: connection refused")
	cases := []struct {
		name  string
		setup func(h *harness)
		want  Failure
	}{
		{"the source does not answer", func(h *harness) { h.src.fail(down) }, FailureUnreachable},
		{"the source has no list", func(*harness) {}, FailureUnreachable},
		{"the list is an error page", func(h *harness) { h.src.set(checksumsFile, []byte("<html>oops</html>")) }, FailureMalformed},
		{"the list is too long", func(h *harness) {
			h.src.set(checksumsFile, []byte(strings.Repeat("a", MaxChecksumsBytes+1)))
		}, FailureMalformed},
		{"a source the gateway will not fetch", func(h *harness) { h.conf.SourceUrl = "http://mirror.example.com/r" }, FailureSource},
	}
	for _, c := range cases {
		h := newHarness("1.8.2")
		c.setup(h)
		st := h.Check(t.Context())
		if st.State != StateFailed || st.Failure != c.want || st.Latest != "" || st.CheckedAt != h.at {
			t.Errorf("%s: %+v, want failure %d and nothing known", c.name, st, c.want)
		}
	}
	h := newHarness("1.8.2")
	h.conf.SourceUrl = "http://mirror.example.com/r"
	h.Check(t.Context())
	if n := h.src.fetches(); n != 0 {
		t.Errorf("a refused source was fetched %d times", n)
	}
}

// One bad day at the release source does not take back what yesterday's
// check established.
func TestAnUnreachableSourceKeepsWhatWasKnown(t *testing.T) {
	pub, priv := testKey(t)
	h := newHarness("1.8.2", pub)
	h.publish("1.8.3", priv)
	h.Check(t.Context())
	h.later()
	h.src.fail(errors.New("timeout"))

	st := h.Check(t.Context())
	if st.State != StateFailed || st.Failure != FailureUnreachable {
		t.Fatalf("state %d failure %d, want failed as unreachable", st.State, st.Failure)
	}
	if st.Latest != "1.8.3" || !st.UpdateAvailable || st.Signature != SignatureVerified || st.CheckedAt != h.at {
		t.Errorf("what was known is gone: %+v", st)
	}
}

func TestCheckingSwitchedOffAsksNothing(t *testing.T) {
	h := newHarness("1.8.2")
	h.publish("1.8.3", nil)
	h.Check(t.Context())
	h.later()

	h.conf.CheckDisabled = true
	before := h.src.fetches()
	st := h.Check(t.Context())
	if st.State != StateDisabled || st.Latest != "" || st.UpdateAvailable || st.DisabledByEnv {
		t.Errorf("switched off in settings: %+v, want disabled and nothing reported", st)
	}
	if got := gaugeValue(t); got != 0 {
		t.Errorf("gateon_update_available = %v while switched off, want 0", got)
	}

	h.conf.CheckDisabled = false
	h.env.CheckOff = true
	if st := h.Check(t.Context()); st.State != StateDisabled || !st.DisabledByEnv {
		t.Errorf("switched off by the environment: %+v", st)
	}
	if n := h.src.fetches(); n != before {
		t.Errorf("the source was asked %d more times while checking was off", n-before)
	}
}

// "Check now" is a button and an RPC; neither is a way to make the gateway
// ask its release source as fast as someone can call it.
func TestChecksAreSpaced(t *testing.T) {
	h := newHarness("1.8.2")
	h.publish("1.8.3", nil)
	first := h.Check(t.Context())
	n := h.src.fetches()
	h.publish("1.8.4", nil)
	h.at = h.at.Add(manualSpacing - time.Second)
	if st := h.Check(t.Context()); st != first || h.src.fetches() != n {
		t.Errorf("a second check inside the spacing fetched again: %+v", st)
	}
	h.at = h.at.Add(2 * time.Second)
	if st := h.Check(t.Context()); st.Latest != "1.8.4" {
		t.Errorf("a check after the spacing = %+v, want 1.8.4", st)
	}
}

// What one source said is not reported for another.
func TestAChangedSourceStartsOver(t *testing.T) {
	h := newHarness("1.8.2")
	h.publish("1.8.3", nil)
	h.Check(t.Context())
	h.conf.SourceUrl = "https://mirror.example.com/releases"
	if st := h.Status(); st.State != StatePending || st.Latest != "" || st.Source != "https://mirror.example.com/releases" {
		t.Errorf("after the source changed: %+v, want pending and nothing known", st)
	}
	// And the spacing does not hold back the first check of the new source.
	if st := h.Check(t.Context()); st.Latest != "1.8.3" || st.NotesURL != "https://mirror.example.com/releases/tag/v1.8.3" {
		t.Errorf("first check of the new source: %+v", st)
	}
}

func TestRunChecksAfterStartThenEveryInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness("1.8.2")
		h.now = time.Now
		h.publish("1.8.3", nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { h.Run(ctx); close(done) }()

		synctest.Wait()
		if n := h.src.fetches(); n != 0 {
			t.Fatalf("%d fetches before the first-check delay", n)
		}
		time.Sleep(firstCheckDelay + firstCheckDelay/10 + time.Second)
		synctest.Wait()
		if n := h.src.fetches(); n != 1 {
			t.Fatalf("%d fetches after the first-check delay, want 1", n)
		}
		time.Sleep(h.env.Interval - time.Hour)
		synctest.Wait()
		if n := h.src.fetches(); n != 1 {
			t.Fatalf("%d fetches before the interval passed, want 1", n)
		}
		time.Sleep(h.env.Interval/10 + 2*time.Hour)
		synctest.Wait()
		if n := h.src.fetches(); n != 2 {
			t.Fatalf("%d fetches after one interval, want 2", n)
		}

		// A settings change brings the next check forward.
		h.publish("1.8.4", nil)
		time.Sleep(time.Minute)
		h.Kick()
		synctest.Wait()
		if st := h.Status(); st.Latest != "1.8.4" {
			t.Fatalf("after Kick: %+v, want 1.8.4", st)
		}
		cancel()
		<-done
	})
}

func TestStatusProto(t *testing.T) {
	at := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	got := Status{
		Current: "1.8.2", ReleaseBuild: true, Latest: "1.8.3", UpdateAvailable: true,
		Signature: SignatureVerified, CheckedAt: at, State: StateFailed, Failure: FailureUnreachable,
		NotesURL: "https://x/tag/v1.8.3", Source: "https://x", InstallKind: InstallKubernetes, DisabledByEnv: true,
	}.Proto()
	if got.GetCurrentVersion() != "1.8.2" || got.GetLatestVersion() != "1.8.3" || !got.GetUpdateAvailable() ||
		got.GetSignature() != gateonv1.UpdateSignature_UPDATE_SIGNATURE_VERIFIED || got.GetCheckedAt() != at.Unix() ||
		got.GetState() != gateonv1.UpdateCheckState_UPDATE_CHECK_STATE_FAILED ||
		got.GetFailure() != gateonv1.UpdateFailure_UPDATE_FAILURE_UNREACHABLE ||
		got.GetReleaseNotesUrl() != "https://x/tag/v1.8.3" || got.GetSourceUrl() != "https://x" ||
		got.GetInstallKind() != gateonv1.InstallKind_INSTALL_KIND_KUBERNETES || !got.GetDisabledByEnv() || !got.GetReleaseBuild() {
		t.Errorf("Proto = %v", got)
	}
	if never := (Status{}).Proto(); never.GetCheckedAt() != 0 {
		t.Errorf("checked_at for a check that never ran = %d, want 0", never.GetCheckedAt())
	}
	// Every value of each enum has a wire form of its own.
	if len(stateProto) != int(StateDisabled)+1 || len(signatureProto) != int(SignatureNoKey)+1 ||
		len(failureProto) != int(FailureSource)+1 || len(kindProto) != int(InstallKubernetes)+1 {
		t.Error("an enum value has no wire form")
	}
	if stateProto[StatePending] == gateonv1.UpdateCheckState_UPDATE_CHECK_STATE_UNSPECIFIED ||
		kindProto[InstallOther] == gateonv1.InstallKind_INSTALL_KIND_UNSPECIFIED {
		t.Error("a known state is reported as unspecified")
	}
}
