// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// This file is the false-positive half of the accuracy measurement, and the
// gate behind `make test-fp`.
//
// waf_corpus_test.go already proves the WAF blocks attacks. On its own that
// number means nothing: a WAF that refuses every request scores perfectly on an
// attack corpus. The control was TestWAFCorpus_BenignAllowed's eleven cases,
// which is enough to catch a WAF that broke completely and not enough to
// measure anything. Eleven samples cannot tell a 0.01% false-positive rate from
// a 5% one, and 5% of a real site's traffic is an outage.
//
// So: a corpus of traffic ordinary applications actually serve, held to exactly
// zero blocks. A false positive here is not a tuning opportunity, it is a user
// who cannot check out, and the build fails on the first one.
//
// Scope, stated so the number is not read as more than it is: this exercises
// the WAF middleware, which is the component that carries rules. The deployed
// chain has other things that can refuse a request — the reputation blocker,
// the honeypot's ban, bot management — and they are not covered here. They key
// off client identity and history rather than request content, so they need a
// different harness than a corpus of requests replayed statelessly.

// corpusSample is one request a real application serves.
//
// Note is not decoration. A case with no stated reason to exist is a case the
// next person deletes to make the build green, which is the failure mode this
// whole file exists to prevent.
type corpusSample struct {
	Name    string            `json:"name"`
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Note    string            `json:"note,omitempty"`

	// Profiles names the app profiles this traffic needs to be allowed. Empty
	// means it must pass on the shipped default, which is the case for almost
	// everything here.
	//
	// A profile is how gateon says "this application's purpose is to carry text
	// a WAF would otherwise refuse" — a paste service, an issue tracker, a
	// security wiki. It is a scoped exception and never a weaker ruleset
	// (mem:gwaf_v040, TestAppProfileIsScopedNotAGlobalOff).
	Profiles []string `json:"profiles,omitempty"`

	// ScopePaths and ScopeFields are the deployment half of a profile: which of
	// this application's routes and field names hold the content that trips those
	// rules. A profile without them is what gateon shipped, and it did nothing
	// outside Jira's own /rest/api/* — see appprofile_scope.go.
	ScopePaths  []string `json:"scope_paths,omitempty"`
	ScopeFields []string `json:"scope_fields,omitempty"`

	// KnownFP records that this sample is refused today and states why, keyed by
	// paranoia level ("1", "2"). Absent means the sample must pass at that level.
	//
	// This is a characterisation field, exactly like TestWAFCorpus_KnownDetectionGaps
	// on the false-negative side: it asserts today's behaviour so a change in
	// either direction is visible. A refusal with a written reason is a debt
	// someone chose; a refusal with no reason is a bug nobody noticed. When one
	// is fixed the gate fails and tells you to clear the entry, so a fix is
	// promoted rather than quietly absorbed.
	//
	// Keyed by level rather than a single flag because most of these are the
	// price of raising paranoia, and averaging the two levels together would
	// hide exactly the thing an operator deciding between them needs to see.
	KnownFP map[string]string `json:"known_fp,omitempty"`
}

// knownFPAt returns the recorded reason for this sample at a paranoia level.
func (s corpusSample) knownFPAt(paranoia int) string {
	return s.KnownFP[strconv.Itoa(paranoia)]
}

// corpusHost is the origin the corpus gateway serves.
//
// Declaring it matters. gwaf's off-origin rules report nothing when no origins
// are configured (see mem:gwaf_v040), so a corpus that left Origins empty would
// never exercise the open-redirect and SSRF rules — and a redirect parameter
// carrying an ordinary relative path is one of the likeliest false positives
// there is. An unarmed rule cannot produce one, which would make the corpus
// look cleaner than the gateway is.
const corpusHost = "app.example.com"

// loadBenignCorpus reads every .jsonl file under testdata/benign.
//
// The format is one JSON object per line, because the corpus is appended to far
// more often than it is rewritten and a line-oriented file gives a reviewable
// diff when someone adds twenty cases. Lines that are blank or begin with # are
// skipped so the files can carry section headings; a corpus nobody can read is
// a corpus nobody extends.
func loadBenignCorpus(t *testing.T) map[string][]corpusSample {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join("testdata", "benign", "*.jsonl"))
	if err != nil {
		t.Fatalf("glob corpus: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no corpus files found under testdata/benign — the false-positive " +
			"gate cannot pass vacuously")
	}
	sort.Strings(paths)

	out := make(map[string][]corpusSample, len(paths))
	seen := make(map[string]string)
	for _, p := range paths {
		category := strings.TrimSuffix(filepath.Base(p), ".jsonl")
		f, err := os.Open(p) // #nosec G304 -- test-only, path comes from a glob of testdata
		if err != nil {
			t.Fatalf("open %s: %v", p, err)
		}

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for line := 1; sc.Scan(); line++ {
			text := strings.TrimSpace(sc.Text())
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			var s corpusSample
			if err := json.Unmarshal([]byte(text), &s); err != nil {
				t.Errorf("%s:%d: malformed sample: %v", p, line, err)
				continue
			}
			switch {
			case s.Name == "":
				t.Errorf("%s:%d: sample has no name", p, line)
				continue
			case s.Path == "":
				t.Errorf("%s:%d: sample %q has no path", p, line, s.Name)
				continue
			case s.Note == "":
				t.Errorf("%s:%d: sample %q has no note; state why this is traffic a "+
					"real application serves, or the next person will delete it to "+
					"green the build", p, line, s.Name)
				continue
			}
			id := category + "/" + s.Name
			if prev, dup := seen[id]; dup {
				t.Errorf("%s:%d: duplicate sample name %q (first at %s); duplicates "+
					"inflate the corpus count without adding coverage", p, line, s.Name, prev)
				continue
			}
			seen[id] = fmt.Sprintf("%s:%d", p, line)
			out[category] = append(out[category], s)
		}
		if err := sc.Err(); err != nil {
			t.Errorf("read %s: %v", p, err)
		}
		_ = f.Close()
	}
	return out
}

// fpCorpusHandler builds the WAF a deployment at the given paranoia level gets.
//
// DisableWordPress mirrors the factory's default (`!w.GetWordpress()` in
// waf_factory.go): the WordPress admin lockdown refuses ordinary WordPress
// traffic by design and is opt-in, so leaving it on would measure a
// configuration nobody ships and report its refusals as false positives.
func fpCorpusHandler(t *testing.T, paranoia int, s corpusSample) http.Handler {
	t.Helper()
	mw, err := WAF(WAFConfig{
		ParanoiaLevel:         paranoia,
		DisableWordPress:      true,
		Origins:               []string{corpusHost},
		AppProfiles:           s.Profiles,
		AppProfileScopePaths:  s.ScopePaths,
		AppProfileScopeFields: s.ScopeFields,
	})
	if err != nil {
		t.Fatalf("create WAF at PL%d profiles=%v: %v", paranoia, s.Profiles, err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// handlerFor returns a handler configured for this sample's profiles, reusing
// one per distinct profile set. Engines are expensive to build and the corpus
// replays hundreds of samples, so building one per sample would make the gate
// slow enough that someone would stop running it.
func handlerFor(t *testing.T, paranoia int, cache map[string]http.Handler, s corpusSample) http.Handler {
	t.Helper()
	key := strings.Join(s.Profiles, ",") + "|" +
		strings.Join(s.ScopePaths, ",") + "|" + strings.Join(s.ScopeFields, ",")
	if h, ok := cache[key]; ok {
		return h
	}
	h := fpCorpusHandler(t, paranoia, s)
	cache[key] = h
	return h
}

// serveSample replays one sample and returns the status and the response body.
func serveSample(h http.Handler, s corpusSample) (int, string) {
	method := s.Method
	if method == "" {
		method = http.MethodGet
	}

	var body io.Reader = strings.NewReader(s.Body)

	// Origin-form target, not an absolute URL.
	//
	// httptest.NewRequest copies the target verbatim into RequestURI, and the WAF
	// hands RequestURI to the engine as the request line. Building this with
	// "https://host/path" therefore made every rule and every exception see
	// "https://app.example.com/pastes" as the path — which no real request
	// carries, and which silently prevented any path-scoped exception from
	// matching. The Host is set on the field instead, which is where a real
	// request keeps it.
	req := httptest.NewRequest(method, s.Path, body)
	req.Host = corpusHost
	req.TLS = nil
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	if s.Body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if req.Header.Get("User-Agent") == "" {
		// A stock browser agent. Left empty, the scanner rules would have a
		// missing-agent signal to work with and every sample would be measuring
		// that instead of its own payload.
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "+
			"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
	}
	req = req.WithContext(context.WithValue(req.Context(),
		request.RequestStateContextKey{}, &request.RequestState{}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	respBody, _ := io.ReadAll(rr.Body)
	return rr.Code, strings.TrimSpace(string(respBody))
}

// runFPCorpus replays the whole corpus and enforces the ratchet.
//
// Three outcomes, and the middle one is the point of the design:
//
//   - a sample passes and is not marked        → fine, the normal case
//   - a sample is refused and is not marked    → FALSE POSITIVE, build fails
//   - a sample is refused and carries known_fp → recorded debt, reported not failed
//   - a sample passes but still carries known_fp → build fails, clear the field
//
// The last one is what stops the recorded set becoming a graveyard. A gate that
// only fails on new problems lets fixed ones sit in the file forever, until the
// list is long enough that nobody reads it and a real regression hides inside.
func runFPCorpus(t *testing.T, paranoia int) {
	t.Helper()

	corpus := loadBenignCorpus(t)
	cache := make(map[string]http.Handler)

	var total, unexpected, recorded, fixed int
	for _, category := range sortedKeys(corpus) {
		t.Run(category, func(t *testing.T) {
			for _, s := range corpus[category] {
				total++
				status, respBody := serveSample(handlerFor(t, paranoia, cache, s), s)
				passed := status == http.StatusOK
				known := s.knownFPAt(paranoia)

				switch {
				case passed && known == "":
					// The normal case.
				case passed && known != "":
					fixed++
					t.Errorf("RECORDED FALSE POSITIVE NOW PASSES AT PL%d: %s\n"+
						"  request: %s %s\n"+
						"  recorded reason: %s\n"+
						"  Clear the \"%d\" entry in known_fp on this sample. Leaving it set "+
						"means the next real regression here is reported as expected debt.",
						paranoia, s.Name, methodOf(s), s.Path, known, paranoia)
				case !passed && known != "":
					recorded++
				default:
					unexpected++
					t.Errorf("FALSE POSITIVE: %s\n"+
						"  request:    %s %s\n"+
						"  why benign: %s\n"+
						"  profiles:   %s\n"+
						"  got:        %d (want 200)\n"+
						"  response:   %s\n"+
						"  Either this is a rule that needs fixing, or it is debt someone "+
						"is choosing — add a known_fp entry for level %d with the reason if so.",
						s.Name, methodOf(s), s.Path, s.Note,
						orNone(strings.Join(s.Profiles, ",")), status, orNone(respBody), paranoia)
				}
			}
		})
	}

	if total == 0 {
		t.Fatal("corpus loaded zero samples — the gate would pass vacuously")
	}
	t.Logf("false-positive corpus at PL%d: %d samples, %d new false positives, "+
		"%d recorded, %d recorded-but-now-passing (%.2f%% refused overall)",
		paranoia, total, unexpected, recorded, fixed,
		100*float64(unexpected+recorded)/float64(total))
}

func methodOf(s corpusSample) string {
	if s.Method == "" {
		return http.MethodGet
	}
	return s.Method
}

func orNone(s string) string {
	if s == "" {
		return "(none reported)"
	}
	return s
}

func sortedKeys(m map[string][]corpusSample) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestWAFFalsePositives_PL1 is the gate for the shipped default.
//
// Paranoia 1 is what a standard-tier install runs, so a block here is a refusal
// a real user would have received. Zero tolerance: this is the number `make
// test-fp` exists to keep at zero.
func TestWAFFalsePositives_PL1(t *testing.T) { runFPCorpus(t, 1) }

// TestWAFFalsePositives_PL2 covers the enterprise paranoia level.
//
// PL2 is where the structural data-leak rules switch on (mem:dlp: credentials
// sit at PL1, structural disclosure at PL2 because a site whose job is to
// display stack traces serves them legitimately). It is the level with the most
// room for a false positive, so it is measured separately rather than folded
// into PL1 — if the two ever need different expectations, that difference
// should be visible rather than averaged away.
func TestWAFFalsePositives_PL2(t *testing.T) { runFPCorpus(t, 2) }

// TestBenignCorpusIsLargeEnoughToMeanSomething guards the measurement itself.
//
// The gate's credibility is entirely a function of corpus size: passing on
// eleven samples is what the old control did, and it caught nothing. This does
// not assert a good corpus — no test can — but it does stop the corpus being
// quietly emptied, and it makes the floor a decision someone has to edit rather
// than a number that drifts.
func TestBenignCorpusIsLargeEnoughToMeanSomething(t *testing.T) {
	const floor = 400

	corpus := loadBenignCorpus(t)
	total := 0
	for _, samples := range corpus {
		total += len(samples)
	}
	if total < floor {
		t.Errorf("benign corpus holds %d samples, want at least %d — a false-positive "+
			"rate measured on fewer is not a rate, it is an anecdote", total, floor)
	}

	// Categories matter as much as the count. Ten thousand pagination requests
	// would clear any floor and prove only that pagination works.
	const minCategories = 8
	if len(corpus) < minCategories {
		t.Errorf("benign corpus spans %d categories, want at least %d — breadth is "+
			"what finds a false positive, not volume", len(corpus), minCategories)
	}
}

// TestBenignCorpusSamplesAreDistinct catches the other way a corpus inflates.
//
// Two samples with different names and the same request are one sample. This
// compares the replayed request rather than the JSON, so reformatting a case
// does not trip it but copying one does.
func TestBenignCorpusSamplesAreDistinct(t *testing.T) {
	corpus := loadBenignCorpus(t)
	seen := make(map[string]string)
	for _, category := range sortedKeys(corpus) {
		for _, s := range corpus[category] {
			var key bytes.Buffer
			key.WriteString(methodOf(s))
			key.WriteString(" ")
			key.WriteString(s.Path)
			key.WriteString("\n")
			for _, h := range sortedHeaderKeys(s.Headers) {
				fmt.Fprintf(&key, "%s: %s\n", h, s.Headers[h])
			}
			key.WriteString(s.Body)

			id := category + "/" + s.Name
			if prev, dup := seen[key.String()]; dup {
				t.Errorf("%s is byte-identical to %s; a duplicate raises the corpus "+
					"count without raising its coverage", id, prev)
				continue
			}
			seen[key.String()] = id
		}
	}
}

func sortedHeaderKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
