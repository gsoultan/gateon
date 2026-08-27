// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/types"
)

// specByID returns the built-in rule with the given id.
func specByID(t *testing.T, id uint32) spec {
	t.Helper()
	for _, s := range defaultSpecs {
		if s.id == id {
			return s
		}
	}
	t.Fatalf("rule %d is not in the corpus", id)
	return spec{}
}

// Every credential below is syntactically valid and none has ever been issued:
// the provider's own documentation example where one exists, and filler in the
// provider's alphabet where it does not.
//
// Each is spelled as a prefix concatenated with its body. Go folds that back to
// one constant, so the corpus is unchanged, but no single literal matches a
// provider pattern — which matters because a secret scanner cannot tell a
// credential detector's own test corpus from a leak, and blocks the push.
// Keep new fixtures in this shape.
const (
	fakeGitHubApp = "gho_" + "16C7e42F292c6912E7710c838347Ae178B4a"
	fakeGitHubSvc = "ghs_" + "16C7e42F292c6912E7710c838347Ae178B4a"
	// Exactly 82 characters after the prefix — the width GitHub issues and the
	// width the rule requires, so a shorter lookalike does not match.
	fakePAT       = "github_pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRST"
	fakeOpenAI    = "sk-proj-" + "abcdefghij1234567890T3BlbkFJabcdefghij1234567890"
	fakeAnthropic = "sk-ant-api03-" + "abcdefghijklmnopqrstuvwxyz0123456789" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abcdefghij"
	fakeSlack = "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
	// 22 then 43, the two field widths SendGrid issues.
	fakeSendGrid = "SG." + "ABCDEFGHIJKLMNOPQRSTUV" + "." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
	fakeTwilio   = "AC" + "0123456789abcdef0123456789abcdef"
	// The API key shares the SID's body; only the prefix distinguishes them,
	// which is the whole of what the rule keys on.
	fakeTwilioKey = "SK" + "0123456789abcdef0123456789abcdef"
	fakeNPM       = "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	fakePyPI      = "pypi-AgEIcHlwaS5vcmc" +
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	fakeAzureKey = "AccountKey=" +
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
		"abcdefghijklmnopqrstuvwx=="

	// Stripe's published documentation key. All four variants share one body,
	// which is exactly what makes the live/test and secret/publishable
	// distinctions the rule draws worth asserting.
	stripeBody     = "4eC39HqLyjWDarjtT1zdp7dc"
	fakeStripeLive = "sk_live_" + stripeBody
	fakeStripeRK   = "rk_live_" + stripeBody
	fakeStripeTest = "sk_test_" + stripeBody
	fakeStripePub  = "pk_live_" + stripeBody
)

// TestDLPDetectors exercises each response-phase detector against a payload it
// must catch and payloads it must not. The negative half is the half that
// decides whether an operator leaves DLP switched on.
func TestDLPDetectors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		id     uint32
		name   string
		hits   []string
		misses []string
	}{
		{
			id: 1130008, name: "stripe",
			hits: []string{
				`{"key":"` + fakeStripeLive + `"}`,
				fakeStripeRK,
			},
			misses: []string{
				fakeStripeTest, // test keys are not a leak
				"sk_live_short",
				fakeStripePub, // publishable, by design public
			},
		},
		{
			id: 1130009, name: "github-token",
			hits:   []string{fakeGitHubApp, fakeGitHubSvc},
			misses: []string{"gho_tooshort", "ghx_16C7e42F292c6912E7710c838347Ae178B4a"},
		},
		{
			id: 1130010, name: "github-fine-grained-pat",
			hits:   []string{fakePAT},
			misses: []string{"github_pat_tooshort", "github_pat_"},
		},
		{
			id: 1130011, name: "openai",
			hits: []string{fakeOpenAI},
			misses: []string{
				// No T3BlbkFJ marker: an sk- prefix alone is not an OpenAI key.
				"sk-abcdefghijklmnopqrstuvwxyz1234567890",
				"sk-ant-api03-notopenai",
			},
		},
		{
			id: 1130012, name: "anthropic",
			hits:   []string{fakeAnthropic},
			misses: []string{"sk-ant-api03-short", "sk-ant-"},
		},
		{
			id: 1130013, name: "slack",
			hits:   []string{fakeSlack, "xoxp-123456789012-abcdefghijkl"},
			misses: []string{"xoxb-short", "xoxz-123456789012-abcdefghijkl"},
		},
		{
			id: 1130014, name: "sendgrid",
			hits:   []string{fakeSendGrid},
			misses: []string{"SG.tooshort.tooshort", "SG."},
		},
		{
			id: 1130015, name: "twilio",
			hits:   []string{fakeTwilio, fakeTwilioKey},
			misses: []string{"0123456789abcdef0123456789abcdef", "ACnothex"},
		},
		{
			id: 1130016, name: "npm",
			hits:   []string{fakeNPM},
			misses: []string{"npm_short", "npmrc_abcdefghijklmnopqrstuvwxyz0123456789"},
		},
		{
			id: 1130017, name: "pypi",
			hits:   []string{fakePyPI},
			misses: []string{"pypi-AgEIcHlwaS5vcmc", "pypi-short"},
		},
		{
			id: 1130018, name: "gcp-service-account",
			hits: []string{
				`{"type": "service_account", "project_id": "prod"}`,
				`{"type":"service_account"}`,
			},
			misses: []string{`{"type": "user_account"}`, `{"type": "service"}`},
		},
		{
			id: 1130019, name: "azure-storage-key",
			hits:   []string{fakeAzureKey},
			misses: []string{"AccountKey=short==", "AccountName=devstoreaccount1"},
		},
		{
			id: 1130020, name: "db-connection-string",
			hits: []string{
				"postgres://app:s3cr3t@db.internal:5432/prod",
				"mongodb+srv://svc:hunter2@cluster0.example.net/app",
				"redis://default:p4ss@cache:6379",
			},
			misses: []string{
				"postgres://db.internal:5432/prod", // no credentials to leak
				"https://user:pass@example.com",    // not a database URI
				"postgres://app@db.internal:5432/prod",
			},
		},
		{
			id: 1130021, name: "putty-key",
			hits:   []string{"PuTTY-User-Key-File-3: ssh-ed25519"},
			misses: []string{"PuTTY user guide", "putty-user-key-file"},
		},
		{
			id: 1130022, name: "go-panic",
			hits:   []string{"panic: runtime error\n\ngoroutine 1 [running]:\nmain.main()"},
			misses: []string{"goroutines are cheap", "goroutine leak detected"},
		},
		{
			id: 1130023, name: "python-traceback",
			hits:   []string{"Traceback (most recent call last):\n  File \"app.py\", line 3"},
			misses: []string{"traceback module", "Traceback:"},
		},
		{
			id: 1130024, name: "java-stack-trace",
			hits:   []string{"\tat com.example.svc.Handler.handle(Handler.java:42)"},
			misses: []string{"at com.example.svc.Handler.handle", "at Handler.java"},
		},
		{
			id: 1130025, name: "php-error",
			hits: []string{
				"Fatal error: Uncaught Error: Call to undefined function " +
					"foo() in /var/www/html/index.php on line 12",
			},
			misses: []string{"Fatal error: something went wrong", "on line 12"},
		},
		{
			id: 1130026, name: "dotnet-exception",
			hits: []string{
				"System.NullReferenceException: Object reference not set. " +
					"at MyApp.Controllers.Home.Index(",
			},
			// Naming the exception type is not disclosing a trace; an API that
			// returns a typed error code should not block.
			misses: []string{"System.NullReferenceException", "catch (System.Exception)"},
		},
		{
			id: 1130027, name: "ruby-backtrace",
			hits:   []string{"app/controllers/users_controller.rb:12:in `index'"},
			misses: []string{"users_controller.rb", "config.rb:12"},
		},
		{
			id: 1130028, name: "sql-error-text",
			hits: []string{
				"You have an error in your SQL syntax; check the manual",
				"SQLSTATE[42S02]: Base table or view not found",
				"org.postgresql.util.PSQLException: ERROR: relation does not exist",
			},
			misses: []string{"SQL syntax highlighting", "SQLSTATE"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := specByID(t, tc.id)

			if s.category != CategoryDLP {
				t.Errorf("rule %d is not in the DLP category", tc.id)
			}
			if s.phase != types.PhaseResponseBody {
				t.Errorf("rule %d does not run at the response-body phase", tc.id)
			}

			for _, hit := range tc.hits {
				if _, ok := s.op.Eval(nil, []byte(hit)); !ok {
					t.Errorf("rule %d missed %q", tc.id, truncate(hit))
				}
			}
			for _, miss := range tc.misses {
				if _, ok := s.op.Eval(nil, []byte(miss)); ok {
					t.Errorf("rule %d false-positived on %q", tc.id, truncate(miss))
				}
			}
		})
	}
}

// TestDLPStructuralRulesAreNotPL1 pins the gradient the corpus depends on: a
// credential prefix is unambiguous and blocks wherever DLP is on, while a stack
// trace is something a site may legitimately serve, so it waits for the
// paranoia level enterprise tier sets. Without this, an error tracker or a CI
// dashboard behind a standard-tier DLP opt-in would 403 its own pages.
func TestDLPStructuralRulesAreNotPL1(t *testing.T) {
	t.Parallel()

	for _, s := range defaultSpecs {
		if s.category != CategoryDLP {
			continue
		}
		structural := false
		for _, tag := range s.tags {
			if tag == TagLeakage {
				structural = true
			}
		}
		if structural && s.pl < 2 {
			t.Errorf("rule %d is a structural-disclosure rule at PL%d; it should "+
				"wait for PL2 so a DLP opt-in alone does not block error pages",
				s.id, s.pl)
		}
	}
}

func truncate(s string) string {
	if len(s) <= 60 {
		return s
	}
	return s[:57] + "..."
}

// TestDLPCorpusIsWiredIntoThePolicy checks the new detectors actually reach a
// compiled engine rather than only existing in the table.
func TestDLPCorpusIsWiredIntoThePolicy(t *testing.T) {
	t.Parallel()

	set := Policy{ParanoiaLevel: 2, ResponseInspection: true}.Ruleset()
	found := make(map[uint32]bool, len(set))
	for _, r := range set {
		found[uint32(r.ID)] = true
	}
	for id := uint32(1130008); id <= 1130028; id++ {
		if !found[id] {
			t.Errorf("rule %d never reached the compiled ruleset", id)
		}
	}

	// And that turning DLP off still takes all of them away.
	off := Policy{ParanoiaLevel: 2, ResponseInspection: true,
		DisabledTags: map[string]bool{"dlp": true}}.Ruleset()
	for _, r := range off {
		if strings.HasPrefix(r.Msg, "Card number") || uint32(r.ID) >= 1130008 && uint32(r.ID) <= 1130028 {
			t.Errorf("rule %d survived the dlp tag being disabled", r.ID)
		}
	}
}
