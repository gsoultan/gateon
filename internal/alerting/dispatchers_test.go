// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestTelegramTextEscapesGatewayObservedStrings is the regression test for
// alerts that never arrived. The Telegram message is sent with parse_mode=HTML,
// and Telegram rejects a message whose text contains a "<" that does not open
// one of the tags it supports (or a stray "&"). Details and RequestURI come
// from the request that triggered the alert -- for an XSS detection the
// details quote the matched "<script" -- so the alerts most worth delivering
// were exactly the ones the API refused with "can't parse entities".
func TestTelegramTextEscapesGatewayObservedStrings(t *testing.T) {
	threat := telemetry.SecurityThreat{
		Type:       "xss_detected",
		SourceIP:   "203.0.113.9",
		Score:      50,
		Details:    "XSS pattern(s) '<script' found in query string",
		RouteID:    "shop",
		RequestURI: "/search?q=<script>alert(1)</script>&x=1",
	}

	text := telegramText(threat)

	for _, raw := range []string{"<script", "</script>", "&x="} {
		if strings.Contains(text, raw) {
			t.Errorf("%q reached a parse_mode=HTML message unescaped:\n%s", raw, text)
		}
	}
	if !strings.Contains(text, "&lt;script") {
		t.Errorf("payload should survive as an entity, got:\n%s", text)
	}
	if !strings.Contains(text, "<b>Details:</b>") {
		t.Errorf("the alert's own markup was lost:\n%s", text)
	}
}

// TestSlackTextEscapesControlSequences: Slack parses <...> in message text as
// links, mentions and commands, so a request path carrying "<!channel>"
// pinged every member of the alert channel, and "<url|label>" placed an
// attacker-chosen link in the alert. Slack's own guidance is to escape &, <
// and > in any text it did not write.
func TestSlackTextEscapesControlSequences(t *testing.T) {
	threat := telemetry.SecurityThreat{
		Type:       "honeypot_triggered",
		SourceIP:   "203.0.113.9",
		Score:      100,
		Details:    "Access to deception trap path: /.env",
		RouteID:    "shop",
		RequestURI: "/.env?<!channel>&x=<http://evil.example|click>",
	}

	text := slackText(threat)

	for _, raw := range []string{"<!channel>", "<http://evil.example|click>", "&x="} {
		if strings.Contains(text, raw) {
			t.Errorf("%q reached Slack message text unescaped:\n%s", raw, text)
		}
	}
	if !strings.Contains(text, "&lt;!channel&gt;") {
		t.Errorf("mention should survive as entities, got:\n%s", text)
	}
	if !strings.Contains(text, "*Details:*") {
		t.Errorf("the alert's own markup was lost:\n%s", text)
	}
}
