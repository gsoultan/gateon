// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"context"
	"net"
	"strings"
	"testing"
)

// TestSendErrorDoesNotQuoteTheWebhook: a failed send's error quoted the whole
// URL, which for a Slack or Discord incoming webhook, and for Telegram's bot
// API, is the credential. The manager logs send errors, and every viewer can
// read the log stream -- so a timeout or a DNS failure published the webhook,
// or the bot token, to the lowest role there is.
func TestSendErrorDoesNotQuoteTheWebhook(t *testing.T) {
	const secret = "T0KEN-7f3a9c1e5b"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	for name, url := range map[string]string{
		"refused":   "http://" + closed + "/services/" + secret,
		"malformed": "http://[::1]:port/bot" + secret + "/sendMessage",
	} {
		err := sendWebhook(context.Background(), url, map[string]string{"text": "x"})
		if err == nil {
			t.Fatalf("%s: the send succeeded", name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the send error quotes the webhook's secret: %v", name, err)
		}
	}
}
