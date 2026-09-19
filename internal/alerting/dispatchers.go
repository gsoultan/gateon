// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

type SlackDispatcher struct {
	webhookURL string
	channel    string
}

func NewSlackDispatcher(webhookURL, channel string) *SlackDispatcher {
	return &SlackDispatcher{webhookURL: webhookURL, channel: channel}
}

func (d *SlackDispatcher) Send(ctx context.Context, threat telemetry.SecurityThreat) error {
	payload := map[string]any{
		"text": slackText(threat),
	}
	if d.channel != "" {
		payload["channel"] = d.channel
	}
	return sendWebhook(ctx, d.webhookURL, payload)
}

// slackEscaper neutralises the three characters Slack parses in message text:
// "<...>" is a link, mention or command, so a request path carrying
// "<!channel>" pinged the whole alert channel. Slack only unescapes these
// three entities, which is why html.EscapeString (which also rewrites quotes)
// is not used here.
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// slackText renders the alert as Slack message text. Every field that came
// from the request is escaped; the markup is the alert's own.
func slackText(threat telemetry.SecurityThreat) string {
	return fmt.Sprintf("🚨 *Gateon Security Alert*\n*Type:* %s\n*Source IP:* %s\n*Score:* %.2f\n*Details:* %s\n*Route:* %s\n*URI:* %s",
		slackEscaper.Replace(threat.Type), slackEscaper.Replace(threat.SourceIP), threat.Score,
		slackEscaper.Replace(threat.Details), slackEscaper.Replace(threat.RouteID), slackEscaper.Replace(threat.RequestURI))
}

type DiscordDispatcher struct {
	webhookURL string
}

func NewDiscordDispatcher(webhookURL string) *DiscordDispatcher {
	return &DiscordDispatcher{webhookURL: webhookURL}
}

func (d *DiscordDispatcher) Send(ctx context.Context, threat telemetry.SecurityThreat) error {
	payload := map[string]any{
		"content": "🚨 **Gateon Security Alert**",
		"embeds": []map[string]any{
			{
				"title": fmt.Sprintf("Threat Detected: %s", threat.Type),
				"color": 15158332, // Red
				"fields": []map[string]any{
					{"name": "Source IP", "value": threat.SourceIP, "inline": true},
					{"name": "Score", "value": fmt.Sprintf("%.2f", threat.Score), "inline": true},
					{"name": "Route", "value": threat.RouteID, "inline": true},
					{"name": "Details", "value": threat.Details},
					{"name": "URI", "value": threat.RequestURI},
				},
				"timestamp": threat.Time.Format(time.RFC3339),
			},
		},
	}
	return sendWebhook(ctx, d.webhookURL, payload)
}

type WebhookDispatcher struct {
	webhookURL string
}

func NewWebhookDispatcher(webhookURL string) *WebhookDispatcher {
	return &WebhookDispatcher{webhookURL: webhookURL}
}

func (d *WebhookDispatcher) Send(ctx context.Context, threat telemetry.SecurityThreat) error {
	return sendWebhook(ctx, d.webhookURL, threat)
}

type TelegramDispatcher struct {
	botToken string
	chatID   string
}

func NewTelegramDispatcher(botToken, chatID string) *TelegramDispatcher {
	return &TelegramDispatcher{botToken: botToken, chatID: chatID}
}

func (d *TelegramDispatcher) Send(ctx context.Context, threat telemetry.SecurityThreat) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", d.botToken)
	payload := map[string]any{
		"chat_id":    d.chatID,
		"text":       telegramText(threat),
		"parse_mode": "HTML",
	}

	return sendWebhook(ctx, url, payload)
}

// telegramText renders the alert for Telegram's parse_mode=HTML.
//
// Telegram rejects a message whose text contains a "<" that does not open one
// of the tags it supports, or a stray "&". Details and RequestURI come from
// the request that triggered the alert -- an XSS detection quotes the matched
// "<script" -- so the alerts most worth delivering were exactly the ones the
// API refused, and the error was logged where nobody was looking for it.
func telegramText(threat telemetry.SecurityThreat) string {
	return fmt.Sprintf("<b>🚨 Gateon Security Alert</b>\n"+
		"<b>Type:</b> %s\n"+
		"<b>Source IP:</b> %s\n"+
		"<b>Score:</b> %.2f\n"+
		"<b>Details:</b> %s\n"+
		"<b>Route:</b> %s\n"+
		"<b>URI:</b> %s",
		html.EscapeString(threat.Type), html.EscapeString(threat.SourceIP), threat.Score,
		html.EscapeString(threat.Details), html.EscapeString(threat.RouteID), html.EscapeString(threat.RequestURI))
}

func sendWebhook(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
