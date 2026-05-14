package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
		"text": fmt.Sprintf("🚨 *Gateon Security Alert*\n*Type:* %s\n*Source IP:* %s\n*Score:* %.2f\n*Details:* %s\n*Route:* %s\n*URI:* %s",
			threat.Type, threat.SourceIP, threat.Score, threat.Details, threat.RouteID, threat.RequestURI),
	}
	if d.channel != "" {
		payload["channel"] = d.channel
	}
	return sendWebhook(ctx, d.webhookURL, payload)
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
	text := fmt.Sprintf("<b>🚨 Gateon Security Alert</b>\n"+
		"<b>Type:</b> %s\n"+
		"<b>Source IP:</b> %s\n"+
		"<b>Score:</b> %.2f\n"+
		"<b>Details:</b> %s\n"+
		"<b>Route:</b> %s\n"+
		"<b>URI:</b> %s",
		threat.Type, threat.SourceIP, threat.Score, threat.Details, threat.RouteID, threat.RequestURI)

	payload := map[string]any{
		"chat_id":    d.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}

	return sendWebhook(ctx, url, payload)
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
