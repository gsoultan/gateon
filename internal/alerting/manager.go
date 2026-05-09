package alerting

import (
	"context"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// AlertingManager handles security alerts and playbooks.
type AlertingManager struct {
	mu          sync.RWMutex
	config      *gateonv1.AlertingConfig
	dispatchers map[string]Dispatcher
}

// Dispatcher is the interface for alert delivery.
type Dispatcher interface {
	Send(ctx context.Context, threat telemetry.SecurityThreat) error
}

var (
	manager *AlertingManager
	once    sync.Once
)

// Init initializes the global AlertingManager.
func Init(cfg *gateonv1.AlertingConfig) {
	once.Do(func() {
		manager = &AlertingManager{
			config:      cfg,
			dispatchers: make(map[string]Dispatcher),
		}
		manager.reconfigure()
	})
}

// UpdateConfig updates the manager with new configuration.
func UpdateConfig(cfg *gateonv1.AlertingConfig) {
	if manager == nil {
		Init(cfg)
		return
	}
	manager.mu.Lock()
	manager.config = cfg
	manager.mu.Unlock()
	manager.reconfigure()
}

func (m *AlertingManager) reconfigure() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.config == nil || !m.config.Enabled {
		m.dispatchers = make(map[string]Dispatcher)
		return
	}

	newDispatchers := make(map[string]Dispatcher)
	for _, d := range m.config.Dispatchers {
		switch d.Type {
		case "slack":
			newDispatchers[d.Id] = NewSlackDispatcher(d.WebhookUrl, d.SlackChannel)
		case "discord":
			newDispatchers[d.Id] = NewDiscordDispatcher(d.WebhookUrl)
		case "webhook":
			newDispatchers[d.Id] = NewWebhookDispatcher(d.WebhookUrl)
		case "telegram":
			newDispatchers[d.Id] = NewTelegramDispatcher(d.TelegramBotToken, d.TelegramChatId)
		}
	}
	m.dispatchers = newDispatchers
}

// HandleThreat processes a security threat and triggers alerts based on playbooks.
func HandleThreat(threat telemetry.SecurityThreat) {
	if manager == nil {
		return
	}
	manager.process(threat)
}

func (m *AlertingManager) process(threat telemetry.SecurityThreat) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config == nil || !m.config.Enabled {
		return
	}

	for _, pb := range m.config.Playbooks {
		if m.matchPlaybook(pb, threat) {
			m.executePlaybook(pb, threat)
		}
	}
}

func (m *AlertingManager) matchPlaybook(pb *gateonv1.AlertPlaybook, threat telemetry.SecurityThreat) bool {
	// Match event type
	if pb.EventType != "all" && pb.EventType != threat.Type {
		// Special cases for generic event types
		if pb.EventType == "high_anomaly" && threat.Score < pb.Threshold {
			return false
		}
		if pb.EventType != threat.Type {
			return false
		}
	}

	// Match threshold
	if threat.Score < pb.Threshold {
		return false
	}

	return true
}

func (m *AlertingManager) executePlaybook(pb *gateonv1.AlertPlaybook, threat telemetry.SecurityThreat) {
	for _, dID := range pb.DispatcherIds {
		if d, ok := m.dispatchers[dID]; ok {
			go func(disp Dispatcher, t telemetry.SecurityThreat) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := disp.Send(ctx, t); err != nil {
					logger.L.LogError("failed to send alert", "dispatcher", dID, "error", err)
				}
			}(d, threat)
		}
	}

	// Handle actions like "block" (XDP shunning)
	if pb.Action == "block" && threat.SourceIP != "" {
		// This is already partially handled by telemetry.RecordSecurityThreat -> eBPF manager
		// but we can make it more explicit here if needed.
	}
}
