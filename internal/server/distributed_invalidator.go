package server

import (
	"context"
	"encoding/json"
	"os"

	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/redis"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const InvalidationChannel = "gateon:config:invalidation"

type InvalidationMessage struct {
	Type   string `json:"type"` // "route", "all", "tls"
	ID     string `json:"id,omitzero"`
	NodeID string `json:"node_id"`
}

type distributedProxyInvalidator struct {
	local  proxy.Invalidator
	redis  redis.Client
	nodeID string
}

// NewDistributedProxyInvalidator wraps a local invalidator and broadcasts events via Redis.
func NewDistributedProxyInvalidator(local proxy.Invalidator, redis redis.Client) proxy.Invalidator {
	nodeID, _ := os.Hostname()
	if nodeID == "" {
		nodeID = "unknown"
	}
	return &distributedProxyInvalidator{
		local:  local,
		redis:  redis,
		nodeID: nodeID,
	}
}

func (i *distributedProxyInvalidator) InvalidateRoute(id string) {
	i.local.InvalidateRoute(id)
	if i.redis != nil {
		msg, _ := json.Marshal(InvalidationMessage{Type: "route", ID: id, NodeID: i.nodeID})
		i.redis.Publish(context.Background(), InvalidationChannel, msg)
	}
}

func (i *distributedProxyInvalidator) InvalidateRoutes(strategy func(*gateonv1.Route) bool) {
	i.local.InvalidateRoutes(strategy)
	if i.redis != nil {
		msg, _ := json.Marshal(InvalidationMessage{Type: "all", NodeID: i.nodeID})
		i.redis.Publish(context.Background(), InvalidationChannel, msg)
	}
}

func (i *distributedProxyInvalidator) InvalidateTLS() {
	i.local.InvalidateTLS()
	if i.redis != nil {
		msg, _ := json.Marshal(InvalidationMessage{Type: "tls", NodeID: i.nodeID})
		i.redis.Publish(context.Background(), InvalidationChannel, msg)
	}
}

// StartListener listens for invalidation events from other nodes.
func StartInvalidationListener(ctx context.Context, local proxy.Invalidator, redisClient redis.Client) {
	if redisClient == nil {
		return
	}
	nodeID, _ := os.Hostname()
	pubsub := redisClient.Subscribe(ctx, InvalidationChannel)
	defer pubsub.Close()

	ch := pubsub.Channel()
	logger.L.LogInfo("Distributed config invalidation listener started")

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			var inv InvalidationMessage
			if err := json.Unmarshal([]byte(msg.Payload), &inv); err != nil {
				continue
			}
			if inv.NodeID == nodeID {
				continue // Skip self-broadcast
			}
			switch inv.Type {
			case "route":
				logger.L.LogDebug("Received remote route invalidation", "route_id", inv.ID, "from", inv.NodeID)
				local.InvalidateRoute(inv.ID)
			case "all":
				logger.L.LogDebug("Received remote global invalidation", "from", inv.NodeID)
				local.InvalidateRoutes(func(*gateonv1.Route) bool { return true })
			case "tls":
				logger.L.LogDebug("Received remote TLS invalidation", "from", inv.NodeID)
				local.InvalidateTLS()
			}
		}
	}
}
