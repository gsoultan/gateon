package server

import (
	"context"
	"encoding/json"
	"os"

	"github.com/gsoultan/gateon/internal/domain"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/redis"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const InvalidationChannel = "gateon:config:invalidation"

type InvalidationMessage struct {
	Type   string `json:"type"` // "route", "all"
	ID     string `json:"id,omitempty"`
	NodeID string `json:"node_id"`
}

type distributedProxyInvalidator struct {
	local  domain.ProxyInvalidator
	redis  redis.Client
	nodeID string
}

// NewDistributedProxyInvalidator wraps a local invalidator and broadcasts events via Redis.
func NewDistributedProxyInvalidator(local domain.ProxyInvalidator, redis redis.Client) domain.ProxyInvalidator {
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

// StartListener listens for invalidation events from other nodes.
func StartInvalidationListener(ctx context.Context, local domain.ProxyInvalidator, redisClient redis.Client) {
	if redisClient == nil {
		return
	}
	nodeID, _ := os.Hostname()
	pubsub := redisClient.Subscribe(ctx, InvalidationChannel)
	defer pubsub.Close()

	ch := pubsub.Channel()
	logger.L.Info().Msg("Distributed config invalidation listener started")

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
				logger.L.Debug().Str("route_id", inv.ID).Str("from", inv.NodeID).Msg("Received remote route invalidation")
				local.InvalidateRoute(inv.ID)
			case "all":
				logger.L.Debug().Str("from", inv.NodeID).Msg("Received remote global invalidation")
				local.InvalidateRoutes(func(*gateonv1.Route) bool { return true })
			}
		}
	}
}
