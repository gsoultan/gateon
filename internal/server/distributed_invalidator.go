// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/redis"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const InvalidationChannel = "gateon:config:invalidation"

type InvalidationMessage struct {
	Type   string `json:"type"` // "route", "all", "tls", "waf", "session"
	ID     string `json:"id,omitzero"`
	NodeID string `json:"node_id"`
}

// nodeID identifies this *process*, not this host.
//
// The listener discards a message whose NodeID equals its own, on the grounds
// that it already applied the change locally. That identity used to be
// os.Hostname(), so two gateon processes on one host — an ordinary container
// arrangement, and the shape most likely to be running more than one instance —
// read each other's invalidations as their own echo and dropped them. Every
// invalidation type was affected, not just sessions.
//
// Computed once: a value that changed between publish and subscribe would make
// a node ignore its own echo sometimes and not others.
var nodeID = func() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		// Only reachable if the OS entropy source fails. Falling back to the
		// pid keeps two processes on one host distinguishable, which is the
		// property this value exists for.
		return fmt.Sprintf("%s-%d", host, os.Getpid())
	}
	return fmt.Sprintf("%s-%d-%s", host, os.Getpid(), hex.EncodeToString(r[:]))
}()

type distributedProxyInvalidator struct {
	local  proxy.Invalidator
	redis  redis.Client
	nodeID string
}

// NewDistributedProxyInvalidator wraps a local invalidator and broadcasts events via Redis.
func NewDistributedProxyInvalidator(local proxy.Invalidator, redis redis.Client) proxy.Invalidator {
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

func (i *distributedProxyInvalidator) InvalidateWAF() {
	i.local.InvalidateWAF()
	if i.redis != nil {
		msg, _ := json.Marshal(InvalidationMessage{Type: "waf", NodeID: i.nodeID})
		i.redis.Publish(context.Background(), InvalidationChannel, msg)
	}
}

// SessionBindingInvalidator applies a session-binding invalidation that arrived
// from another instance. *auth.Holder satisfies it.
//
// Narrow on purpose: the listener is fed a message from the broker, and the
// only thing it is able to do with it is drop a cached binding. Handing it the
// whole auth.Service would let a later change reach something that populates.
type SessionBindingInvalidator interface {
	InvalidateBinding(id string)
}

// redisBindingPublisher tells other instances to drop a user's cached session
// binding. It implements auth.BindingPublisher, which is how internal/auth
// broadcasts without importing a broker. See ADR 0012.
type redisBindingPublisher struct {
	redis redis.Client
}

// NewRedisBindingPublisher returns a publisher for session-binding
// revocations, or nil if there is no Redis client — in which case propagation
// is off and the binding TTL remains the whole mechanism.
func NewRedisBindingPublisher(c redis.Client) auth.BindingPublisher {
	if c == nil {
		return nil
	}
	return &redisBindingPublisher{redis: c}
}

func (p *redisBindingPublisher) PublishBindingRevocation(userID string) {
	if p.redis == nil || userID == "" {
		return
	}
	msg, err := json.Marshal(InvalidationMessage{Type: "session", ID: userID, NodeID: nodeID})
	if err != nil {
		return
	}
	// Best effort, and logged rather than returned. The revocation has already
	// been applied locally and every sibling still expires its entry within
	// DefaultBindingTTL, so a broker that is down costs propagation latency and
	// not correctness -- but it should not do so silently.
	if err := p.redis.Publish(context.Background(), InvalidationChannel, msg).Err(); err != nil {
		logger.L.LogWarn("session revocation not propagated to peers; they converge at the binding TTL instead",
			"user_id", userID, "error", err)
	}
}

// installBindingPublisher puts the peer-notification publisher on the auth
// service, so a revocation reaches the other instances instead of waiting out
// their binding TTL.
//
// Deliberately *not* guarded by auth.Available. An empty Holder is the first-run
// case, and that is precisely when this still has to be recorded: Setup builds
// the Manager minutes later, and the Holder re-applies the publisher to it. A
// readiness check here would mean propagation silently never started on exactly
// the installs that began life unconfigured.
//
// The comma-ok assertion is what makes this safe against a zero-value Service
// in a test-built Server, without comparing an auth.Service to nil -- which is
// the shape the first-run bypass had, and which check-security-invariants
// rejects.
func installBindingPublisher(svc auth.Service, c redis.Client) {
	setter, ok := svc.(interface {
		SetBindingPublisher(auth.BindingPublisher)
	})
	if !ok {
		return
	}
	setter.SetBindingPublisher(NewRedisBindingPublisher(c))
}

// StartListener listens for invalidation events from other nodes.
func StartInvalidationListener(ctx context.Context, local proxy.Invalidator, bindings SessionBindingInvalidator, redisClient redis.Client) {
	if redisClient == nil {
		return
	}
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
			handleInvalidation(inv, local, bindings)
		}
	}
}

// handleInvalidation applies one message from a peer. Split out of the receive
// loop so it can be tested without a broker: the routing is the part with the
// behaviour in it, and the loop around it is plumbing.
func handleInvalidation(inv InvalidationMessage, local proxy.Invalidator, bindings SessionBindingInvalidator) {
	if inv.NodeID == nodeID {
		return // our own broadcast, already applied locally
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
	case "waf":
		logger.L.LogDebug("Received remote WAF invalidation", "from", inv.NodeID)
		local.InvalidateWAF()
	case "session":
		// Drops the cached binding only. The next verify for this user re-reads
		// the account, so a message can make the check stricter and never
		// weaker -- which is what makes an untrusted input acceptable here at
		// all. See ADR 0012.
		if bindings != nil && inv.ID != "" {
			logger.L.LogDebug("Received remote session revocation", "user_id", inv.ID, "from", inv.NodeID)
			bindings.InvalidateBinding(inv.ID)
		}
	}
}
