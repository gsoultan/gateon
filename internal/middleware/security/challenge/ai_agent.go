// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"errors"
	"net/http"
	"net/netip"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/security/aiagent"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// AIAgentPolicy is what a route does with a client that names an AI agent
// (ADR 0108). It is the route's own; the address lists are global.
type AIAgentPolicy uint8

const (
	// AIAgentsOff treats a client that names an AI agent like any other.
	AIAgentsOff AIAgentPolicy = iota
	// AIAgentsVerify lets a client whose address its agent's vendor
	// publishes past the challenge, which a crawler cannot run, and refuses
	// one that names an agent from any other address. A claim no list in
	// force can judge meets the route's other checks.
	AIAgentsVerify
	// AIAgentsRefuse refuses every client that names an AI agent, real or
	// not.
	AIAgentsRefuse
	// AIAgentsMaze verifies as AIAgentsVerify does, and answers a client
	// that names an agent from any other address with a maze page instead of
	// a refusal (ADR 0109).
	AIAgentsMaze
)

// AIAgentsKey is the route's setting.
const AIAgentsKey = "ai_agents"

// ParseAIAgentPolicy reads the route's setting; empty is off.
func ParseAIAgentPolicy(v string) (AIAgentPolicy, error) {
	switch v {
	case "", "off":
		return AIAgentsOff, nil
	case "verify":
		return AIAgentsVerify, nil
	case "refuse":
		return AIAgentsRefuse, nil
	case "maze":
		return AIAgentsMaze, nil
	}
	return AIAgentsOff, errors.New("want off, verify, maze or refuse")
}

// Outcomes on gateon_middleware_bot_management_total. A spoofed claim is a
// recorded threat and counted as "blocked" by the threat pipeline.
const (
	outcomeAIAgentVerified = "ai_agent_verified"
	outcomeAIAgentRefused  = "ai_agent_refused"
)

// serveAIAgent applies the route's AI agent policy, and reports whether it
// answered the request. A request that names no agent costs a dozen substring
// searches of its User-Agent and nothing else.
func serveAIAgent(cfg BotManagementConfig, clientIP string, next http.Handler, w http.ResponseWriter, r *http.Request) bool {
	agent, claimed := aiagent.Claim(r.UserAgent())
	if !claimed {
		return false
	}
	if cfg.AIAgents == AIAgentsRefuse {
		telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, outcomeAIAgentRefused).Inc()
		kind.Refuse(w, http.StatusForbidden)
		return true
	}
	addr, _ := netip.ParseAddr(clientIP)
	switch cfg.AIAgentRanges.Verify(agent.Name, addr) {
	case aiagent.Verified:
		telemetry.MiddlewareBotManagementTotal.WithLabelValues(cfg.RouteID, outcomeAIAgentVerified).Inc()
		next.ServeHTTP(w, r)
		return true
	case aiagent.Spoofed:
		refuseSpoofedAgent(cfg, clientIP, agent, w, r)
		return true
	}
	return false
}

// refuseSpoofedAgent answers a client that named agent from an address its
// vendor does not publish: with the maze on a route that asks for it, and the
// uniform refusal otherwise. Either way it is recorded, and nothing of the
// request reaches the origin.
func refuseSpoofedAgent(cfg BotManagementConfig, clientIP string, agent aiagent.Agent, w http.ResponseWriter, r *http.Request) {
	details := "Named " + agent.Name + " (" + agent.Vendor + ") from an address " + agent.Vendor + " does not publish for it"
	if cfg.AIAgents == AIAgentsMaze {
		details += "; served a maze page"
	}
	logger.SecurityEvent("bot_detected_ai_agent_spoofed", r, "named an AI agent from an address its vendor does not publish")
	recordBotThreat(r, cfg, clientIP, "ai_agent", 60, details, kind.SeverityMedium)
	if cfg.AIAgents == AIAgentsMaze {
		aiagent.Maze(w, r, []byte(cfg.SecretKey))
		return
	}
	kind.Refuse(w, http.StatusForbidden)
}
