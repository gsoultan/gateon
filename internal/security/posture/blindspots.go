// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package posture

import (
	"cmp"
	"sort"
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// BlindSpotKind names one reason traffic reaches a backend without the WAF
// having judged it. The dashboard keys its wording on these, so they are part
// of the report's contract.
type BlindSpotKind string

const (
	// BlindL4Passthrough: a TCP or UDP route. The gateway forwards its bytes
	// unread; no HTTP middleware, the WAF included, runs on them. This is
	// where CVE-2026-123158 (inside an SSH session) lived.
	BlindL4Passthrough BlindSpotKind = "l4_passthrough"
	// BlindL4OpenToAll: a TCP route with no IP filter, the one control a TCP
	// route enforces (ADR 0084). Anyone may open the connection.
	BlindL4OpenToAll BlindSpotKind = "l4_open_to_all"
	// BlindWAFOff: an HTTP route no WAF inspects.
	BlindWAFOff BlindSpotKind = "waf_off"
	// BlindWAFDetectOnly: a WAF records what it matches and forwards it.
	BlindWAFDetectOnly BlindSpotKind = "waf_detect_only"
	// BlindWAFNoCategories: a WAF with every attack family switched off.
	BlindWAFNoCategories BlindSpotKind = "waf_no_categories"
	// BlindWebSocketMessages: gateway-wide. The WAF judges the upgrade
	// request. What the client sends afterwards is judged only on a route
	// whose WAF has websocket_inspection on, and what the backend sends is
	// never judged, so this is true of every install whatever it sets.
	BlindWebSocketMessages BlindSpotKind = "websocket_messages"
)

const typeIPFilter = "ipfilter"

// MaxBlindSpots bounds the list a report carries. An install with thousands of
// routes still gets a count of the rest (BlindSpotReport.Omitted).
const MaxBlindSpots = 200

// BlindSpot is one place the WAF does not see, or sees and does not refuse.
// Route and Name are empty for a gateway-wide entry.
type BlindSpot struct {
	Kind  BlindSpotKind `json:"kind"`
	Route string        `json:"route,omitempty"`
	Name  string        `json:"name,omitempty"`
}

// BlindSpotReport is what the WAF cannot see or does not stop, computed from
// configuration only, the way Coverage is.
type BlindSpotReport struct {
	Spots []BlindSpot `json:"spots"`
	// Omitted is how many more there are past MaxBlindSpots.
	Omitted int `json:"omitted,omitempty"`
}

// BlindSpots lists, for the configuration in c, every enabled route whose
// traffic the WAF does not judge or does not refuse, and the gateway-wide
// limits no route setting changes.
//
// It exists because the two most dangerous CVEs of November 2026 -- a kernel
// handshake bug and an OpenSSH bypass -- had no WAF answer at all, and nothing
// in the dashboard said which routes were in that position. A posture score
// says how much is protected; this says what is not.
func BlindSpots(c Config) BlindSpotReport {
	var spots []BlindSpot
	for _, rt := range c.Routes {
		if rt.GetDisabled() {
			continue
		}
		for _, kind := range routeBlindSpots(rt, c) {
			spots = append(spots, BlindSpot{Kind: kind, Route: rt.GetId(), Name: routeLabel(rt)})
		}
	}
	// Stable for a reader and for a test: by kind, then by name.
	sort.SliceStable(spots, func(i, j int) bool {
		if spots[i].Kind != spots[j].Kind {
			return spots[i].Kind < spots[j].Kind
		}
		return spots[i].Name < spots[j].Name
	})
	// The route entries are cut to fit; the gateway-wide entry is always
	// kept, because it is true of every install whatever its routes are.
	var report BlindSpotReport
	if room := MaxBlindSpots - 1; len(spots) > room {
		report.Omitted = len(spots) - room
		spots = spots[:room]
	}
	report.Spots = append(spots, BlindSpot{Kind: BlindWebSocketMessages})
	return report
}

func routeBlindSpots(rt *gateonv1.Route, c Config) []BlindSpotKind {
	if isL4(rt.GetType()) {
		kinds := []BlindSpotKind{BlindL4Passthrough}
		// UDP enforces no filter at all (ADR 0084), so "open to all" is only
		// a finding where a filter would have been honoured.
		if isTCP(rt.GetType()) && len(routeMiddlewares(rt, c.Middlewares, typeIPFilter)) == 0 {
			kinds = append(kinds, BlindL4OpenToAll)
		}
		return kinds
	}
	switch routeWAFMode(rt, c) {
	case ModeEnforce:
		return nil
	case ModeDetect:
		return []BlindSpotKind{BlindWAFDetectOnly}
	case ModeNoCategories:
		return []BlindSpotKind{BlindWAFNoCategories}
	default:
		return []BlindSpotKind{BlindWAFOff}
	}
}

func isTCP(routeType string) bool {
	return strings.EqualFold(strings.TrimSpace(routeType), "tcp")
}

func routeLabel(rt *gateonv1.Route) string {
	return cmp.Or(strings.TrimSpace(rt.GetName()), rt.GetId())
}
