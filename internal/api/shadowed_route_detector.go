package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ShadowedRouteDetector identifies routes that are never reached because a more generic route has higher priority.
type ShadowedRouteDetector struct{}

func (d *ShadowedRouteDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	// Group routes by entrypoint
	epToRoutes := make(map[string][]*gateonv1.Route)
	for _, rt := range data.Routes {
		if rt.Disabled {
			continue
		}
		for _, epID := range rt.Entrypoints {
			epToRoutes[epID] = append(epToRoutes[epID], rt)
		}
	}

	for epID, routes := range epToRoutes {
		for i, r1 := range routes {
			for j, r2 := range routes {
				if i == j {
					continue
				}

				// If r1 has higher or equal priority and is more generic than r2
				if r1.Priority >= r2.Priority && isMoreGeneric(r1.Rule, r2.Rule) {
					anomalies = append(anomalies, &gateonv1.Anomaly{
						Type:           "shadowed_route",
						Severity:       "warning",
						Description:    fmt.Sprintf("Route '%s' (Priority %d) is shadowed by '%s' (Priority %d) on entrypoint %s", r2.Name, r2.Priority, r1.Name, r1.Priority, epID),
						Timestamp:      time.Now().Format(time.RFC3339),
						Source:         r2.Id,
						Recommendation: fmt.Sprintf("Increase priority of route '%s' or refine the rule for '%s' to avoid overlap.", r2.Name, r1.Name),
					})
					// Only report once per shadowed route
					break
				}
			}
		}
	}

	return anomalies
}

// isMoreGeneric is a simplified heuristic to check if rule1 shadows rule2.
func isMoreGeneric(rule1, rule2 string) bool {
	if rule1 == rule2 {
		return true
	}

	// Heuristic: Host("example.com") shadows Host("example.com") && PathPrefix("/api")
	if strings.HasPrefix(rule2, rule1) && strings.Contains(rule2, "&&") {
		return true
	}

	// Heuristic: Host(`example.com`) shadows Host(`example.com`)
	r1Normalized := strings.ReplaceAll(rule1, "`", "\"")
	r2Normalized := strings.ReplaceAll(rule2, "`", "\"")

	if r1Normalized == r2Normalized {
		return true
	}

	// Check if rule1 is just a Host and rule2 is same Host with more conditions
	if strings.HasPrefix(r1Normalized, "Host(") && !strings.Contains(r1Normalized, "&&") {
		if strings.HasPrefix(r2Normalized, r1Normalized) && strings.Contains(r2Normalized, "&&") {
			return true
		}
	}

	return false
}
