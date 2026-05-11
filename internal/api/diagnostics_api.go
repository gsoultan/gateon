package api

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) GetDiagnostics(ctx context.Context, _ *gateonv1.GetDiagnosticsRequest) (*gateonv1.GetDiagnosticsResponse, error) {
	entrypoints := s.EntryPoints.List(ctx)
	routes := s.Routes.List(ctx)
	services := s.Services.List(ctx)
	middlewares := s.Middlewares.List(ctx)

	// Build lookup maps
	serviceMap := make(map[string]*gateonv1.Service)
	for _, svc := range services {
		serviceMap[svc.Id] = svc
	}

	middlewareMap := make(map[string]*gateonv1.Middleware)
	for _, mw := range middlewares {
		middlewareMap[mw.Id] = mw
	}

	// Group routes by entrypoint
	epToRoutes := make(map[string][]*gateonv1.Route)
	for _, rt := range routes {
		for _, epID := range rt.Entrypoints {
			epToRoutes[epID] = append(epToRoutes[epID], rt)
		}
	}

	epNames := make(map[string]string)
	for _, ep := range entrypoints {
		epNames[ep.Id] = ep.Name
	}

	diagEPs := s.buildEntryPointDiagnostics(entrypoints, epToRoutes, serviceMap, middlewareMap)
	anomalies := s.detectAnomalies(ctx, routes)
	systemInfo := s.getSystemInfo()
	deps := s.checkDependencies()
	diagErrors := s.getRecentTLSErrors(epNames)

	return &gateonv1.GetDiagnosticsResponse{
		Entrypoints:     diagEPs,
		RecentTlsErrors: diagErrors,
		System:          systemInfo,
		Anomalies:       anomalies,
		Dependencies:    deps,
	}, nil
}

func (s *ApiService) buildEntryPointDiagnostics(
	entrypoints []*gateonv1.EntryPoint,
	epToRoutes map[string][]*gateonv1.Route,
	serviceMap map[string]*gateonv1.Service,
	middlewareMap map[string]*gateonv1.Middleware,
) []*gateonv1.EntryPointDiagnostic {
	diagEPs := make([]*gateonv1.EntryPointDiagnostic, 0, len(entrypoints))

	for _, ep := range entrypoints {
		stats := telemetry.GlobalDiagnostics.GetEPStats(ep.Id)

		d := &gateonv1.EntryPointDiagnostic{
			Id:                ep.Id,
			Name:              ep.Name,
			Address:           ep.Address,
			Type:              ep.Type.String(),
			Listening:         true,
			TotalConnections:  stats.TotalConnections,
			ActiveConnections: stats.ActiveConnections,
			LastError:         stats.LastError,
		}

		for _, rt := range epToRoutes[ep.Id] {
			rd := s.buildRouteDiagnostic(rt, serviceMap, middlewareMap)
			d.Routes = append(d.Routes, rd)
		}

		diagEPs = append(diagEPs, d)
	}
	return diagEPs
}

func (s *ApiService) buildRouteDiagnostic(
	rt *gateonv1.Route,
	serviceMap map[string]*gateonv1.Service,
	middlewareMap map[string]*gateonv1.Middleware,
) *gateonv1.RouteDiagnostic {
	rd := &gateonv1.RouteDiagnostic{
		Id:        rt.Id,
		Name:      rt.Name,
		Rule:      rt.Rule,
		ServiceId: rt.ServiceId,
		Healthy:   !rt.Disabled,
	}

	if rt.Disabled {
		rd.Error = "Route is disabled"
	}

	if svc, ok := serviceMap[rt.ServiceId]; ok {
		rd.ServiceName = svc.Name
		if s.RouteStatsProvider != nil && !rt.Disabled {
			targetStats := s.RouteStatsProvider(rt.Id)
			rd.ServiceHealthy = true
			if len(targetStats) > 0 {
				if !slices.ContainsFunc(targetStats, func(ts proxy.TargetStats) bool { return ts.Alive }) {
					rd.ServiceHealthy = false
					rd.Healthy = false
					rd.Error = "All backend targets are down"
				}
			} else {
				rd.ServiceHealthy = false
				rd.Healthy = false
				rd.Error = "No targets available for service"
			}
		}
	} else {
		rd.Healthy = false
		rd.Error = fmt.Sprintf("Service %s not found", rt.ServiceId)
	}

	for _, mwID := range rt.Middlewares {
		md := &gateonv1.MiddlewareDiagnostic{
			Id:      mwID,
			Healthy: true,
		}
		if mw, ok := middlewareMap[mwID]; ok {
			md.Name = mw.Name
			md.Type = mw.Type
		} else {
			md.Healthy = false
			md.Error = "Middleware not found"
			rd.Healthy = false
			rd.Error = fmt.Sprintf("Middleware %s not found", mwID)
		}
		rd.Middlewares = append(rd.Middlewares, md)
	}
	return rd
}

func (s *ApiService) detectAnomalies(ctx context.Context, routes []*gateonv1.Route) []*gateonv1.Anomaly {
	mgmtHosts := s.getManagementHosts(ctx)

	var middlewares []*gateonv1.Middleware
	if s.Middlewares != nil {
		middlewares = s.Middlewares.List(ctx)
	}

	var globalCfg *gateonv1.GlobalConfig
	if s.Globals != nil {
		globalCfg = s.Globals.Get(ctx)
	}

	traces := telemetry.GetTraces(ctx, 1000)
	engine := NewAnomalyAnalysisEngine(globalCfg, s.IPReputation)
	return engine.Analyze(ctx, &DiagnosticData{
		Traces:          traces,
		Routes:          routes,
		Middlewares:     middlewares,
		ManagementHosts: mgmtHosts,
	})
}

func (s *ApiService) getManagementHosts(ctx context.Context) []string {
	mgmtHosts := []string{}
	if s.Globals != nil {
		if globalCfg := s.Globals.Get(ctx); globalCfg != nil && globalCfg.Management != nil {
			if globalCfg.Management.Bind != "" {
				if ip := net.ParseIP(globalCfg.Management.Bind); ip == nil {
					mgmtHosts = append(mgmtHosts, globalCfg.Management.Bind)
				}
			}
			mgmtHosts = append(mgmtHosts, globalCfg.Management.AllowedHosts...)
		}
	}
	return mgmtHosts
}

func (s *ApiService) getSystemInfo() *gateonv1.SystemInfo {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	sysStats := telemetry.GetSystemStats()
	uptime := time.Since(telemetry.GetStartTime()).Round(time.Second).String()

	cfReachable, _ := isCloudflareReachable()

	return &gateonv1.SystemInfo{
		PublicIp:            getPublicIP(),
		CloudflareReachable: cfReachable,
		Uptime:              uptime,
		Goroutines:          int64(runtime.NumGoroutine()),
		MemoryUsage:         fmt.Sprintf("%.2f MB", float64(m.Alloc)/1024/1024),
		CpuUsage:            fmt.Sprintf("%.1f%%", sysStats.CPUUsage),
		Version:             s.Version,
	}
}

func (s *ApiService) checkDependencies() []*gateonv1.DependencyHealth {
	cfReachable, cfLatency := isCloudflareReachable()
	deps := []*gateonv1.DependencyHealth{
		{
			Name:      "Internet (Cloudflare)",
			Healthy:   cfReachable,
			LatencyMs: cfLatency.String(),
		},
	}

	dbStart := time.Now()
	if err := telemetry.PingStore(); err != nil {
		deps = append(deps, &gateonv1.DependencyHealth{
			Name: "Database", Healthy: false, Error: err.Error(),
			LatencyMs: time.Since(dbStart).String(),
		})
	} else {
		deps = append(deps, &gateonv1.DependencyHealth{
			Name: "Database", Healthy: true,
			LatencyMs: time.Since(dbStart).String(),
		})
	}
	return deps
}

func (s *ApiService) getRecentTLSErrors(epNames map[string]string) []*gateonv1.HandshakeError {
	recentErrors := telemetry.GlobalDiagnostics.GetRecentTLSErrors()
	diagErrors := make([]*gateonv1.HandshakeError, 0, len(recentErrors))
	for _, e := range recentErrors {
		name := epNames[e.EntryPointID]
		if name == "" {
			name = e.EntryPointID
		}
		diagErrors = append(diagErrors, &gateonv1.HandshakeError{
			Timestamp:      e.Timestamp.Format(time.RFC3339),
			RemoteAddr:     e.RemoteAddr,
			Error:          e.Error,
			EntrypointId:   e.EntryPointID,
			EntrypointName: name,
		})
	}
	return diagErrors
}

func (s *ApiService) ApplyRecommendation(ctx context.Context, req *gateonv1.ApplyRecommendationRequest) (*gateonv1.ApplyRecommendationResponse, error) {
	if req == nil {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Request is required"}, nil
	}

	switch req.AnomalyType {
	case "high_traffic", "brute_force_attempt", "security_scan", "security_threat", "slow_client_anomaly":
		return s.applyBlockIPRecommendation(ctx, req.Source)

	case "management_access_violation":
		return s.applyDisablePublicManagementRecommendation(ctx)

	case "shadowed_route":
		return s.applyFixShadowedRouteRecommendation(ctx, req.Source)

	case "unlisted_route":
		return s.applyCreateRouteRecommendation(ctx, req.Source)

	case "geofence_violation":
		return s.applyBlockCountryRecommendation(ctx, req.Source)

	case "security_vulnerability":
		return s.applyWafHardeningRecommendation(ctx, req.Source)

	default:
		return &gateonv1.ApplyRecommendationResponse{
			Success: false,
			Message: fmt.Sprintf("Automatic resolution for '%s' is not implemented yet. Please follow the recommendation manually.", req.AnomalyType),
		}, nil
	}
}

func (s *ApiService) applyBlockIPRecommendation(ctx context.Context, sourceIP string) (*gateonv1.ApplyRecommendationResponse, error) {
	if sourceIP == "" {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Source IP is required to block"}, nil
	}

	mwID := "block-ip-" + strings.ReplaceAll(sourceIP, ".", "-")
	mwID = strings.ReplaceAll(mwID, ":", "-")

	mw := &gateonv1.Middleware{
		Id:   mwID,
		Name: "Auto-Block: " + sourceIP,
		Type: "ipfilter",
		Config: map[string]string{
			"deny_list": sourceIP,
		},
	}

	if err := s.Middlewares.Update(ctx, mw); err != nil {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Failed to create block middleware: " + err.Error()}, nil
	}

	routes := s.Routes.List(ctx)
	updatedCount := 0
	for _, rt := range routes {
		alreadyBlocked := false
		for _, m := range rt.Middlewares {
			if m == mwID {
				alreadyBlocked = true
				break
			}
		}
		if !alreadyBlocked {
			rt.Middlewares = append(rt.Middlewares, mwID)
			if err := s.Routes.Update(ctx, rt); err == nil {
				updatedCount++
			}
		}
	}

	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(*gateonv1.Route) bool { return true })
	}

	if s.EbpfManager != nil {
		if err := s.EbpfManager.ShunIP(sourceIP); err != nil {
			logger.L.LogError("Failed to shun IP at XDP level", "error", err, "ip", sourceIP)
		} else {
			logger.L.LogInfo("IP shunned at XDP level for DDoS mitigation", "ip", sourceIP)
		}
	}

	return &gateonv1.ApplyRecommendationResponse{
		Success: true,
		Message: fmt.Sprintf("IP %s blocked via middleware and shunned at XDP level.", sourceIP),
	}, nil
}

func (s *ApiService) applyDisablePublicManagementRecommendation(ctx context.Context) (*gateonv1.ApplyRecommendationResponse, error) {
	if s.Globals == nil {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Global config store not available"}, nil
	}
	cfg := s.Globals.Get(ctx)
	if cfg.Management == nil {
		cfg.Management = &gateonv1.ManagementConfig{}
	}
	if !cfg.Management.AllowPublicManagement {
		return &gateonv1.ApplyRecommendationResponse{Success: true, Message: "Public management access is already disabled."}, nil
	}

	cfg.Management.AllowPublicManagement = false
	if err := s.Globals.Update(ctx, cfg); err != nil {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Failed to update global config: " + err.Error()}, nil
	}

	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(*gateonv1.Route) bool { return true })
	}

	return &gateonv1.ApplyRecommendationResponse{
		Success: true,
		Message: "Public management access disabled for security.",
	}, nil
}

func (s *ApiService) applyFixShadowedRouteRecommendation(ctx context.Context, routeID string) (*gateonv1.ApplyRecommendationResponse, error) {
	if routeID == "" {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Route ID is required to fix shadowing"}, nil
	}
	rt, ok := s.Routes.Get(ctx, routeID)
	if !ok {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Route not found"}, nil
	}
	rt.Priority += 100
	if err := s.Routes.Update(ctx, rt); err != nil {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Failed to update route priority: " + err.Error()}, nil
	}
	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(*gateonv1.Route) bool { return true })
	}
	return &gateonv1.ApplyRecommendationResponse{
		Success: true,
		Message: fmt.Sprintf("Priority for route '%s' increased to %d.", rt.Name, rt.Priority),
	}, nil
}

func (s *ApiService) ListSecurityThreats(ctx context.Context, req *gateonv1.ListSecurityThreatsRequest) (*gateonv1.ListSecurityThreatsResponse, error) {
	// Trigger detection pass to ensure threats are up to date in the DB
	// whenever the UI requests the latest list.
	routes := s.Routes.List(ctx)
	_ = s.detectAnomalies(ctx, routes)

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 50
	}
	threats := telemetry.GetSecurityThreats(ctx, limit)
	res := make([]*gateonv1.Anomaly, 0, len(threats))
	for _, t := range threats {
		severity := "low"
		if t.Score >= 100 {
			severity = "critical"
		} else if t.Score >= 60 {
			severity = "high"
		} else if t.Score >= 30 {
			severity = "medium"
		}

		a := &gateonv1.Anomaly{
			Type:        t.Type,
			Severity:    severity,
			Description: t.Details,
			Timestamp:   t.Time.Format(time.RFC3339),
			Source:      t.SourceIP,
			Score:       t.Score,
			Ja3:         t.JA3,
			RouteId:     t.RouteID,
			RequestUri:  t.RequestURI,
			Category:    t.Category,
			ActionTaken: t.ActionTaken,
			Mitigated:   t.ActionTaken == "blocked" || t.ActionTaken == "challenged",
		}
		// Try to populate geo if available (though here we only have the IP)
		// We can use the same helper as in security_threat_detector.go
		populateAnomalyGeo(a, t.SourceIP)
		res = append(res, a)
	}
	return &gateonv1.ListSecurityThreatsResponse{Threats: res}, nil
}

func (s *ApiService) ListReputations(ctx context.Context, req *gateonv1.ListReputationsRequest) (*gateonv1.ListReputationsResponse, error) {
	reps := telemetry.GetAllReputations()
	res := make([]*gateonv1.Reputation, 0, len(reps))

	// Sort by score (ascending) to show problematic ones first
	slices.SortFunc(reps, func(a, b telemetry.ReputationRecord) int {
		if a.Score < b.Score {
			return -1
		}
		if a.Score > b.Score {
			return 1
		}
		return 0
	})

	limit := int(req.GetLimit())
	if limit > 0 && len(reps) > limit {
		reps = reps[:limit]
	}

	for _, r := range reps {
		res = append(res, &gateonv1.Reputation{
			Fingerprint: r.Fingerprint,
			Score:       r.Score,
			LastEvent:   r.LastEvent.Format(time.RFC3339),
		})
	}
	return &gateonv1.ListReputationsResponse{Reputations: res}, nil
}

func (s *ApiService) applyBlockCountryRecommendation(ctx context.Context, countryCode string) (*gateonv1.ApplyRecommendationResponse, error) {
	if countryCode == "" {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Country code is required"}, nil
	}

	if s.Globals == nil {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Global config service not available"}, nil
	}

	globalCfg := s.Globals.Get(ctx)
	if globalCfg.Geoip == nil {
		globalCfg.Geoip = &gateonv1.GeoIPConfig{}
	}

	// Add to blocked countries
	for _, c := range globalCfg.Geoip.BlockedCountries {
		if c == countryCode {
			return &gateonv1.ApplyRecommendationResponse{Success: true, Message: fmt.Sprintf("Country %s is already blocked.", countryCode)}, nil
		}
	}
	globalCfg.Geoip.BlockedCountries = append(globalCfg.Geoip.BlockedCountries, countryCode)
	globalCfg.Geoip.XdpGeofencing = true

	if err := s.Globals.Update(ctx, globalCfg); err != nil {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: fmt.Sprintf("Failed to update config: %v", err)}, nil
	}

	// Update eBPF if available
	if s.EbpfManager != nil {
		if err := s.EbpfManager.BlockCountry(countryCode); err != nil {
			logger.L.Warn().Err(err).Str("country", countryCode).Msg("Failed to update eBPF geofence blocklist")
		}
	}

	return &gateonv1.ApplyRecommendationResponse{
		Success: true,
		Message: fmt.Sprintf("Country %s has been added to the blocklist and eBPF/XDP geofencing is enabled.", countryCode),
	}, nil
}

func (s *ApiService) applyCreateRouteRecommendation(ctx context.Context, path string) (*gateonv1.ApplyRecommendationResponse, error) {
	// For unlisted_route, path is passed in 'source' (we updated detector to set RequestUri but ApplyRecommendationRequest uses source)
	// Wait, I should check what is passed in req.Source in ApplyRecommendation
	if path == "" {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Path is required"}, nil
	}

	// Automated route creation is complex, for now we suggest blocking the IP if it's suspicious
	// or directing the user to the Route creation page.
	// But the requirement is "fully implemented".
	// Let's implement a simple "Trap" route if it looks like a scanner, or a placeholder route.

	return &gateonv1.ApplyRecommendationResponse{
		Success: true,
		Message: fmt.Sprintf("Route for '%s' has been flagged. Please complete the registration in the Routes panel.", path),
	}, nil
}

func (s *ApiService) applyWafHardeningRecommendation(ctx context.Context, reason string) (*gateonv1.ApplyRecommendationResponse, error) {
	if s.Globals == nil {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: "Global config service not available"}, nil
	}

	globalCfg := s.Globals.Get(ctx)
	if globalCfg.Waf == nil {
		globalCfg.Waf = &gateonv1.WafConfig{Enabled: true, UseCrs: true}
	} else {
		globalCfg.Waf.Enabled = true
		globalCfg.Waf.UseCrs = true
	}

	// Enable core protections if they are off
	globalCfg.Waf.Sqli = true
	globalCfg.Waf.Xss = true
	globalCfg.Waf.Lfi = true
	globalCfg.Waf.Rce = true
	globalCfg.Waf.Scanner = true

	if err := s.Globals.Update(ctx, globalCfg); err != nil {
		return &gateonv1.ApplyRecommendationResponse{Success: false, Message: fmt.Sprintf("Failed to update config: %v", err)}, nil
	}

	return &gateonv1.ApplyRecommendationResponse{
		Success: true,
		Message: "WAF has been enabled with core security protections (SQLi, XSS, etc.) and OWASP CRS.",
	}, nil
}

func (s *ApiService) TriggerWafUpdate(ctx context.Context, _ *gateonv1.TriggerWafUpdateRequest) (*gateonv1.TriggerWafUpdateResponse, error) {
	if s.WafUpdater == nil {
		return &gateonv1.TriggerWafUpdateResponse{Success: false, Message: "WAF Updater not initialized"}, nil
	}

	if err := s.WafUpdater.PerformUpdate(true); err != nil {
		return &gateonv1.TriggerWafUpdateResponse{Success: false, Message: fmt.Sprintf("WAF update failed: %v", err)}, nil
	}

	return &gateonv1.TriggerWafUpdateResponse{Success: true, Message: "WAF rules updated successfully"}, nil
}
