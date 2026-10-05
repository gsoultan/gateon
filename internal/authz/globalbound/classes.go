// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package globalbound

import "google.golang.org/protobuf/reflect/protoreflect"

// Class says who may change one field of the global configuration.
type Class uint8

const (
	// Unclassified is a field the table below does not name. It is enforced
	// as Boundary, so a field added to the proto and forgotten here is
	// administrator-only rather than silently operator-writable, and
	// TestEveryGlobalFieldIsClassified fails on it.
	Unclassified Class = iota
	// Boundary is administrator-only: it decides who can reach or sign in to
	// the management plane, whom the gateway trusts, or what record is kept
	// of either. A message-typed Boundary field is compared as a whole, so
	// every field ever added inside it is administrator-only too.
	Boundary
	// Operational is a setting an operator may change. On a message-typed
	// field every field inside it must be classified Operational as well (the
	// completeness test enforces this), so nothing new inside one inherits it.
	Operational
	// Section is a singular message whose fields are classified one by one.
	Section
)

func (c Class) String() string {
	switch c {
	case Boundary:
		return "Boundary"
	case Operational:
		return "Operational"
	case Section:
		return "Section"
	default:
		return "Unclassified"
	}
}

// classes classifies every field reachable from GlobalConfig, keyed by the
// field's full proto name. The reasoning for each Boundary entry is in ADR
// 0040; the short form is beside it.
var classes = map[protoreflect.FullName]Class{
	// --- GlobalConfig ---
	"gateon.v1.GlobalConfig.tls":               Section,
	"gateon.v1.GlobalConfig.redis":             Section,
	"gateon.v1.GlobalConfig.otel":              Section,
	"gateon.v1.GlobalConfig.log":               Section,
	"gateon.v1.GlobalConfig.auth":              Boundary, // sign-in, the session key, the user database
	"gateon.v1.GlobalConfig.transport":         Section,
	"gateon.v1.GlobalConfig.waf":               Section,
	"gateon.v1.GlobalConfig.ha":                Section,
	"gateon.v1.GlobalConfig.anomaly_detection": Section,
	"gateon.v1.GlobalConfig.ebpf":              Section,
	"gateon.v1.GlobalConfig.management":        Boundary, // bind, allowlist, CORS, public exposure, GitOps source
	"gateon.v1.GlobalConfig.geoip":             Section,
	"gateon.v1.GlobalConfig.debugger":          Section,
	"gateon.v1.GlobalConfig.security_advanced": Section,
	"gateon.v1.GlobalConfig.alerting":          Section,
	"gateon.v1.GlobalConfig.audit":             Boundary, // the record of management activity
	"gateon.v1.GlobalConfig.rbac":              Boundary, // who may do what
	"gateon.v1.GlobalConfig.profile":           Operational,

	// --- tls ---
	"gateon.v1.TlsConfig.enabled":            Operational,
	"gateon.v1.TlsConfig.email":              Operational,
	"gateon.v1.TlsConfig.domains":            Operational,
	"gateon.v1.TlsConfig.auto_redirect":      Operational,
	"gateon.v1.TlsConfig.min_tls_version":    Operational,
	"gateon.v1.TlsConfig.max_tls_version":    Operational,
	"gateon.v1.TlsConfig.cipher_suites":      Operational,
	"gateon.v1.TlsConfig.client_auth_type":   Boundary, // whether client certificates are demanded
	"gateon.v1.TlsConfig.certificates":       Operational,
	"gateon.v1.TlsConfig.client_authorities": Boundary, // the CAs a client certificate is trusted from
	"gateon.v1.TlsConfig.acme":               Section,

	"gateon.v1.Certificate.id":         Operational,
	"gateon.v1.Certificate.name":       Operational,
	"gateon.v1.Certificate.cert_file":  Operational,
	"gateon.v1.Certificate.key_file":   Operational,
	"gateon.v1.Certificate.ca_file":    Operational,
	"gateon.v1.Certificate.validation": Operational,

	"gateon.v1.CertificateValidation.valid":               Operational,
	"gateon.v1.CertificateValidation.warnings":            Operational,
	"gateon.v1.CertificateValidation.recommended_ciphers": Operational,

	"gateon.v1.AcmeConfig.enabled":        Operational,
	"gateon.v1.AcmeConfig.email":          Operational,
	"gateon.v1.AcmeConfig.ca_server":      Operational,
	"gateon.v1.AcmeConfig.challenge_type": Operational,

	// --- redis: where the ACME certificate cache (private keys) and the
	// token revocation store live. Switching it on or off is an operator's;
	// choosing the server is not. ---
	"gateon.v1.RedisConfig.enabled":  Operational,
	"gateon.v1.RedisConfig.addr":     Boundary,
	"gateon.v1.RedisConfig.password": Boundary,
	"gateon.v1.RedisConfig.db":       Boundary,

	// --- otel ---
	"gateon.v1.OtelConfig.enabled":      Operational,
	"gateon.v1.OtelConfig.endpoint":     Operational,
	"gateon.v1.OtelConfig.service_name": Operational,

	// --- log ---
	"gateon.v1.LogConfig.level":                          Operational,
	"gateon.v1.LogConfig.development":                    Operational,
	"gateon.v1.LogConfig.format":                         Operational,
	"gateon.v1.LogConfig.path_stats_retention_days":      Operational,
	"gateon.v1.LogConfig.access_log_retention_days":      Operational,
	"gateon.v1.LogConfig.security_threat_retention_days": Operational,
	"gateon.v1.LogConfig.audit_log_retention_days":       Boundary, // a short window deletes the audit trail
	"gateon.v1.LogConfig.trace_archive_enabled":          Operational,
	"gateon.v1.LogConfig.trace_archive_retention_days":   Operational,
	"gateon.v1.LogConfig.trace_archive_max_size_mb":      Operational,

	// --- transport ---
	"gateon.v1.TransportConfig.max_idle_conns":            Operational,
	"gateon.v1.TransportConfig.max_idle_conns_per_host":   Operational,
	"gateon.v1.TransportConfig.idle_conn_timeout_seconds": Operational,

	// --- waf ---
	"gateon.v1.WafConfig.enabled":                       Operational,
	"gateon.v1.WafConfig.paranoia_level":                Operational,
	"gateon.v1.WafConfig.custom_directives":             Operational,
	"gateon.v1.WafConfig.wordpress":                     Operational,
	"gateon.v1.WafConfig.ip_reputation":                 Operational,
	"gateon.v1.WafConfig.dos_protection":                Operational,
	"gateon.v1.WafConfig.malware_detection":             Operational,
	"gateon.v1.WafConfig.dlp":                           Operational,
	"gateon.v1.WafConfig.anomaly_threshold":             Operational,
	"gateon.v1.WafConfig.request_body_limit":            Operational,
	"gateon.v1.WafConfig.response_body_limit":           Operational,
	"gateon.v1.WafConfig.audit_log_path":                Boundary, // a file the gateway appends request data to
	"gateon.v1.WafConfig.audit_log_relevant_only":       Operational,
	"gateon.v1.WafConfig.bot_management":                Section,
	"gateon.v1.WafConfig.allowed_admin_ips":             Operational,
	"gateon.v1.WafConfig.auto_update_rules":             Operational,
	"gateon.v1.WafConfig.clamav_addr":                   Operational,
	"gateon.v1.WafConfig.clamav":                        Section,
	"gateon.v1.WafConfig.entropy_threshold":             Operational,
	"gateon.v1.WafConfig.disable_entropy":               Operational,
	"gateon.v1.WafConfig.tier":                          Operational,
	"gateon.v1.WafConfig.trust_cloudflare_headers":      Boundary, // decides which header names the client address
	"gateon.v1.WafConfig.enable_body_entropy":           Operational,
	"gateon.v1.WafConfig.enable_fingerprint_validation": Operational,
	"gateon.v1.WafConfig.enable_confidence_scoring":     Operational,
	"gateon.v1.WafConfig.audit_only":                    Operational,
	"gateon.v1.WafConfig.app_profiles":                  Operational,
	"gateon.v1.WafConfig.ssrf_protection":               Operational,
	"gateon.v1.WafConfig.origins":                       Operational,
	"gateon.v1.WafConfig.dlp_action":                    Operational,
	"gateon.v1.WafConfig.categories":                    Operational,

	"gateon.v1.WafCategories.sqli":                 Operational,
	"gateon.v1.WafCategories.xss":                  Operational,
	"gateon.v1.WafCategories.lfi":                  Operational,
	"gateon.v1.WafCategories.rce":                  Operational,
	"gateon.v1.WafCategories.php":                  Operational,
	"gateon.v1.WafCategories.java":                 Operational,
	"gateon.v1.WafCategories.nodejs":               Operational,
	"gateon.v1.WafCategories.scanner":              Operational,
	"gateon.v1.WafCategories.protocol":             Operational,
	"gateon.v1.WafCategories.ransomware_detection": Operational,

	"gateon.v1.BotManagementConfig.enabled":                   Operational,
	"gateon.v1.BotManagementConfig.enable_js_challenge":       Operational,
	"gateon.v1.BotManagementConfig.enable_browser_integrity":  Operational,
	"gateon.v1.BotManagementConfig.challenge_timeout_seconds": Operational,
	"gateon.v1.BotManagementConfig.secret_key":                Operational,

	"gateon.v1.ClamavConfig.installation_mode":        Operational,
	"gateon.v1.ClamavConfig.auto_install":             Operational,
	"gateon.v1.ClamavConfig.docker_image":             Operational,
	"gateon.v1.ClamavConfig.full_scan_schedule":       Operational,
	"gateon.v1.ClamavConfig.low_resource_mode":        Operational,
	"gateon.v1.ClamavConfig.clamav_addr":              Operational,
	"gateon.v1.ClamavConfig.database_update_schedule": Operational,
	"gateon.v1.ClamavConfig.app_update_schedule":      Operational,

	// --- ha ---
	"gateon.v1.HaConfig.enabled":           Operational,
	"gateon.v1.HaConfig.interface":         Operational,
	"gateon.v1.HaConfig.virtual_router_id": Operational,
	"gateon.v1.HaConfig.priority":          Operational,
	"gateon.v1.HaConfig.virtual_ips":       Operational,
	"gateon.v1.HaConfig.advert_int":        Operational,
	"gateon.v1.HaConfig.auth_pass":         Operational,
	"gateon.v1.HaConfig.enable_gossip":     Operational,
	"gateon.v1.HaConfig.gossip_bind_addr":  Operational,
	"gateon.v1.HaConfig.gossip_bind_port":  Operational,
	"gateon.v1.HaConfig.gossip_peers":      Operational,

	// --- anomaly_detection ---
	"gateon.v1.AnomalyDetectionConfig.enabled":                          Operational,
	"gateon.v1.AnomalyDetectionConfig.check_interval_seconds":           Operational,
	"gateon.v1.AnomalyDetectionConfig.sensitivity":                      Operational,
	"gateon.v1.AnomalyDetectionConfig.security_threat_threshold":        Operational,
	"gateon.v1.AnomalyDetectionConfig.enable_behavioral_fingerprinting": Operational,
	"gateon.v1.AnomalyDetectionConfig.enable_brute_force_detection":     Operational,
	"gateon.v1.AnomalyDetectionConfig.enable_exploit_detection":         Operational,

	// --- ebpf: the packet filters are an operator's; the kernel-side
	// management allowlist and port knocking, and switching off or moving
	// the programs that carry them, are not. ---
	"gateon.v1.EbpfConfig.enabled":               Boundary,
	"gateon.v1.EbpfConfig.xdp_rate_limit":        Operational,
	"gateon.v1.EbpfConfig.tc_filtering":          Operational,
	"gateon.v1.EbpfConfig.interface":             Boundary,
	"gateon.v1.EbpfConfig.xdp_ip_shunning":       Operational,
	"gateon.v1.EbpfConfig.xdp_load_balancing":    Operational,
	"gateon.v1.EbpfConfig.enable_knocking":       Boundary,
	"gateon.v1.EbpfConfig.mgmt_port":             Boundary,
	"gateon.v1.EbpfConfig.knocking_sequence":     Boundary,
	"gateon.v1.EbpfConfig.allow_generic_xdp":     Operational,
	"gateon.v1.EbpfConfig.enable_mgmt_whitelist": Boundary,
	"gateon.v1.EbpfConfig.mgmt_whitelist_ips":    Boundary,

	// --- geoip ---
	"gateon.v1.GeoIPConfig.enabled":              Operational,
	"gateon.v1.GeoIPConfig.db_path":              Operational,
	"gateon.v1.GeoIPConfig.maxmind_license_key":  Operational,
	"gateon.v1.GeoIPConfig.auto_update":          Operational,
	"gateon.v1.GeoIPConfig.update_interval_days": Operational,
	"gateon.v1.GeoIPConfig.blocked_countries":    Operational,
	"gateon.v1.GeoIPConfig.allowed_countries":    Operational,
	"gateon.v1.GeoIPConfig.asn_db_path":          Operational,
	"gateon.v1.GeoIPConfig.country_db_path":      Operational,

	// --- debugger: captures raw request headers and bodies, which carry
	// credentials -- a dashboard session cookie among them, when the browser
	// sends it to an app on the same host. ---
	"gateon.v1.DebuggerConfig.enabled":       Boundary,
	"gateon.v1.DebuggerConfig.max_body_size": Operational,

	// --- security_advanced ---
	"gateon.v1.SecurityAdvancedConfig.deception":     Section,
	"gateon.v1.SecurityAdvancedConfig.tarpit":        Section,
	"gateon.v1.SecurityAdvancedConfig.entropy":       Section,
	"gateon.v1.SecurityAdvancedConfig.behavioral":    Section,
	"gateon.v1.SecurityAdvancedConfig.pow":           Section,
	"gateon.v1.SecurityAdvancedConfig.ip_reputation": Section,
	"gateon.v1.SecurityAdvancedConfig.tls_binding":   Section,

	"gateon.v1.DeceptionConfig.enabled":                Operational,
	"gateon.v1.DeceptionConfig.honeypot_paths":         Operational,
	"gateon.v1.DeceptionConfig.inject_invisible_links": Operational,
	"gateon.v1.DeceptionConfig.invisible_link_paths":   Operational,
	"gateon.v1.DeceptionConfig.honey_forms":            Operational,
	"gateon.v1.DeceptionConfig.canary_header":          Operational,
	"gateon.v1.DeceptionConfig.canary_token":           Operational,
	"gateon.v1.DeceptionConfig.enable_troll_response":  Operational,

	"gateon.v1.TarpitConfig.enabled":         Operational,
	"gateon.v1.TarpitConfig.delay_base_ms":   Operational,
	"gateon.v1.TarpitConfig.delay_max_ms":    Operational,
	"gateon.v1.TarpitConfig.score_threshold": Operational,

	"gateon.v1.EntropyConfig.enabled":   Operational,
	"gateon.v1.EntropyConfig.threshold": Operational,

	"gateon.v1.BehavioralConfig.enabled":                    Operational,
	"gateon.v1.BehavioralConfig.enable_impossible_travel":   Operational,
	"gateon.v1.BehavioralConfig.enable_sequence_validation": Operational,

	"gateon.v1.PowConfig.enabled":         Operational,
	"gateon.v1.PowConfig.difficulty":      Operational,
	"gateon.v1.PowConfig.score_threshold": Operational,
	"gateon.v1.PowConfig.secret":          Operational,

	"gateon.v1.IPReputationConfig.enabled":               Operational,
	"gateon.v1.IPReputationConfig.feed_urls":             Operational,
	"gateon.v1.IPReputationConfig.update_interval_hours": Operational,
	"gateon.v1.IPReputationConfig.block_threshold":       Operational,
	"gateon.v1.IPReputationConfig.integrations":          Operational,

	"gateon.v1.IPReputationIntegration.id":                   Operational,
	"gateon.v1.IPReputationIntegration.name":                 Operational,
	"gateon.v1.IPReputationIntegration.type":                 Operational,
	"gateon.v1.IPReputationIntegration.api_key":              Operational,
	"gateon.v1.IPReputationIntegration.enabled":              Operational,
	"gateon.v1.IPReputationIntegration.confidence_threshold": Operational,

	"gateon.v1.TlsBindingConfig.enabled":     Operational,
	"gateon.v1.TlsBindingConfig.cookie_name": Operational,

	// --- alerting ---
	"gateon.v1.AlertingConfig.enabled":     Operational,
	"gateon.v1.AlertingConfig.dispatchers": Operational,
	"gateon.v1.AlertingConfig.playbooks":   Operational,

	"gateon.v1.AlertDispatcher.id":                 Operational,
	"gateon.v1.AlertDispatcher.name":               Operational,
	"gateon.v1.AlertDispatcher.type":               Operational,
	"gateon.v1.AlertDispatcher.webhook_url":        Operational,
	"gateon.v1.AlertDispatcher.slack_channel":      Operational,
	"gateon.v1.AlertDispatcher.telegram_bot_token": Operational,
	"gateon.v1.AlertDispatcher.telegram_chat_id":   Operational,

	"gateon.v1.AlertPlaybook.id":             Operational,
	"gateon.v1.AlertPlaybook.name":           Operational,
	"gateon.v1.AlertPlaybook.event_type":     Operational,
	"gateon.v1.AlertPlaybook.threshold":      Operational,
	"gateon.v1.AlertPlaybook.dispatcher_ids": Operational,
	"gateon.v1.AlertPlaybook.action":         Operational,
}

// recordFields are the settings that decide what record is kept of
// management activity. Changing one is itself audited, before it takes effect.
var recordFields = map[protoreflect.FullName]bool{
	"gateon.v1.GlobalConfig.audit":                 true,
	"gateon.v1.LogConfig.audit_log_retention_days": true,
}

// ClassOf returns how fd is classified. A field the table does not name is
// Unclassified, which Authorize enforces as Boundary.
func ClassOf(fd protoreflect.FieldDescriptor) Class {
	return classes[fd.FullName()]
}

// effective is the class a save is held to: an unclassified field, and a
// Section that is not a singular message (which cannot be walked), are
// administrator-only.
func effective(fd protoreflect.FieldDescriptor) Class {
	c := ClassOf(fd)
	switch {
	case c == Unclassified:
		return Boundary
	case c == Section && !singularMessage(fd):
		return Boundary
	default:
		return c
	}
}

func singularMessage(fd protoreflect.FieldDescriptor) bool {
	return fd.Message() != nil && !fd.IsList() && !fd.IsMap()
}
