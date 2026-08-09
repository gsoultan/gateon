// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package correlation

// Technique is a reference to a MITRE ATT&CK technique. It lets Gateon map raw
// detection signals onto the industry-standard adversary tactic/technique
// taxonomy, the same way a SIEM such as Wazuh annotates its rules.
type Technique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

// techniqueByThreat maps Gateon's internal threat Type values (as recorded via
// telemetry.RecordSecurityThreat) to the MITRE ATT&CK techniques they evidence.
// Unknown types simply yield no techniques rather than failing.
var techniqueByThreat = map[string][]Technique{
	"brute_force_attempt":   {{ID: "T1110", Name: "Brute Force", Tactic: "Credential Access"}},
	"exploit_scan":          {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}, {ID: "T1595", Name: "Active Scanning", Tactic: "Reconnaissance"}},
	"probe_detected":        {{ID: "T1595", Name: "Active Scanning", Tactic: "Reconnaissance"}},
	"api_fuzzing":           {{ID: "T1595.003", Name: "Active Scanning: Wordlist Scanning", Tactic: "Reconnaissance"}},
	"dga_detected":          {{ID: "T1568.002", Name: "Dynamic Resolution: Domain Generation Algorithms", Tactic: "Command and Control"}},
	"behavioral_anomaly":    {{ID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control"}},
	"rate_limit":            {{ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "Impact"}},
	"error_rate_spike":      {{ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "Impact"}},
	"latency_spike":         {{ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "Impact"}},
	"bot_detected":          {{ID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control"}},
	"geoip_block":           {{ID: "T1090", Name: "Proxy", Tactic: "Command and Control"}},
	"sql_injection":         {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},
	"impossible_travel":     {{ID: "T1078", Name: "Valid Accounts", Tactic: "Defense Evasion"}},
	"device_posture_change": {{ID: "T1078", Name: "Valid Accounts", Tactic: "Defense Evasion"}},
	"security_threat":       {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},

	// The WAF records "waf_" + action, so the types that actually arrive here
	// are waf_blocked and waf_detected. "waf_block" was neither, and it was the
	// single most common threat gateon produces — the Incidents tab showed an
	// empty MITRE column for every WAF finding. It is kept because it is written
	// into rows that already exist, and dropping it would unmap history.
	"waf_block":    {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},
	"waf_blocked":  {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},
	"waf_detected": {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},

	// A mitigation is the response to an adversary that already cleared a
	// detector, so it evidences the same initial-access attempt that earned it.
	"user_mitigation": {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},
	"ip_mitigation":   {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},

	// A client with a hostile reputation is a known-bad infrastructure signal.
	"reputation_block": {{ID: "T1583", Name: "Acquire Infrastructure", Tactic: "Resource Development"}},

	// Nothing reaches a honeypot path by browsing. It is enumeration by
	// definition, which is what makes it such a low-false-positive signal.
	"honeypot_triggered": {{ID: "T1595", Name: "Active Scanning", Tactic: "Reconnaissance"}},
	"honeypot_hit":       {{ID: "T1595", Name: "Active Scanning", Tactic: "Reconnaissance"}},

	// A cross-origin request the policy refused is an attempt to read a resource
	// from a context that should not be able to.
	"cors_violation": {{ID: "T1185", Name: "Browser Session Hijacking", Tactic: "Collection"}},

	"geofence_violation":          {{ID: "T1090", Name: "Proxy", Tactic: "Command and Control"}},
	"sqli_detected":               {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},
	"security_scan":               {{ID: "T1595", Name: "Active Scanning", Tactic: "Reconnaissance"}},
	"coordinated_attack":          {{ID: "T1498", Name: "Network Denial of Service", Tactic: "Impact"}},
	"ip_shunning":                 {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},
	"slow_client_anomaly":         {{ID: "T1499.002", Name: "Endpoint Denial of Service: Service Exhaustion Flood", Tactic: "Impact"}},
	"management_access_violation": {{ID: "T1133", Name: "External Remote Services", Tactic: "Initial Access"}},
	"system_integrity_violation":  {{ID: "T1565.001", Name: "Data Manipulation: Stored Data Manipulation", Tactic: "Impact"}},
}

// Techniques returns the MITRE ATT&CK techniques associated with a threat type.
// The returned slice is a copy and safe for the caller to retain or mutate.
func Techniques(threatType string) []Technique {
	src := techniqueByThreat[threatType]
	if len(src) == 0 {
		return nil
	}
	out := make([]Technique, len(src))
	copy(out, src)
	return out
}
