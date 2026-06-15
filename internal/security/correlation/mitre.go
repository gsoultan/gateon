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
	"waf_block":             {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},
	"sql_injection":         {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},
	"impossible_travel":     {{ID: "T1078", Name: "Valid Accounts", Tactic: "Defense Evasion"}},
	"device_posture_change": {{ID: "T1078", Name: "Valid Accounts", Tactic: "Defense Evasion"}},
	"security_threat":       {{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}},
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
