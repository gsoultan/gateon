// Package siem exports Gateon's structured security events (raw threats and
// correlated incidents) to external SIEM/log collectors such as the Wazuh
// indexer, Elasticsearch/OpenSearch, Splunk, or any syslog sink. It is
// dependency-free (standard library only) and ships events asynchronously over
// a bounded queue so the request hot path is never blocked.
package siem

import "time"

// Kind classifies an exported event.
type Kind string

const (
	// KindThreat is a single raw detection event.
	KindThreat Kind = "threat"
	// KindIncident is a correlated, MITRE-annotated finding.
	KindIncident Kind = "incident"
)

// Event is a transport-neutral security event. Formatters render it as JSON,
// CEF, or RFC 5424 syslog; the Fields map carries format-specific extras
// (e.g. MITRE technique IDs, signal types) as stable string key/values.
type Event struct {
	Time     time.Time         `json:"timestamp"`
	Kind     Kind              `json:"kind"`
	Name     string            `json:"name"`
	Severity string            `json:"severity"`
	SourceIP string            `json:"source_ip,omitzero"`
	Message  string            `json:"message,omitzero"`
	Fields   map[string]string `json:"fields,omitzero"`
}
