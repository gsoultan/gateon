// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { SettingsTab } from "./tabs/settingsTab";

export interface SettingsIndexEntry {
  /** The SettingsEntry id the result scrolls to. */
  id: string;
  section: SettingsTab;
  title: string;
  /** The words an operator types that the title does not contain. */
  keywords: string[];
}

/**
 * Every card of Settings, by the words someone might search for. A search
 * finds the card and its section; six sections are more than anyone can
 * remember the contents of.
 */
export const SETTINGS_INDEX: readonly SettingsIndexEntry[] = [
  { id: "import-export", section: "general", title: "Import and export", keywords: ["backup", "restore", "yaml", "json", "config file"] },
  { id: "dashboard", section: "general", title: "Dashboard connection", keywords: ["api url", "refresh", "interval", "poll"] },
  { id: "profile", section: "general", title: "Resource profile", keywords: ["tier", "minimal", "standard", "enterprise", "memory limit"] },
  { id: "appearance", section: "general", title: "Appearance", keywords: ["theme", "dark", "light", "colour", "color"] },
  { id: "presets", section: "gateway", title: "Presets", keywords: ["development", "production", "high throughput"] },
  { id: "gateway", section: "gateway", title: "Gateway", keywords: ["tls", "certificate", "acme", "cipher", "transport", "pool", "keep-alive", "management api", "bind", "allowlist", "auth", "sign in", "session"] },
  { id: "environment", section: "gateway", title: "Performance environment", keywords: ["gogc", "memory limit", "env", "GATEON_PROFILE"] },
  { id: "access", section: "security", title: "Access control", keywords: ["users", "roles", "api tokens", "rbac"] },
  { id: "waf", section: "security", title: "WAF", keywords: ["rules", "paranoia", "categories", "enforce", "audit only", "bot management"] },
  { id: "malware", section: "security", title: "Malware scanning", keywords: ["clamav", "antivirus", "upload", "virus"] },
  { id: "anomaly", section: "security", title: "Anomaly detection", keywords: ["baseline", "score", "behaviour"] },
  { id: "geoip", section: "security", title: "GeoIP", keywords: ["country", "mmdb", "asn", "block countries"] },
  { id: "advanced", section: "security", title: "Advanced security", keywords: ["honeypot", "deception", "tarpit", "proof of work", "ip reputation", "entropy", "behavioral"] },
  { id: "ha", section: "network", title: "High availability", keywords: ["vrrp", "failover", "virtual ip", "keepalived"] },
  { id: "ebpf", section: "network", title: "eBPF offload", keywords: ["xdp", "kernel", "port knocking", "drop"] },
  { id: "logging", section: "storage", title: "Logging and retention", keywords: ["log level", "format", "json", "retention days", "access log", "path metrics"] },
  { id: "trace-archive", section: "storage", title: "Trace archive", keywords: ["traces", "pebble", "archive", "disk"] },
  { id: "threat-archive", section: "storage", title: "Threat archive", keywords: ["security threats", "archive", "retention"] },
  { id: "audit", section: "storage", title: "Audit log", keywords: ["forensic", "signing", "retention", "tamper"] },
  { id: "redis", section: "integrations", title: "Redis", keywords: ["cache", "shared rate limit", "cluster"] },
  { id: "otel", section: "integrations", title: "OpenTelemetry", keywords: ["otlp", "tracing", "exporter", "jaeger", "tempo"] },
  { id: "alerting", section: "integrations", title: "Alerting", keywords: ["webhook", "slack", "email", "soar", "playbook", "dispatcher", "siem"] },
  { id: "ai", section: "integrations", title: "AI provider", keywords: ["llm", "openai", "anthropic", "advisory", "model"] },
];

/** The entries whose title or keywords contain every word of the query, in index order. */
export function searchSettings(query: string): SettingsIndexEntry[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [];
  return SETTINGS_INDEX.filter((e) => {
    const hay = `${e.title} ${e.keywords.join(" ")} ${e.section}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}
