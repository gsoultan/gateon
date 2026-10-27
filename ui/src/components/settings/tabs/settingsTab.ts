// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

export const SETTINGS_TABS = ["general", "gateway", "security", "network", "storage", "integrations"] as const;
export type SettingsTab = (typeof SETTINGS_TABS)[number];

/** What each section is called and what it holds, in the order of the sub-nav. */
export const SETTINGS_SECTIONS: ReadonlyArray<{ id: SettingsTab; label: string; description: string }> = [
  { id: "general", label: "General", description: "This dashboard, the resource profile, import and export." },
  { id: "gateway", label: "Gateway", description: "TLS, transports, the management API and sign-in." },
  { id: "security", label: "Security", description: "The WAF, detection, GeoIP and the advanced protections." },
  { id: "network", label: "Network", description: "Failover between gateways and the kernel offload." },
  { id: "storage", label: "Storage and retention", description: "Logs, how long each record is kept, and the archives." },
  { id: "integrations", label: "Integrations", description: "Redis, OpenTelemetry, alerting and the AI provider." },
];

// asSettingsTab reads the ?tab= search param. Anything it does not name,
// including nothing, is the General section, so an old bookmark still lands.
export function asSettingsTab(value: string | undefined): SettingsTab {
  return SETTINGS_TABS.find((t) => t === value) ?? "general";
}
