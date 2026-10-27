// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * Where each page the redesign retired or renamed now lives. Bookmarks, alert
 * links and the docs name the old paths, so every one of them keeps working:
 * the router redirects, keeping any search params and adding the tab the
 * old page became.
 */
export interface LegacyTarget {
  to: string;
  search?: Record<string, string>;
}

export const LEGACY_PATHS: Record<string, LegacyTarget> = {
  "/entryPoints": { to: "/listeners" },
  "/middlewares": { to: "/policies" },
  "/security-center": { to: "/security" },
  "/certificates": { to: "/tls", search: { tab: "certificates" } },
  "/client-authorities": { to: "/tls", search: { tab: "client-cas" } },
  "/tls-options": { to: "/tls", search: { tab: "profiles" } },
  "/users": { to: "/access", search: { tab: "users" } },
  "/api-tokens": { to: "/access", search: { tab: "tokens" } },
  "/circuit-breaker": { to: "/services" },
  "/topology": { to: "/", search: { tab: "map" } },
  "/path-metrics": { to: "/metrics-dashboard", search: { tab: "paths" } },
  // The "malware protection degraded" alert links here; malware scanning is a
  // Settings › Security matter, not a page of its own.
  "/clamav": { to: "/settings", search: { tab: "security", section: "malware" } },
};

/** The redirect for a retired path, or undefined when the path is current. */
export function legacyRedirect(pathname: string): LegacyTarget | undefined {
  return LEGACY_PATHS[pathname];
}
