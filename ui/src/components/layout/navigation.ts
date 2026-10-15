// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ComponentType } from "react";
import {
  IconAccessPoint,
  IconActivity,
  IconBook2,
  IconCertificate,
  IconChartBar,
  IconCircuitSwitchClosed,
  IconDashboard,
  IconKey,
  IconListDetails,
  IconLockAccess,
  IconNetwork,
  IconRoute,
  IconServer,
  IconSettings,
  IconSettingsAutomation,
  IconShieldCheck,
  IconShieldLock,
  IconStethoscope,
  IconTerminal2,
  IconTimeline,
  IconUsers,
  IconVirus,
} from "@tabler/icons-react";

export interface NavItem {
  label: string;
  to: string;
  icon: ComponentType<{ size?: number | string; stroke?: number }>;
}

export interface NavSection {
  title: string;
  items: NavItem[];
}

export interface NavContext {
  /** ClamAV is listed only once the daemon is installed. */
  clamavInstalled: boolean;
  /** Users and API tokens are an administrator's pages. */
  isAdmin: boolean;
}

/**
 * The sidebar, in the order an operator reaches for it: traffic first, then
 * what protects it, then the gateway itself. Pages a role cannot use are left
 * out rather than shown and refused.
 */
export function navSections({ clamavInstalled, isAdmin }: NavContext): NavSection[] {
  return [
    {
      title: "Traffic",
      items: [
        { label: "Dashboard", to: "/", icon: IconDashboard },
        { label: "Routes", to: "/routes", icon: IconRoute },
        { label: "Services", to: "/services", icon: IconServer },
        { label: "EntryPoints", to: "/entryPoints", icon: IconAccessPoint },
        { label: "Topology", to: "/topology", icon: IconNetwork },
      ],
    },
    {
      title: "Observe",
      items: [
        { label: "Metrics", to: "/metrics-dashboard", icon: IconChartBar },
        { label: "Path Metrics", to: "/path-metrics", icon: IconActivity },
        { label: "Traces", to: "/traces", icon: IconTimeline },
        { label: "Circuit Breaker", to: "/circuit-breaker", icon: IconCircuitSwitchClosed },
        { label: "Logs", to: "/logs", icon: IconTerminal2 },
      ],
    },
    {
      title: "Security",
      items: [
        { label: "Security Hub", to: "/security-center", icon: IconShieldCheck },
        // An operator without ClamAV has nothing to manage here, and a
        // permanent dead entry teaches people to ignore the section. The
        // route still exists for anyone who follows a link to it.
        ...(clamavInstalled ? [{ label: "Antivirus", to: "/clamav", icon: IconVirus }] : []),
        { label: "Middlewares", to: "/middlewares", icon: IconSettingsAutomation },
        { label: "Certificates", to: "/certificates", icon: IconCertificate },
        { label: "Client Authorities", to: "/client-authorities", icon: IconShieldLock },
        { label: "TLS Options", to: "/tls-options", icon: IconLockAccess },
        { label: "Audit Logs", to: "/audit-logs", icon: IconListDetails },
      ],
    },
    {
      title: "System",
      items: [
        { label: "Settings", to: "/settings", icon: IconSettings },
        ...(isAdmin
          ? [
              { label: "Users", to: "/users", icon: IconUsers },
              { label: "API Tokens", to: "/api-tokens", icon: IconKey },
            ]
          : []),
        { label: "Diagnostics", to: "/diagnostics", icon: IconStethoscope },
        { label: "Docs", to: "/docs", icon: IconBook2 },
      ],
    },
  ];
}

/**
 * Whether a sidebar entry is the page being shown. A page's own sub-paths
 * count, so /traces/abc keeps Traces highlighted; the dashboard at "/" matches
 * only itself, or it would be highlighted on every page.
 */
export function isActivePath(pathname: string, to: string): boolean {
  if (to === "/") return pathname === "/";
  return pathname === to || pathname.startsWith(`${to}/`);
}
