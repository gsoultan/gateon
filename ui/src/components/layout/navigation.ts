// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ComponentType } from "react";
import {
  IconAccessPoint,
  IconChartBar,
  IconDashboard,
  IconListDetails,
  IconLockAccess,
  IconRoute,
  IconServer,
  IconSettings,
  IconSettingsAutomation,
  IconShieldCheck,
  IconStethoscope,
  IconTerminal2,
  IconTimeline,
  IconUsers,
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
  /** Access (users and API tokens) is an administrator's page. */
  isAdmin: boolean;
}

/**
 * The sidebar: fourteen destinations in four groups, ordered by the question
 * an operator is asking. Where does traffic go (Traffic), what protects it
 * (Security), what is happening (Observe), how is the gateway set up (System).
 * The sidebar label is the page title, everywhere. Pages a role cannot use are
 * left out rather than shown and refused. Docs is a book in the header.
 */
export function navSections({ isAdmin }: NavContext): NavSection[] {
  return [
    {
      title: "",
      items: [{ label: "Overview", to: "/", icon: IconDashboard }],
    },
    {
      title: "Traffic",
      items: [
        { label: "Routes", to: "/routes", icon: IconRoute },
        { label: "Services", to: "/services", icon: IconServer },
        { label: "Listeners", to: "/listeners", icon: IconAccessPoint },
        { label: "Policies", to: "/policies", icon: IconSettingsAutomation },
      ],
    },
    {
      title: "Security",
      items: [
        { label: "Security", to: "/security", icon: IconShieldCheck },
        { label: "TLS", to: "/tls", icon: IconLockAccess },
      ],
    },
    {
      title: "Observe",
      items: [
        { label: "Logs", to: "/logs", icon: IconTerminal2 },
        { label: "Traces", to: "/traces", icon: IconTimeline },
        { label: "Metrics", to: "/metrics-dashboard", icon: IconChartBar },
      ],
    },
    {
      title: "System",
      items: [
        { label: "Settings", to: "/settings", icon: IconSettings },
        ...(isAdmin ? [{ label: "Access", to: "/access", icon: IconUsers }] : []),
        { label: "Audit log", to: "/audit-logs", icon: IconListDetails },
        { label: "Diagnostics", to: "/diagnostics", icon: IconStethoscope },
      ],
    },
  ];
}

/**
 * Whether a sidebar entry is the page being shown. A page's own sub-paths
 * count, so /traces/abc keeps Traces highlighted; the Overview at "/" matches
 * only itself, or it would be highlighted on every page.
 */
export function isActivePath(pathname: string, to: string): boolean {
  if (to === "/") return pathname === "/";
  return pathname === to || pathname.startsWith(`${to}/`);
}
