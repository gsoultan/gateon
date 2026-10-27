// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMantineColorScheme } from "@mantine/core";
import {
  IconDashboard,
  IconRoute,
  IconServer,
  IconTerminal2,
  IconSettings,
  IconCertificate,
  IconShieldCheck,
  IconSettingsAutomation,
  IconUsers,
  IconAccessPoint,
  IconSun,
  IconMoon,
  IconDeviceDesktop,
  IconBook2,
  IconTimeline,
  IconChartBar,
  IconStethoscope,
  IconUser,
  IconLogout,
  IconLayoutSidebar,
} from "@tabler/icons-react";
import { useAuthStore } from "../../store/useAuthStore";
import { usePreferencesStore } from "../../store/usePreferencesStore";
import { useSignOut } from "../../hooks/useSignOut";
import { SIGN_OUT_SCOPE } from "../signOut";
import type { Command } from "./types";

interface NavSpec {
  label: string;
  to: string;
  icon: Command["icon"];
  keywords?: string[];
  adminOnly?: boolean;
}

const navSpecs: NavSpec[] = [
  { label: "Overview", to: "/", icon: IconDashboard, keywords: ["home", "dashboard", "map", "topology"] },
  { label: "Routes", to: "/routes", icon: IconRoute },
  { label: "Services", to: "/services", icon: IconServer, keywords: ["backends", "circuit breaker"] },
  { label: "Listeners", to: "/listeners", icon: IconAccessPoint, keywords: ["entrypoints", "ports"] },
  { label: "Policies", to: "/policies", icon: IconSettingsAutomation, keywords: ["middlewares"] },
  { label: "Security", to: "/security", icon: IconShieldCheck, keywords: ["waf", "threats", "blocks", "rules"] },
  { label: "TLS", to: "/tls", icon: IconCertificate, keywords: ["certificates", "ssl", "client ca", "profiles"] },
  { label: "Logs", to: "/logs", icon: IconTerminal2, keywords: ["live"] },
  { label: "Traces", to: "/traces", icon: IconTimeline },
  { label: "Metrics", to: "/metrics-dashboard", icon: IconChartBar, keywords: ["paths", "golden signals"] },
  { label: "Settings", to: "/settings", icon: IconSettings },
  { label: "Access", to: "/access", icon: IconUsers, keywords: ["users", "api tokens", "rbac"], adminOnly: true },
  { label: "Audit log", to: "/audit-logs", icon: IconTimeline },
  { label: "Diagnostics", to: "/diagnostics", icon: IconStethoscope },
  { label: "Docs", to: "/docs", icon: IconBook2, keywords: ["help", "documentation"] },
  { label: "Profile", to: "/profile", icon: IconUser, keywords: ["account"] },
];

/**
 * useCommands assembles the full set of palette commands (navigation + quick
 * actions) tailored to the current user's role. The list is memoized so the
 * palette re-renders cheaply on every keystroke.
 */
export function useCommands(close: () => void): Command[] {
  const navigate = useNavigate();
  const { setColorScheme } = useMantineColorScheme();
  const role = useAuthStore((s) => s.user?.role);
  const signOut = useSignOut();
  const toggleSidebar = usePreferencesStore((s) => s.toggleSidebar);

  return useMemo<Command[]>(() => {
    const go = (to: string) => () => {
      close();
      void navigate({ to });
    };

    const navCommands: Command[] = navSpecs
      .filter((spec) => !spec.adminOnly || role === "admin")
      .map((spec) => ({
        id: `nav:${spec.to}`,
        label: spec.label,
        description: spec.to,
        group: "Navigation",
        icon: spec.icon,
        keywords: spec.keywords,
        perform: go(spec.to),
      }));


    const actionCommands: Command[] = [
      {
        id: "action:toggle-sidebar",
        label: "Toggle Sidebar",
        group: "Actions",
        icon: IconLayoutSidebar,
        keywords: ["collapse", "expand", "navbar"],
        perform: () => {
          close();
          toggleSidebar();
        },
      },
      {
        id: "action:theme-light",
        label: "Theme: Light",
        group: "Appearance",
        icon: IconSun,
        perform: () => {
          close();
          setColorScheme("light");
        },
      },
      {
        id: "action:theme-dark",
        label: "Theme: Dark",
        group: "Appearance",
        icon: IconMoon,
        perform: () => {
          close();
          setColorScheme("dark");
        },
      },
      {
        id: "action:theme-auto",
        label: "Theme: Follow System",
        group: "Appearance",
        icon: IconDeviceDesktop,
        perform: () => {
          close();
          setColorScheme("auto");
        },
      },
      {
        id: "action:logout",
        label: "Sign out",
        description: SIGN_OUT_SCOPE,
        group: "Actions",
        icon: IconLogout,
        keywords: ["logout", "exit"],
        perform: () => {
          close();
          void signOut();
        },
      },
    ];

    return [...navCommands, ...actionCommands];
  }, [navigate, setColorScheme, role, signOut, toggleSidebar, close]);
}
