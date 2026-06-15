import { useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMantineColorScheme } from "@mantine/core";
import {
  IconDashboard,
  IconRoute,
  IconServer,
  IconTerminal2,
  IconSettings,
  IconActivity,
  IconCertificate,
  IconShieldCheck,
  IconShieldLock,
  IconLockAccess,
  IconSettingsAutomation,
  IconUsers,
  IconAccessPoint,
  IconSun,
  IconMoon,
  IconDeviceDesktop,
  IconCircuitSwitchClosed,
  IconBook2,
  IconNetwork,
  IconTimeline,
  IconChartBar,
  IconStethoscope,
  IconUser,
  IconLogout,
  IconLayoutSidebar,
} from "@tabler/icons-react";
import { useAuthStore } from "../../store/useAuthStore";
import { usePreferencesStore } from "../../store/usePreferencesStore";
import { apiFetch } from "../../hooks/useGateon";
import { queryClient } from "../../queryClient";
import type { Command } from "./types";

interface NavSpec {
  label: string;
  to: string;
  icon: Command["icon"];
  keywords?: string[];
}

const navSpecs: NavSpec[] = [
  { label: "Dashboard", to: "/", icon: IconDashboard, keywords: ["home", "overview"] },
  { label: "Topology", to: "/topology", icon: IconNetwork, keywords: ["graph", "map"] },
  { label: "Traces", to: "/traces", icon: IconTimeline },
  { label: "Routes", to: "/routes", icon: IconRoute },
  { label: "Services", to: "/services", icon: IconServer },
  { label: "Metrics", to: "/metrics", icon: IconChartBar },
  { label: "Path Metrics", to: "/path-metrics", icon: IconActivity },
  { label: "Circuit Breaker", to: "/circuit-breaker", icon: IconCircuitSwitchClosed },
  { label: "EntryPoints", to: "/entrypoints", icon: IconAccessPoint },
  { label: "Security Hub", to: "/security-center", icon: IconShieldCheck, keywords: ["waf", "threats"] },
  { label: "Audit Logs", to: "/audit-logs", icon: IconTimeline },
  { label: "Certificates", to: "/certificates", icon: IconCertificate, keywords: ["tls", "ssl"] },
  { label: "Client Authorities", to: "/client-authorities", icon: IconShieldLock },
  { label: "TLS Options", to: "/tls-options", icon: IconLockAccess },
  { label: "Middlewares", to: "/middlewares", icon: IconSettingsAutomation },
  { label: "Docs", to: "/docs", icon: IconBook2, keywords: ["help", "documentation"] },
  { label: "Diagnostics", to: "/diagnostics", icon: IconStethoscope },
  { label: "Logs", to: "/logs", icon: IconTerminal2, keywords: ["live"] },
  { label: "Settings", to: "/settings", icon: IconSettings },
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
  const logout = useAuthStore((s) => s.logout);
  const toggleSidebar = usePreferencesStore((s) => s.toggleSidebar);

  return useMemo<Command[]>(() => {
    const go = (to: string) => () => {
      close();
      void navigate({ to });
    };

    const navCommands: Command[] = navSpecs
      .filter((spec) => spec.to !== "/users" || role === "admin")
      .map((spec) => ({
        id: `nav:${spec.to}`,
        label: spec.label,
        description: spec.to,
        group: "Navigation",
        icon: spec.icon,
        keywords: spec.keywords,
        perform: go(spec.to),
      }));

    if (role === "admin") {
      navCommands.push({
        id: "nav:/users",
        label: "Users",
        description: "/users",
        group: "Navigation",
        icon: IconUsers,
        keywords: ["accounts", "rbac"],
        perform: go("/users"),
      });
    }

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
        group: "Actions",
        icon: IconLogout,
        keywords: ["logout", "exit"],
        perform: () => {
          close();
          void (async () => {
            try {
              await apiFetch("/v1/logout", { method: "POST" });
            } catch {
              // Ignore network errors; clear local session regardless.
            } finally {
              queryClient.clear();
              logout();
              void navigate({ to: "/login" });
            }
          })();
        },
      },
    ];

    return [...navCommands, ...actionCommands];
  }, [navigate, setColorScheme, role, logout, toggleSidebar, close]);
}
