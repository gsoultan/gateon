// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
  redirect,
  isRedirect,
  Outlet,
  type Register,
  createRootRouteWithContext,
} from "@tanstack/react-router";
import { lazy, Suspense } from "react";
import { QueryClient } from "@tanstack/react-query";
import { queryClient } from "./queryClient";
const Shell = lazy(() => import("./components/Shell").then((m) => ({ default: m.Shell })));
import { RouteErrorComponent, RouteFallback } from "./components/ErrorBoundary";
import { useAuthStore } from "./store/useAuthStore";
import { asSearchString } from "./hooks/useUrlFilters";
import { apiFetch, restoreSessionFromCookie } from "./hooks/http";
import { LEGACY_PATHS } from "./components/layout/legacyPaths";

const Dashboard = lazy(() => import("./routes/Dashboard"));
const RoutesPage = lazy(() => import("./routes/RoutesPage"));
const ServicesPage = lazy(() => import("./routes/ServicesPage"));
const LogsPage = lazy(() => import("./routes/LogsPage"));
const EntryPointsPage = lazy(() => import("./routes/EntryPointsPage"));
const MiddlewaresPage = lazy(() => import("./routes/MiddlewaresPage"));
const SettingsPage = lazy(() => import("./routes/SettingsPage"));
const ProfilePage = lazy(() => import("./routes/ProfilePage"));
const DocsPage = lazy(() => import("./routes/DocsPage"));
const LoginPage = lazy(() => import("./routes/LoginPage"));
const SetupPage = lazy(() => import("./routes/SetupPage"));
const SecurityCommandCenter = lazy(() => import("./routes/SecurityCommandCenter"));
const TLSPage = lazy(() => import("./routes/TLSPage"));
const AccessPage = lazy(() => import("./routes/AccessPage"));
const TracesPage = lazy(() => import("./routes/TracesPage"));
const MetricsPage = lazy(() => import("./routes/MetricsPage"));
const DiagnosticsPage = lazy(() => import("./routes/DiagnosticsPage"));
const AuditLogsPage = lazy(() => import("./routes/AuditLogsPage"));

const rootRoute = createRootRouteWithContext<{
  queryClient: QueryClient;
}>()({
  component: () => (
    <Suspense fallback={<RouteFallback />}>
      <Outlet />
    </Suspense>
  ),
  beforeLoad: async ({ location, context }) => {
    if (location.pathname === "/setup") {
      return;
    }
    try {
      const data = await context.queryClient.ensureQueryData({
        queryKey: ["setup-required"],
        queryFn: async () => {
          const res = await apiFetch("/v1/setup/required");
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          return res.json();
        },
      });
      if (data && (data.required === true || data.required === "true")) {
        throw redirect({ to: "/setup" });
      }
    } catch (e) {
      if (isRedirect(e)) {
        throw e;
      }
    }
  },
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: () => <LoginPage />,
});

const setupRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/setup",
  beforeLoad: async ({ context }) => {
    try {
      const data = await context.queryClient.ensureQueryData({
        queryKey: ["setup-required"],
        queryFn: async () => {
          const res = await apiFetch("/v1/setup/required");
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          return res.json();
        },
      });
      if (data && !(data.required === true || data.required === "true")) {
        throw redirect({ to: "/" });
      }
    } catch (e) {
      if (isRedirect(e)) {
        throw e;
      }
    }
  },
  component: () => <SetupPage />,
});

const authenticatedRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "authenticated",
  beforeLoad: async ({ location }) => {
    let token = useAuthStore.getState().token;
    if (!token) {
      const restored = await restoreSessionFromCookie();
      if (restored) token = useAuthStore.getState().token;
    }
    if (!token) {
      throw redirect({
        to: "/login",
        search: {
          redirect: location.href,
        },
      });
    }
  },
  component: () => <Shell />,
});

const indexRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/",
  // The Overview's open tab (Map holds the topology graph), so /topology
  // bookmarks and a reload land on it.
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: asSearchString(search.tab),
  }),
  component: () => <Dashboard />,
});


const routesRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/routes",
  component: () => <RoutesPage />,
});

const servicesRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/services",
  component: () => <ServicesPage />,
});

const logsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/logs",
  component: () => <LogsPage />,
});

const listenersRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/listeners",
  component: () => <EntryPointsPage />,
});

const policiesRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/policies",
  component: () => <MiddlewaresPage />,
});

const settingsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/settings",
  // The open tab, so a link can land on the card it names and a reload keeps
  // it; SettingsPage treats anything it does not know as General.
  validateSearch: (search: Record<string, unknown>): { tab?: string; section?: string; q?: string } => ({
    tab: asSearchString(search.tab),
    // The setting row a link points at, and the search box's text.
    section: asSearchString(search.section),
    q: asSearchString(search.q),
  }),
  component: () => <SettingsPage />,
});

const profileRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/profile",
  component: () => <ProfilePage />,
});

const docsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/docs",
  component: () => <DocsPage />,
});

const securityRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/security",
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: asSearchString(search.tab),
  }),
  component: () => <SecurityCommandCenter />,
});

// Certificates, client CAs and TLS profiles are three tabs of one page; the
// three old pages redirect to their tab.
const tlsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/tls",
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: asSearchString(search.tab),
  }),
  component: () => <TLSPage />,
});

// Users and API tokens, for administrators.
const accessRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/access",
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: asSearchString(search.tab),
  }),
  component: () => <AccessPage />,
});

// Every path the redesign retired or renamed still answers: it redirects to
// the page that replaced it, keeping the search and adding the tab the old
// page became, so bookmarks, alert links and the docs keep working.
const legacyRoutes = Object.entries(LEGACY_PATHS).map(([from, target]) =>
  createRoute({
    getParentRoute: () => authenticatedRoute,
    path: from,
    beforeLoad: ({ search }) => {
      throw redirect({
        to: target.to,
        search: { ...(search as Record<string, unknown>), ...target.search },
        replace: true,
      });
    },
  }),
);

const tracesRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/traces",
  validateSearch: (
    search: Record<string, unknown>,
  ): { q?: string; route?: string; tab?: string; from?: string; to?: string } => ({
    q: asSearchString(search.q),
    route: asSearchString(search.route),
    // The History tab's period, so a period of traces can be bookmarked and
    // shared; TracesPage checks both are times before using them.
    tab: asSearchString(search.tab),
    from: asSearchString(search.from),
    to: asSearchString(search.to),
  }),
  component: () => <TracesPage />,
});

// Not /metrics: that is Prometheus' exposition endpoint on this same origin, so
// a reload, a bookmark or a link opened in a new tab asked the gateway for
// /metrics and rendered raw exposition text instead of this page.
const metricsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/metrics-dashboard",
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: asSearchString(search.tab),
  }),
  component: () => <MetricsPage />,
});

const diagnosticsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/diagnostics",
  component: () => <DiagnosticsPage />,
});

const auditLogsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/audit-logs",
  validateSearch: (search: Record<string, unknown>): { q?: string } => ({
    q: asSearchString(search.q),
  }),
  component: () => <AuditLogsPage />,
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  setupRoute,
  authenticatedRoute.addChildren([
    indexRoute,
    routesRoute,
    servicesRoute,
    listenersRoute,
    policiesRoute,
    securityRoute,
    tlsRoute,
    logsRoute,
    tracesRoute,
    metricsRoute,
    settingsRoute,
    accessRoute,
    auditLogsRoute,
    diagnosticsRoute,
    profileRoute,
    docsRoute,
    ...legacyRoutes,
  ]),
]);

export const router = createRouter({
  routeTree,
  context: {
    queryClient,
  },
  defaultErrorComponent: RouteErrorComponent,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

export function AppRouter() {
  return <RouterProvider router={router} />;
}
