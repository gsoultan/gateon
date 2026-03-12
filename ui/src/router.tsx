import {
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
  redirect,
  isRedirect,
  Outlet,
  type Register,
} from "@tanstack/react-router";
import { lazy, Suspense } from "react";
import { Shell } from "./components/Shell";
import { useAuthStore } from "./store/useAuthStore";
import { apiFetch } from "./hooks/useGateon";

const Dashboard = lazy(() => import("./routes/Dashboard"));
const RoutesPage = lazy(() => import("./routes/RoutesPage"));
const ServicesPage = lazy(() => import("./routes/ServicesPage"));
const LogsPage = lazy(() => import("./routes/LogsPage"));
const PathMetricsPage = lazy(() => import("./routes/PathMetricsPage"));
const CertificatesPage = lazy(() => import("./routes/CertificatesPage"));
const ClientAuthoritiesPage = lazy(() => import("./routes/ClientAuthoritiesPage"));
const EntryPointsPage = lazy(() => import("./routes/EntryPointsPage"));
const MiddlewaresPage = lazy(() => import("./routes/MiddlewaresPage"));
const TLSOptionsPage = lazy(() => import("./routes/TLSOptionsPage"));
const SettingsPage = lazy(() => import("./routes/SettingsPage"));
const UsersPage = lazy(() => import("./routes/UsersPage"));
const LoginPage = lazy(() => import("./routes/LoginPage"));
const SetupPage = lazy(() => import("./routes/SetupPage"));

const rootRoute = createRootRoute({
  component: () => (
    <Suspense fallback={null}>
      <Outlet />
    </Suspense>
  ),
  beforeLoad: async ({ location }) => {
    if (location.pathname === "/setup") {
      return;
    }
    try {
      const res = await apiFetch("/v1/setup/required");
      if (!res.ok) {
        return;
      }

      const data = await res.json();
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
  component: () => <SetupPage />,
});

const authenticatedRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "authenticated",
  beforeLoad: async ({ location }) => {
    const token = useAuthStore.getState().token;
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

const pathMetricsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/path-metrics",
  component: () => <PathMetricsPage />,
});

const certificatesRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/certificates",
  component: () => <CertificatesPage />,
});

const clientAuthoritiesRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/client-authorities",
  component: () => <ClientAuthoritiesPage />,
});

const entryPointsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/entrypoints",
  component: () => <EntryPointsPage />,
});

const middlewaresRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/middlewares",
  component: () => <MiddlewaresPage />,
});

const tlsOptionsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/tls-options",
  component: () => <TLSOptionsPage />,
});

const settingsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/settings",
  component: () => <SettingsPage />,
});

const usersRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: "/users",
  component: () => <UsersPage />,
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  setupRoute,
  authenticatedRoute.addChildren([
    indexRoute,
    routesRoute,
    servicesRoute,
    logsRoute,
    pathMetricsRoute,
    certificatesRoute,
    clientAuthoritiesRoute,
    entryPointsRoute,
    middlewaresRoute,
    tlsOptionsRoute,
    settingsRoute,
    usersRoute,
  ]),
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

export function AppRouter() {
  return <RouterProvider router={router} />;
}
