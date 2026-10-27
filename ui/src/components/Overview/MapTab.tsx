// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { lazy, Suspense } from "react";
import { Box, LoadingOverlay } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../../hooks/api";
import type { EntryPoint, Middleware, Route, Service } from "../../types/gateon";
import { QueryError } from "../QueryError";

// The graph pulls in @xyflow/react and dagre, fetched only when this tab opens.
const TopologyGraph = lazy(() => import("../TopologyGraph").then((m) => ({ default: m.TopologyGraph })));

/**
 * Every item of one list endpoint. A failed read throws: this used to become
 * an empty list, so an unreachable gateway drew a gateway with no traffic
 * path at all.
 */
function useFullList<T>(key: string, path: string, field: string) {
  return useQuery<T[]>({
    queryKey: [key, "all"],
    queryFn: async () => {
      const res = await apiFetch(`${path}?pageSize=1000`);
      if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
      const data = (await res.json()) as Record<string, unknown> | null;
      const list = data?.[field];
      return Array.isArray(list) ? (list as T[]) : [];
    },
  });
}

/** The gateway as a picture: listeners, routes, policies and services, and how traffic flows between them. */
export default function MapTab() {
  const routesQ = useFullList<Route>("routes", "/v1/routes", "routes");
  const servicesQ = useFullList<Service>("services", "/v1/services", "services");
  const entryPointsQ = useFullList<EntryPoint>("entryPoints", "/v1/entryPoints", "entryPoints");
  const middlewaresQ = useFullList<Middleware>("middlewares", "/v1/middlewares", "middlewares");
  const queries = [routesQ, servicesQ, entryPointsQ, middlewaresQ];
  const failed = queries.find((q) => q.isError);
  const isLoading = queries.some((q) => q.isLoading);

  return (
    <Box pos="relative" mih={480}>
      <LoadingOverlay visible={isLoading} />
      {failed && <QueryError error={failed.error} what="the map" onRetry={() => queries.forEach((q) => void q.refetch())} />}
      {!failed && entryPointsQ.data && routesQ.data && servicesQ.data && middlewaresQ.data && (
        <Suspense fallback={<LoadingOverlay visible />}>
          <TopologyGraph entryPoints={entryPointsQ.data} routes={routesQ.data} services={servicesQ.data} middlewares={middlewaresQ.data} />
        </Suspense>
      )}
    </Box>
  );
}
