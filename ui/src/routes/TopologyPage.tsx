// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { lazy, Suspense } from "react";
import {
  Title,
  Text,
  Stack,
  Group,
  LoadingOverlay,
} from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../hooks/useGateon";
import { QueryError } from "../components/QueryError";
import { type Route, type Service, type EntryPoint, type Middleware } from "../types/gateon";

// Lazy-loaded: the graph pulls in @xyflow/react + dagre (the heavy `viz-vendor`
// chunk), which we only want to fetch once this page actually renders the graph.
const TopologyGraph = lazy(() =>
  import("../components/TopologyGraph").then((m) => ({ default: m.TopologyGraph })),
);

/**
 * Every item of one list endpoint. A failed read throws: the page used to turn
 * it into an empty list, so an unreachable gateway or an expired session drew
 * an empty graph -- a picture of a gateway with no traffic path at all.
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

export default function TopologyPage() {
  const routesQ = useFullList<Route>("routes", "/v1/routes", "routes");
  const servicesQ = useFullList<Service>("services", "/v1/services", "services");
  const entryPointsQ = useFullList<EntryPoint>("entryPoints", "/v1/entryPoints", "entryPoints");
  const middlewaresQ = useFullList<Middleware>("middlewares", "/v1/middlewares", "middlewares");
  const queries = [routesQ, servicesQ, entryPointsQ, middlewaresQ];
  const failed = queries.find((q) => q.isError);
  const routes = routesQ.data;
  const services = servicesQ.data;
  const entryPoints = entryPointsQ.data;
  const middlewares = middlewaresQ.data;
  const isLoading = queries.some((q) => q.isLoading);

  return (
    <Stack gap="xl" pos="relative" h="100%">
      <LoadingOverlay visible={isLoading} />
      <Group justify="space-between">
        <div>
          <Title order={2}>Traffic Topology</Title>
          <Text size="sm" c="dimmed">
            Animated visual flow of traffic from entryPoints to backend services through middlewares.
          </Text>
        </div>
      </Group>

      {failed && (
        <QueryError error={failed.error} what="the topology" onRetry={() => queries.forEach((q) => void q.refetch())} />
      )}

      {!failed && entryPoints && routes && services && middlewares && (
        <Suspense fallback={<LoadingOverlay visible />}>
          <TopologyGraph
            entryPoints={entryPoints}
            routes={routes}
            services={services}
            middlewares={middlewares}
          />
        </Suspense>
      )}
    </Stack>
  );
}
