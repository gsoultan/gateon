import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { useApiConfigStore } from "../store/useApiConfigStore";
import type { TargetStats } from "../types/gateon";

type AllRouteStats = Record<string, TargetStats[]>;

const EMPTY: TargetStats[] = [];

/**
 * Every route's target stats, fetched once.
 *
 * This is deliberately a single query shared by every caller rather than one
 * query per route. The dashboard renders a sparkline per route and the circuit
 * breaker page a row per route, so the per-route form issued one request per
 * route per refresh — 21 requests every 30 seconds on a seven-route gateway,
 * from a tab nobody was interacting with, growing with the routing table.
 *
 * React Query dedupes by key, so N components subscribing to this key produce
 * one request no matter how many rows are on screen.
 */
export function useAllRouteStats() {
  const refreshIntervalSec = useApiConfigStore((s) => s.refreshInterval);
  return useQuery<AllRouteStats>({
    queryKey: ["route-stats"],
    queryFn: async () => {
      const res = await apiFetch("/v1/routes/stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: refreshIntervalSec * 1000,
  });
}

/**
 * One route's target stats.
 *
 * The signature is unchanged from when this fetched per route, so every call
 * site keeps working; only the number of requests changed. `select` runs
 * against the shared cache entry, so a component re-renders when its own
 * route's numbers move.
 */
export function useRouteStats(routeId: string) {
  const refreshIntervalSec = useApiConfigStore((s) => s.refreshInterval);
  return useQuery<AllRouteStats, Error, TargetStats[]>({
    queryKey: ["route-stats"],
    queryFn: async () => {
      const res = await apiFetch("/v1/routes/stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: refreshIntervalSec * 1000,
    select: (all) => all?.[routeId] ?? EMPTY,
  });
}
