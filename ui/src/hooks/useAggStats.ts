import { useQuery } from "@tanstack/react-query";
import { queryClient } from "../queryClient";
import { apiFetch } from "./api";
import { useApiConfigStore } from "../store/useApiConfigStore";

export type AggStats = {
  totalRequests: number;
  totalBandwidthBytes: number;
  totalErrors: number;
  activeConnections: number;
  openCircuits: number;
  halfOpenCircuits: number;
  healthyTargets: number;
  totalTargets: number;
  cpuUsage: number;
  memoryUsage: number;
};

export function useAggStats() {
  const refreshIntervalSec = useApiConfigStore((s) => s.refreshInterval);
  return useQuery<AggStats>({
    queryKey: ["agg-stats"],
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/agg-stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: refreshIntervalSec * 1000,
  }, queryClient);
}
