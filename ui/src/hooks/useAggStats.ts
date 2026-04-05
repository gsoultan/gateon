import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { useApiConfigStore } from "../store/useApiConfigStore";

export type AggStats = {
  total_requests: number;
  total_bandwidth_bytes: number;
  total_errors: number;
  active_connections: number;
  open_circuits: number;
  half_open_circuits: number;
  healthy_targets: number;
  total_targets: number;
  cpu_usage: number;
  memory_usage: number;
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
  });
}
