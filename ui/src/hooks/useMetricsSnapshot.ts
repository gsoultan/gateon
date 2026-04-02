import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { useApiConfigStore } from "../store/useApiConfigStore";
import type { MetricsSnapshot } from "../types/metrics";

export function useMetricsSnapshot() {
  const refreshIntervalSec = useApiConfigStore((s) => s.refreshInterval);
  return useQuery<MetricsSnapshot>({
    queryKey: ["metrics-snapshot"],
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/metrics");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: refreshIntervalSec * 1000,
  });
}
