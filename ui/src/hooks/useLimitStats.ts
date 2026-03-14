import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { useApiConfigStore } from "../store/useApiConfigStore";
import type { LimitStats } from "../types/gateon";

export function useLimitStats() {
  const refreshIntervalSec = useApiConfigStore((s) => s.refreshInterval);
  return useQuery<LimitStats>({
    queryKey: ["limit-stats"],
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/limit-stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: refreshIntervalSec * 1000,
  });
}
