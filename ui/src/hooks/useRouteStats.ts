import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { useApiConfigStore } from "../store/useApiConfigStore";
import type { TargetStats } from "../types/gateon";

export function useRouteStats(routeId: string) {
  const refreshIntervalSec = useApiConfigStore((s) => s.refreshInterval);
  return useQuery<TargetStats[]>({
    queryKey: ["stats", routeId],
    queryFn: async () => {
      const res = await apiFetch(
        `/v1/routes/${encodeURIComponent(routeId)}/stats`
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: refreshIntervalSec * 1000,
  });
}
