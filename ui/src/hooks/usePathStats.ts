import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { useApiConfigStore } from "../store/useApiConfigStore";
import type { PathStats } from "../types/gateon";

export function usePathStats() {
  const refreshIntervalSec = useApiConfigStore((s) => s.refreshInterval);
  return useQuery<PathStats[]>({
    queryKey: ["path-stats"],
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/path-stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: refreshIntervalSec * 1000,
  });
}
