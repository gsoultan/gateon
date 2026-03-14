import { useQuery } from "@tanstack/react-query";
import { useApiConfigStore } from "../store/useApiConfigStore";
import { apiFetch } from "./api";
import type { StatusResponse } from "../types/gateon";

export function useGateonStatus() {
  const refreshIntervalSec = useApiConfigStore((s) => s.refreshInterval);
  return useQuery<StatusResponse>({
    queryKey: ["status"],
    queryFn: async () => {
      const res = await apiFetch("/v1/status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: refreshIntervalSec * 1000,
  });
}
