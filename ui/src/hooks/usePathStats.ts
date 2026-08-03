import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { useRealTimeStore } from "../store/useRealTimeStore";
import type { PathStats } from "../types/gateon";

const queryKey = ["path-stats"];

export function usePathStats() {
  const queryClient = useQueryClient();
  const subscribe = useRealTimeStore(state => state.subscribe);

  const query = useQuery<PathStats[]>({
    queryKey,
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/path-stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });

  useEffect(() => {
    return subscribe('metrics', (snap) => {
      if (snap.pathMetrics) {
        queryClient.setQueryData(queryKey, snap.pathMetrics);
      }
    });
  }, [queryClient, subscribe]);

  return query;
}
