import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, getApiUrl } from "./api";
import type { MetricsSnapshot } from "../types/metrics";

export function useMetricsSnapshot() {
  const queryClient = useQueryClient();
  const queryKey = ["metrics-snapshot"];

  const query = useQuery<MetricsSnapshot>({
    queryKey,
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/metrics");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });

  useEffect(() => {
    const url = getApiUrl("/v1/diag/metrics/watch");
    const eventSource = new EventSource(url);

    eventSource.onmessage = (event) => {
      try {
        const newData = JSON.parse(event.data) as MetricsSnapshot;
        queryClient.setQueryData(queryKey, newData);
      } catch (err) {
        console.error("Failed to parse metrics snapshot SSE", err);
      }
    };

    return () => {
      eventSource.close();
    };
  }, [queryClient, queryKey]);

  return query;
}
