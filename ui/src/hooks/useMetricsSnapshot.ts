import { useEffect, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, getApiUrl } from "./api";
import type { MetricsSnapshot } from "../types/metrics";

export function useMetricsSnapshot(limit?: number, page?: number) {
  const queryClient = useQueryClient();
  const queryKey = useMemo(() => ["metrics-snapshot", limit, page], [limit, page]);

  const query = useQuery<MetricsSnapshot>({
    queryKey,
    queryFn: async () => {
      let url = "/v1/diag/metrics";
      const params = new URLSearchParams();
      if (limit) params.append("limit", limit.toString());
      if (page) params.append("page", page.toString());
      if (params.toString()) url += `?${params.toString()}`;

      const res = await apiFetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });

  useEffect(() => {
    // Only use SSE for the default view (page 1) to avoid confusing behavior during pagination
    if (page && page > 1) return;

    const url = getApiUrl("/v1/diag/metrics/watch");
    const eventSource = new EventSource(url, { withCredentials: true });

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
