import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, getApiUrl } from "./api";
import type { StatusResponse } from "../types/gateon";

export function useGateonStatus() {
  const queryClient = useQueryClient();
  const queryKey = ["status"];

  const query = useQuery<StatusResponse>({
    queryKey,
    queryFn: async () => {
      const res = await apiFetch("/v1/status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });

  useEffect(() => {
    const url = getApiUrl("/v1/status/watch");
    const eventSource = new EventSource(url, { withCredentials: true });

    eventSource.onmessage = (event) => {
      try {
        const newStatus = JSON.parse(event.data) as StatusResponse;
        queryClient.setQueryData(queryKey, newStatus);
      } catch (err) {
        console.error("Failed to parse status SSE", err);
      }
    };

    return () => {
      eventSource.close();
    };
  }, [queryClient, queryKey]);

  return query;
}
