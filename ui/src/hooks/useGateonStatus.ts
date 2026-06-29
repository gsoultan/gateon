import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { queryClient } from "../queryClient";
import { apiFetch, getApiUrl } from "./api";
import type { StatusResponse } from "../types/gateon";

const queryKey = ["status"];

export function useGateonStatus() {
  const query = useQuery<StatusResponse>({
    queryKey,
    queryFn: async () => {
      const res = await apiFetch("/v1/status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  }, queryClient);

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
  }, []); // Only connect on mount

  return query;
}
