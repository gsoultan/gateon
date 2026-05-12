import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, getApiUrl } from "./api";
import type { Anomaly } from "../types/gateon";

export interface SecurityThreatsResponse {
  threats: Anomaly[];
}

export function useSecurityThreats(limit = 50) {
  const queryClient = useQueryClient();
  const queryKey = ["security-threats", limit];

  const query = useQuery<SecurityThreatsResponse>({
    queryKey,
    queryFn: async () => {
      const res = await apiFetch(`/v1/diag/security-threats?limit=${limit}`);
      if (!res.ok) {
        throw new Error("Failed to fetch security threats");
      }
      return res.json();
    },
  });

  useEffect(() => {
    const url = getApiUrl(`/v1/diag/security-threats/watch`);
    const eventSource = new EventSource(url, { withCredentials: true });

    eventSource.onmessage = (event) => {
      try {
        const newThreat = JSON.parse(event.data) as Anomaly;
        queryClient.setQueryData<SecurityThreatsResponse>(queryKey, (old) => {
          if (!old) return { threats: [newThreat] };
          const exists = old.threats.some((t) => t.id === newThreat.id);
          if (exists) return old;
          return {
            threats: [newThreat, ...old.threats].slice(0, limit),
          };
        });
      } catch (err) {
        console.error("Failed to parse security threat SSE", err);
      }
    };

    return () => {
      eventSource.close();
    };
  }, [limit, queryClient, queryKey]);

  return query;
}
