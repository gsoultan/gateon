import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, getApiUrl } from "./api";
import type { Anomaly } from "../types/gateon";

export interface SecurityThreatsResponse {
  threats: Anomaly[];
  totalCount: number;
}

export interface SecurityThreatsParams {
  limit?: number;
  offset?: number;
  search?: string;
  category?: string;
  status?: string;
}

export function useSecurityThreats(params: SecurityThreatsParams | number = 50) {
  const queryClient = useQueryClient();
  const p: SecurityThreatsParams = typeof params === "number" ? { limit: params } : params;
  const { limit = 50, offset = 0, search = "", category = "", status = "" } = p;
  
  const queryKey = ["security-threats", limit, offset, search, category, status];

  const query = useQuery<SecurityThreatsResponse>({
    queryKey,
    queryFn: async () => {
      const qs = new URLSearchParams();
      qs.set("limit", limit.toString());
      qs.set("offset", offset.toString());
      if (search) qs.set("search", search);
      if (category && category !== "all") qs.set("category", category);
      if (status && status !== "all") qs.set("status", status);

      const res = await apiFetch(`/v1/diag/security-threats?${qs.toString()}`);
      if (!res.ok) {
        throw new Error("Failed to fetch security threats");
      }
      return res.json();
    },
  });

  useEffect(() => {
    // Only subscribe to SSE for the first page/unfiltered view or generic dashboard view
    // to avoid complex cache reconciliation for now.
    if (offset !== 0 || search || (category && category !== "all") || (status && status !== "all")) {
      return;
    }

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
            totalCount: (old.totalCount || old.threats.length) + 1,
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

export function useSecurityThreat(id: string | null) {
  return useQuery<Anomaly>({
    queryKey: ["security-threat", id],
    queryFn: async () => {
      const res = await apiFetch(`/v1/diag/security-threats/${id}`);
      if (!res.ok) {
        throw new Error("Failed to fetch security threat details");
      }
      const data = await res.json();
      return data.threat;
    },
    enabled: !!id,
  });
}
