import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, getApiUrl, buildQueryString } from "./api";
import type { AuditLog } from "../types/gateon";

export interface AuditLogsResponse {
  logs: AuditLog[];
  total_count?: number;
  page?: number;
  page_size?: number;
}

export interface AuditLogsParams {
  page?: number;
  page_size?: number;
  search?: string;
}

export function useAuditLogs(params: AuditLogsParams = {}) {
  const { page = 0, page_size = 50, search = "" } = params;
  const queryClient = useQueryClient();
  const queryKey = ["audit-logs", page, page_size, search];

  const query = useQuery<AuditLogsResponse>({
    queryKey,
    queryFn: async () => {
      const qs = buildQueryString({ page, page_size, search });
      const res = await apiFetch(`/v1/audit/logs${qs}`);
      if (!res.ok) {
        throw new Error("Failed to fetch audit logs");
      }
      return res.json();
    },
  });

  useEffect(() => {
    // Live updates only make sense on the first page of an unfiltered view —
    // prepending to a later page or a filtered list would corrupt pagination.
    if (page !== 0 || search) return;

    const url = getApiUrl(`/v1/audit/logs/watch`);
    const eventSource = new EventSource(url, { withCredentials: true });

    eventSource.onmessage = (event) => {
      try {
        const newEntry = JSON.parse(event.data) as AuditLog;
        queryClient.setQueryData<AuditLogsResponse>(queryKey, (old) => {
          if (!old) return { logs: [newEntry], total_count: 1, page, page_size };
          const exists = old.logs.some((l) => l.id === newEntry.id);
          if (exists) return old;
          return {
            ...old,
            logs: [newEntry, ...old.logs].slice(0, page_size),
            total_count: (old.total_count ?? old.logs.length) + 1,
          };
        });
      } catch (err) {
        console.error("Failed to parse audit log SSE", err);
      }
    };

    return () => {
      eventSource.close();
    };
  }, [page, page_size, search, queryClient, queryKey]);

  return query;
}
