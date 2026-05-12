import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch, getApiUrl } from "./api";
import type { AuditLog } from "../types/gateon";

export interface AuditLogsResponse {
  logs: AuditLog[];
}

export function useAuditLogs(limit = 100) {
  const queryClient = useQueryClient();
  const queryKey = ["audit-logs", limit];

  const query = useQuery<AuditLogsResponse>({
    queryKey,
    queryFn: async () => {
      const res = await apiFetch(`/v1/audit/logs?limit=${limit}`);
      if (!res.ok) {
        throw new Error("Failed to fetch audit logs");
      }
      return res.json();
    },
  });

  useEffect(() => {
    const url = getApiUrl(`/v1/audit/logs/watch`);
    const eventSource = new EventSource(url);

    eventSource.onmessage = (event) => {
      try {
        const newEntry = JSON.parse(event.data) as AuditLog;
        queryClient.setQueryData<AuditLogsResponse>(queryKey, (old) => {
          if (!old) return { logs: [newEntry] };
          const exists = old.logs.some((l) => l.id === newEntry.id);
          if (exists) return old;
          return {
            logs: [newEntry, ...old.logs].slice(0, limit),
          };
        });
      } catch (err) {
        console.error("Failed to parse audit log SSE", err);
      }
    };

    return () => {
      eventSource.close();
    };
  }, [limit, queryClient, queryKey]);

  return query;
}
