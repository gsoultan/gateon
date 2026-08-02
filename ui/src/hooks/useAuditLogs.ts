import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/client";
import { useRealTimeStore } from "../store/useRealTimeStore";
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
  const subscribe = useRealTimeStore((s: any) => s.subscribe);
  const queryKey = ["audit-logs", page, page_size, search];

  const query = useQuery<AuditLogsResponse>({
    queryKey,
    queryFn: async () => {
      const res = await api.listAuditLogs({ page, pageSize: page_size, search });
      return {
        logs: res.logs as any,
        total_count: res.totalCount,
        page: res.page,
        page_size: res.pageSize,
      };
    },
  });

  useEffect(() => {
    // Live updates only make sense on the first page of an unfiltered view —
    // prepending to a later page or a filtered list would corrupt pagination.
    if (page !== 0 || search) return;

    return subscribe("audit", (newEntry: AuditLog) => {
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
    });
  }, [page, page_size, search, queryClient, queryKey, subscribe]);

  return query;
}
