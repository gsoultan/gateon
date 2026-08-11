// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/client";
import { useRealTimeStore } from "../store/useRealTimeStore";
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
      const res = await api.listSecurityThreats({ 
        limit, 
        offset, 
        search, 
        category: category === "all" ? "" : category, 
        status: status === "all" ? "" : status 
      });
      return {
        threats: res.threats as any,
        totalCount: res.totalCount,
      };
    },
  });

  useEffect(() => {
    // Only subscribe to SSE for the first page/unfiltered view or generic dashboard view
    if (offset !== 0 || search || (category && category !== "all") || (status && status !== "all")) {
      return;
    }

    const unsubscribe = useRealTimeStore.getState().subscribe("threat", (newThreat: Anomaly) => {
      queryClient.setQueryData<SecurityThreatsResponse>(queryKey, (old) => {
        if (!old) return { threats: [newThreat], totalCount: 1 };
        const exists = old.threats.some((t) => t.id === newThreat.id);
        if (exists) return old;
        return {
          threats: [newThreat, ...old.threats].slice(0, limit),
          totalCount: (old.totalCount || old.threats.length) + 1,
        };
      });
    });

    return unsubscribe;
  }, [limit, queryClient, queryKey, offset, search, category, status]);

  return query;
}

export function useSecurityThreat(id: string | null) {
  return useQuery<Anomaly>({
    queryKey: ["security-threat", id],
    queryFn: async () => {
      const res = await api.getSecurityThreat({ id: id! });
      return res.threat as any;
    },
    enabled: !!id,
  });
}
