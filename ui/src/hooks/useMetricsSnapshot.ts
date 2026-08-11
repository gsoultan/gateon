// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { MetricsSnapshot } from "../types/metrics";
import { useRealTimeStore } from "../store/useRealTimeStore";

export function useMetricsSnapshot(limit?: number, page?: number) {
  const queryClient = useQueryClient();
  const queryKey = useMemo(() => ["metrics-snapshot", limit, page], [limit, page]);
  const subscribe = useRealTimeStore(state => state.subscribe);

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
    // Only use SSE for the default view to avoid confusing behavior during pagination
    if (page && page > 1) return;

    return subscribe('metrics', (newData) => {
      queryClient.setQueryData(queryKey, newData);
    });
  }, [queryClient, queryKey, subscribe, page]);

  return query;
}
