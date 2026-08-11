// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./api";
import { useRealTimeStore } from "../store/useRealTimeStore";

export type AggStats = {
  totalRequests: number;
  totalBandwidthBytes: number;
  totalErrors: number;
  activeConnections: number;
  openCircuits: number;
  halfOpenCircuits: number;
  healthyTargets: number;
  totalTargets: number;
  cpuUsage: number;
  memoryUsage: number;
};

const queryKey = ["agg-stats"];

export function useAggStats() {
  const queryClient = useQueryClient();
  const subscribe = useRealTimeStore(state => state.subscribe);

  const query = useQuery<AggStats>({
    queryKey,
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/agg-stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });

  useEffect(() => {
    return subscribe('metrics', (snap) => {
      const gs = snap.goldenSignals;
      if (!gs) return;

      const newStats: AggStats = {
        totalRequests: gs.requestsTotal,
        totalBandwidthBytes: gs.bytesInTotal + gs.bytesOutTotal,
        totalErrors: gs.errorsTotal,
        activeConnections: gs.activeConnTotal,
        openCircuits: gs.openCircuits,
        halfOpenCircuits: gs.halfOpenCircuits,
        healthyTargets: gs.healthyTargets,
        totalTargets: gs.totalTargets,
        cpuUsage: snap.system?.cpuUsagePercent || 0,
        memoryUsage: snap.system?.memoryUsagePercent || 0,
      };

      queryClient.setQueryData(queryKey, newStats);
    });
  }, [queryClient, subscribe]);

  return query;
}
