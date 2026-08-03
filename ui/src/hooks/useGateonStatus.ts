import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { StatusResponse } from "../types/gateon";
import { useRealTimeStore } from "../store/useRealTimeStore";

const queryKey = ["status"];

export function useGateonStatus() {
  const queryClient = useQueryClient();
  const subscribe = useRealTimeStore(state => state.subscribe);

  const query = useQuery<StatusResponse>({
    queryKey,
    queryFn: async () => {
      const res = await apiFetch("/v1/status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });

  useEffect(() => {
    return subscribe('metrics', (metricsSnap) => {
      // Map MetricsSnapshot.System to StatusResponse format
      const sys = metricsSnap.system;
      if (!sys) return;

      const newStatus: StatusResponse = {
        status: sys.status || 'running',
        version: sys.version || '',
        uptimeSeconds: sys.uptimeSeconds,
        cpuUsage: sys.cpuUsagePercent,
        memoryUsageMb: sys.memoryAllocBytes / (1024 * 1024),
        memoryTotalMb: sys.memoryTotalGb * 1024,
        storageUsageGb: sys.storageUsageGb,
        storageTotalGb: sys.storageTotalGb,
        storageUsagePercent: sys.storageUsagePercent,
        publicIp: sys.publicIp,
        titanEnabled: sys.titanEnabled,
        neuralSentinelEnabled: sys.neuralSentinelEnabled,
        graphIntelligenceEnabled: sys.graphIntelligenceEnabled,
        predictiveAiEnabled: sys.predictiveAiEnabled,
        pqcEnabled: sys.pqcEnabled,
        tpmEnabled: sys.tpmEnabled,
        resourceGovernorEnabled: sys.resourceGovernorEnabled,
      } as any; // Cast as any because StatusResponse might missing some fields we added
      
      queryClient.setQueryData(queryKey, newStatus);
    });
  }, [queryClient, subscribe]);

  return query;
}
