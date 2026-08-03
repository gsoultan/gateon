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
        uptimeSeconds: sys.uptimeSeconds ?? (sys as any).uptime_seconds ?? 0,
        cpuUsage: sys.cpuUsagePercent ?? (sys as any).cpu_usage_percent ?? 0,
        memoryUsageMb: (sys.memoryAllocBytes ?? (sys as any).memory_alloc_bytes ?? 0) / (1024 * 1024),
        memoryTotalMb: (sys.memoryTotalGb ?? (sys as any).memory_total_gb ?? 0) * 1024,
        storageUsageGb: sys.storageUsageGb ?? (sys as any).storage_usage_gb ?? 0,
        storageTotalGb: sys.storageTotalGb ?? (sys as any).storage_total_gb ?? 0,
        storageUsagePercent: sys.storageUsagePercent ?? (sys as any).storage_usage_percent ?? 0,
        publicIp: sys.publicIp ?? (sys as any).public_ip ?? '',
        titanEnabled: sys.titanEnabled ?? (sys as any).titan_enabled ?? false,
        neuralSentinelEnabled: sys.neuralSentinelEnabled ?? (sys as any).neural_sentinel_enabled ?? false,
        graphIntelligenceEnabled: sys.graphIntelligenceEnabled ?? (sys as any).graph_intelligence_enabled ?? false,
        predictiveAiEnabled: sys.predictiveAiEnabled ?? (sys as any).predictive_ai_enabled ?? false,
        pqcEnabled: sys.pqcEnabled ?? (sys as any).pqc_enabled ?? false,
        tpmEnabled: sys.tpmEnabled ?? (sys as any).tpm_enabled ?? false,
        resourceGovernorEnabled: sys.resourceGovernorEnabled ?? (sys as any).resource_governor_enabled ?? false,
      } as any; // Cast as any because StatusResponse might missing some fields we added
      
      queryClient.setQueryData(queryKey, newStatus);
    });
  }, [queryClient, subscribe]);

  return query;
}
