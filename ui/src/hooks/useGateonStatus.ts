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

      // Only the fields this snapshot actually carries. Everything else that
      // /v1/status returns is merged from the previous value below rather than
      // dropped — see the setQueryData call.
      const fromMetrics = {
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
      };

      // Merge over the cached value instead of replacing it.
      //
      // This used to assign the object above wholesale. MetricsSnapshot.System
      // carries a strict subset of what /v1/status returns, and the query has
      // no refetchInterval, so the first metrics tick after mount permanently
      // erased every field the snapshot does not mention: clamavInstalled,
      // profile, profilePinned, cpuCores, memoryUsagePercent and the routes,
      // services, entryPoints and middlewares counts. They became undefined
      // and stayed that way, because nothing fetched /v1/status again.
      //
      // It read as unrelated dashboard flakiness. The ClamAV card was the
      // clearest case: install succeeds, the backend reports installed, and the
      // card still offers "Install Now" forever, because clamavInstalled had
      // been wiped seconds after page load and only the "Refresh status" button
      // could bring it back.
      //
      // The `as any` cast that used to sit here is what let it through — the
      // object is not a StatusResponse, and saying so out loud would have been
      // a type error. Typing the updater restores that check.
      queryClient.setQueryData<StatusResponse>(queryKey, (prev) =>
        ({ ...(prev ?? {}), ...fromMetrics }) as StatusResponse);
    });
  }, [queryClient, subscribe]);

  return query;
}
