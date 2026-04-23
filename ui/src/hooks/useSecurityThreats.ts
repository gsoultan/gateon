import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { Anomaly } from "../types/gateon";

export interface SecurityThreatsResponse {
  threats: Anomaly[];
}

export function useSecurityThreats(limit = 50) {
  return useQuery<SecurityThreatsResponse>({
    queryKey: ["security-threats", limit],
    queryFn: async () => {
      const res = await apiFetch(`/v1/diag/security-threats?limit=${limit}`);
      if (!res.ok) {
        throw new Error("Failed to fetch security threats");
      }
      return res.json();
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}
