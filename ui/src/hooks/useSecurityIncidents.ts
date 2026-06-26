import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface SecurityIncident {
  id: string;
  source_key: string;
  source_ip: string;
  fingerprint?: string;
  first_seen: string;
  last_seen: string;
  severity: string;
  score: number;
  signal_count: number;
  signal_types: string[];
  techniques: MitreTechnique[];
  countries?: string[];
}

export interface SecurityIncidentsResponse {
  incidents: SecurityIncident[];
  total_seen: number;
  retained: number;
  generated_at: string;
}

export function useSecurityIncidents(limit = 100, refetchIntervalMs = 10000) {
  return useQuery<SecurityIncidentsResponse>({
    queryKey: ["security-incidents", limit],
    queryFn: async () => {
      const res = await apiFetch(`/v1/security/incidents?limit=${limit}`);
      if (!res.ok) throw new Error("Failed to fetch security incidents");
      return res.json();
    },
    refetchInterval: refetchIntervalMs,
  });
}
