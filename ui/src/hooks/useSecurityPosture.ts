import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";

export interface SiemStats {
  enqueued: number;
  shipped: number;
  dropped: number;
  errors: number;
}

export interface SiemStatus {
  enabled: boolean;
  endpoint?: string;
  format?: string;
  transport?: string;
  queue_size?: number;
  stats: SiemStats;
}

export interface WafPosture {
  enabled: boolean;
  auto_update: boolean;
  last_updated?: string;
}

export interface ClamavPosture {
  enabled: boolean;
  installed: boolean;
  last_scan?: string;
  last_result?: string;
  last_error?: string;
}

export interface SignaturePosture {
  enabled: boolean;
  rule_count: number;
}

export interface FimStatus {
  enabled: boolean;
  watched_paths?: string[];
  baseline_files?: number;
  last_scan?: string;
  total_drift?: number;
}

export interface SecurityPosture {
  version: string;
  generated_at: string;
  waf: WafPosture;
  clamav: ClamavPosture;
  signatures: SignaturePosture;
  siem: SiemStatus;
  fim?: FimStatus;
}

export function useSecurityPosture(refetchIntervalMs = 15000) {
  return useQuery<SecurityPosture>({
    queryKey: ["security-posture"],
    queryFn: async () => {
      const res = await apiFetch("/v1/security/posture");
      if (!res.ok) throw new Error("Failed to fetch security posture");
      return res.json();
    },
    refetchInterval: refetchIntervalMs,
  });
}
