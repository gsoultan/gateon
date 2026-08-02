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
  autoUpdate: boolean;
  lastUpdated?: string;
}

export interface ClamavPosture {
  enabled: boolean;
  installed: boolean;
  lastScan?: string;
  lastResult?: string;
  lastError?: string;
}

export interface SignaturePosture {
  enabled: boolean;
  ruleCount: number;
}

export interface FimStatus {
  enabled: boolean;
  watchedPaths?: string[];
  baselineFiles?: number;
  lastScan?: string;
  totalDrift?: number;
}

export interface EbpfPosture {
  enabled: boolean;
  attached: boolean;
  interface?: string;
  attachMode?: string;
  shunnedIps: number;
}

export interface SecurityPosture {
  version: string;
  generatedAt: string;
  waf: WafPosture;
  clamav: ClamavPosture;
  signatures: SignaturePosture;
  siem: SiemStatus;
  fim?: FimStatus;
  ebpf: EbpfPosture;
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
