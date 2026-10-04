// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
  queueSize?: number;
  stats: SiemStats;
}

/** Enabled HTTP routes by the mode of the WAF that inspects each one. */
export interface RouteCoverage {
  total: number;
  enforcing: number;
  detecting: number;
  unprotected: number;
  /** Routes running the upload signature engine (file_security). */
  signatureScanning: number;
  /** Routes carrying a bot_management middleware. */
  botManagement: number;
  /** Routes carrying a ratelimit or inflightreq middleware. */
  rateLimited: number;
}

/** "enforce" blocks, "detect" is audit-only (records and forwards), "off". */
export type WafMode = "enforce" | "detect" | "off";

export interface WafPosture {
  enabled: boolean;
  /** The gateway-wide WAF's effective mode. */
  mode: WafMode;
  routes: RouteCoverage;
  /** What the old auto_update_rules flag does: load rules already on disk. */
  customRulesFromDisk: boolean;
  lastUpdated?: string;
}

export interface ClamavPosture {
  enabled: boolean;
  installed: boolean;
  lastScan?: string;
  lastResult?: string;
  lastError?: string;
}

/** The upload signature engine as routes run it: only inside file_security. */
export interface SignaturePosture {
  enabled: boolean;
  routes: number;
  ruleCount: number;
}

export interface PostureControl {
  id: string;
  label: string;
  weight: number;
  state: "on" | "partial" | "off";
  /** 0..1, the share of weight earned. */
  credit: number;
  detail: string;
}

/** Computed from configuration only; see ADR 0048. */
export interface PostureScore {
  percent: number;
  controls: PostureControl[];
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
  score: PostureScore;
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
