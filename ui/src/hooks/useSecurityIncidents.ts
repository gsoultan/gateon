// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface SecurityIncident {
  id: string;
  sourceKey: string;
  sourceIp: string;
  sourceIps?: string[];
  fingerprint?: string;
  firstSeen: string;
  lastSeen: string;
  severity: string;
  score: number;
  signalCount: number;
  signalTypes: string[];
  techniques: MitreTechnique[];
  countries?: string[];
}

export interface SecurityIncidentsResponse {
  incidents: SecurityIncident[];
  totalSeen: number;
  retained: number;
  generatedAt: string;
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
