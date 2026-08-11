// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";

export interface NetworkInterface {
  name: string;
  mac?: string;
  up: boolean;
  running: boolean;
  loopback: boolean;
  addrs: string[];
  recommended: boolean;
}

export interface EbpfStatus {
  enabled: boolean;
  attached: boolean;
  interface?: string;
  loadError?: string;
  attachMode?: string; // "native" or "generic" (SKB fallback)
}

export interface SystemInterfaces {
  interfaces: NetworkInterface[];
  ebpf: EbpfStatus;
}

// useNetworkInterfaces lists the host's network interfaces (so the eBPF
// settings can offer a real NIC picker) and reports current XDP attach status.
export function useNetworkInterfaces(refetchIntervalMs = 10000) {
  return useQuery<SystemInterfaces>({
    queryKey: ["system-interfaces"],
    queryFn: async () => {
      const res = await apiFetch("/v1/system/interfaces");
      if (!res.ok) throw new Error("Failed to fetch network interfaces");
      return res.json();
    },
    refetchInterval: refetchIntervalMs,
  });
}
