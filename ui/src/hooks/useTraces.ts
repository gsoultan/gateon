import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";

export interface Trace {
  id: string;
  operationName: string;
  serviceName: string;
  durationMs: number;
  timestamp: string;
  status: string;
  path: string;
  requestUri?: string;
  sourceIp: string;
  userAgent?: string;
  method?: string;
  referer?: string;
  ja4?: string;
  ja4h?: string;
  requestHeaders?: Record<string, string>;
  requestBody?: string;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
  recommendation?: string;
  reputation?: number;
  entrypointDelayMs?: number;
  routeDelayMs?: number;
  middlewareDelayMs?: number;
  serviceDelayMs?: number;
}

export function useTraces(limit: number = 100) {
  return useQuery({
    queryKey: ["traces", limit],
    queryFn: async () => {
      const response = await apiFetch(`/v1/traces?limit=${limit}&summary=true`);
      const data = await response.json();
      return (data.traces || []) as Trace[];
    },
    refetchInterval: 5000,
  });
}

export function useTrace(id?: string, timestamp?: string) {
  return useQuery({
    queryKey: ["trace", id, timestamp],
    queryFn: async () => {
      if (!id || !timestamp) return null;
      const response = await apiFetch(`/v1/traces/detail?id=${id}&timestamp=${encodeURIComponent(timestamp)}`);
      const data = await response.json();
      return data.trace as Trace;
    },
    enabled: !!id && !!timestamp,
  });
}
