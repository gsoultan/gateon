import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";

export interface Trace {
  id: string;
  operation_name: string;
  service_name: string;
  duration_ms: number;
  timestamp: string;
  status: string;
  path: string;
  request_uri?: string;
  source_ip: string;
  user_agent?: string;
  method?: string;
  referer?: string;
  ja3?: string;
  ja4?: string;
  request_headers?: Record<string, string>;
  request_body?: string;
  response_headers?: Record<string, string>;
  response_body?: string;
  recommendation?: string;
  reputation?: number;
  entrypoint_delay_ms?: number;
  route_delay_ms?: number;
  middleware_delay_ms?: number;
  service_delay_ms?: number;
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
