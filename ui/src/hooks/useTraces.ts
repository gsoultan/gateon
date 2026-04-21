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
  source_ip: string;
}

export function useTraces(limit: number = 100) {
  return useQuery({
    queryKey: ["traces", limit],
    queryFn: async () => {
      const response = await apiFetch(`/v1/traces?limit=${limit}`);
      const data = await response.json();
      return (data.traces || []) as Trace[];
    },
    refetchInterval: 5000,
  });
}
