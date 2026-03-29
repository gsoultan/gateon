import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";

export interface CircuitBreakerEvent {
  target: string;
  state: "CLOSED" | "OPEN" | "HALF-OPEN";
  reason: string;
  timestamp: string;
}

export function useCircuitBreakerEvents() {
  return useQuery<CircuitBreakerEvent[]>({
    queryKey: ["circuit-breaker-events"],
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/circuit-breaker/events");
      if (!res.ok) throw new Error("Failed to fetch circuit breaker events");
      return res.json();
    },
    refetchInterval: 5000, // Refresh every 5s
  });
}
