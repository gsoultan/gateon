import { useEffect, useRef, useState } from "react";
import { useAggStats } from "./useAggStats";

const HISTORY_LEN = 24;
const HISTORY_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_HISTORY_SAMPLES = 10_000;

export type RequestDeltaSample = {
  ts: number;
  requests: number;
};

/** Rolling request-rate history (delta of total_requests per poll). */
export function useAggStatsHistory() {
  const { data, ...rest } = useAggStats();
  const [requestDeltaHistory, setRequestDeltaHistory] = useState<RequestDeltaSample[]>([]);
  const prevTotal = useRef<number | null>(null);

  useEffect(() => {
    if (data == null) return;
    const total = data.total_requests ?? 0;
    if (prevTotal.current !== null) {
      const delta = Math.max(0, total - prevTotal.current);
      const now = Date.now();
      const retentionCutoff = now - HISTORY_RETENTION_MS;
      setRequestDeltaHistory((history) => {
        const next = [...history, { ts: now, requests: delta }].filter(
          (sample) => sample.ts >= retentionCutoff,
        );
        return next.slice(-MAX_HISTORY_SAMPLES);
      });
    }
    prevTotal.current = total;
  }, [data]);

  const requestRateHistory = requestDeltaHistory
    .slice(-HISTORY_LEN)
    .map((sample) => sample.requests);

  return { data, requestRateHistory, requestDeltaHistory, ...rest };
}
