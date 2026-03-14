import { useEffect, useRef, useState } from "react";
import { useAggStats } from "./useAggStats";

const HISTORY_LEN = 24;

/** Rolling request-rate history (delta of total_requests per poll). */
export function useAggStatsHistory() {
  const { data, ...rest } = useAggStats();
  const [requestRateHistory, setRequestRateHistory] = useState<number[]>([]);
  const prevTotal = useRef<number | null>(null);

  useEffect(() => {
    if (data == null) return;
    const total = data.total_requests ?? 0;
    if (prevTotal.current !== null) {
      const delta = Math.max(0, total - prevTotal.current);
      setRequestRateHistory((h) => [...h.slice(-(HISTORY_LEN - 1)), delta]);
    }
    prevTotal.current = total;
  }, [data]);

  return { data, requestRateHistory, ...rest };
}
