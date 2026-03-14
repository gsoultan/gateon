import { useEffect, useRef, useState } from "react";
import { useLimitStats } from "./useLimitStats";
import type { LimitStats } from "../types/gateon";

const LIMIT_HISTORY_LEN = 24;

function sumLimitStats(stats: LimitStats | undefined): number {
  if (!stats) return 0;
  const r =
    stats.rate_limit_rejected && typeof stats.rate_limit_rejected === "object"
      ? Object.values(stats.rate_limit_rejected).reduce(
          (a, b) => a + Number(b),
          0
        )
      : 0;
  const i =
    stats.inflight_rejected && typeof stats.inflight_rejected === "object"
      ? Object.values(stats.inflight_rejected).reduce(
          (a, b) => a + Number(b),
          0
        )
      : 0;
  const b =
    stats.buffering_rejected && typeof stats.buffering_rejected === "object"
      ? Object.values(stats.buffering_rejected).reduce(
          (a, v) => a + Number(v),
          0
        )
      : 0;
  return r + i + b;
}

/** Rolling delta history of limit rejections per poll interval (e.g. 5s). */
export function useLimitStatsHistory() {
  const { data, ...rest } = useLimitStats();
  const [history, setHistory] = useState<number[]>([]);
  const prevTotal = useRef<number | null>(null);

  useEffect(() => {
    if (data == null) return;
    const total = sumLimitStats(data);
    if (prevTotal.current !== null) {
      const delta = Math.max(0, total - prevTotal.current);
      setHistory((h) => [...h.slice(-(LIMIT_HISTORY_LEN - 1)), delta]);
    }
    prevTotal.current = total;
  }, [data]);

  return { data, history, ...rest };
}
