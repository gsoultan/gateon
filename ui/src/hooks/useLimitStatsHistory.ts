import { useEffect, useRef, useState } from "react";
import { useLimitStats } from "./useLimitStats";
import type { LimitStats } from "../types/gateon";

const LIMIT_HISTORY_LEN = 24;

function sumLimitStats(stats: LimitStats | undefined): number {
  if (!stats) return 0;
  const s = stats as any;
  const rateObj = (s.rateLimitRejected ?? s.rate_limit_rejected) as Record<string, number> | undefined;
  const inflightObj = (s.inflightRejected ?? s.inflight_rejected) as Record<string, number> | undefined;
  const bufferingObj = (s.bufferingRejected ?? s.buffering_rejected) as Record<string, number> | undefined;

  const r =
    rateObj && typeof rateObj === "object"
      ? Object.values(rateObj).reduce(
          (a: number, b: number) => a + Number(b || 0),
          0
        )
      : 0;
  const i =
    inflightObj && typeof inflightObj === "object"
      ? Object.values(inflightObj).reduce(
          (a: number, b: number) => a + Number(b || 0),
          0
        )
      : 0;
  const b =
    bufferingObj && typeof bufferingObj === "object"
      ? Object.values(bufferingObj).reduce(
          (a: number, v: number) => a + Number(v || 0),
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
