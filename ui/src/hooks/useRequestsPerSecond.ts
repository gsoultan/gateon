import { useEffect, useRef, useState } from "react";
import { usePathStats } from "./usePathStats";

/** Rolling req/s from path_stats delta between polls. */
export function useRequestsPerSecond(): number {
  const { data } = usePathStats();
  const [reqPerSec, setReqPerSec] = useState(0);
  const prevRef = useRef<{ total: number; ts: number } | null>(null);

  useEffect(() => {
    if (!data) return;
    const total = data.reduce((s, p) => s + (p.request_count ?? 0), 0);
    const now = Date.now();
    if (prevRef.current) {
      const dt = (now - prevRef.current.ts) / 1000;
      if (dt > 0) {
        const delta = Math.max(0, total - prevRef.current.total);
        setReqPerSec(Math.round((delta / dt) * 10) / 10);
      }
    }
    prevRef.current = { total, ts: now };
  }, [data]);

  return reqPerSec;
}
