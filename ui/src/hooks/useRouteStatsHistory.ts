import { useEffect, useRef, useState } from "react";
import { useRouteStats } from "./useGateon";

const MAX_POINTS = 12;

export function useRouteStatsHistory(routeId: string) {
  const { data: stats } = useRouteStats(routeId);
  const [history, setHistory] = useState<number[]>([]);
  const prevRef = useRef<number>(0);

  useEffect(() => {
    if (!stats || stats.length === 0) return;
    const total = stats.reduce((s, t) => s + t.request_count, 0);
    const delta = total - prevRef.current;
    prevRef.current = total;
    setHistory((h) => {
      const next = [...h, delta >= 0 ? delta : 0].slice(-MAX_POINTS);
      return next.length >= 2 ? next : next;
    });
  }, [stats]);

  return history;
}
