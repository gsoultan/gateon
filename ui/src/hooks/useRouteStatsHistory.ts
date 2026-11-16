// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useRef, useState } from "react";
import { useRouteStats } from "./useRouteStats";
import { nextRouteHistory } from "./routeStatsHistory";

export function useRouteStatsHistory(routeId: string) {
  const { data: stats } = useRouteStats(routeId);
  const [history, setHistory] = useState<number[]>([]);
  const prevRef = useRef<number | null>(null);

  useEffect(() => {
    if (!stats || stats.length === 0) return;
    const total = stats.reduce((s, t) => s + t.requestCount, 0);
    const previous = prevRef.current;
    prevRef.current = total;
    setHistory((h) => nextRouteHistory(h, previous, total));
  }, [stats]);

  return history;
}
