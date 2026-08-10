// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useRef, useState } from "react";
import { usePathStats } from "./usePathStats";

/** Rolling req/s from pathStats delta between polls. */
export function useRequestsPerSecond(): number {
  const { data } = usePathStats();
  const [reqPerSec, setReqPerSec] = useState(0);
  const prevRef = useRef<{ total: number; ts: number } | null>(null);

  useEffect(() => {
    if (!data) return;
    const total = data.reduce((s, p) => s + (p.requestCount ?? 0), 0);
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
