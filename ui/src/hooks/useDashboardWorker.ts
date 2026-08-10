// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useCallback, useMemo } from "react";
import { useWorker } from "./useWorker";

// Vite handles ?worker suffix
const dashboardWorkerFactory = () => new Worker(
  new URL("../workers/dashboard.worker.ts", import.meta.url),
  { type: "module" }
);

export function useDashboardWorker() {
  const { runTask } = useWorker(dashboardWorkerFactory);

  const buildDashboardData = useCallback(
    (payload: any) => runTask("buildDashboardData", payload),
    [runTask]
  );

  return { buildDashboardData };
}
