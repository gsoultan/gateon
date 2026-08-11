// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useCallback } from "react";
import { useWorker } from "./useWorker";

const sseWorkerFactory = () => new Worker(
  new URL("../workers/sse.worker.ts", import.meta.url),
  { type: "module" }
);

export function useSSEWorker() {
  const { runTask } = useWorker(sseWorkerFactory);

  const parseSSE = useCallback(
    (data: string) => runTask("parseSSE", { data }),
    [runTask]
  );

  return { parseSSE };
}
