// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useCallback, useEffect, useRef } from "react";
import { WorkerClient } from "./workerClient";

// useWorker owns one worker for the lifetime of the component. The factory must
// be stable (defined at module scope), or the worker is recreated each render.
export function useWorker<TRequest, TResponse>(workerFactory: () => Worker) {
  const clientRef = useRef<WorkerClient<TResponse> | null>(null);

  useEffect(() => {
    const client = new WorkerClient<TResponse>(workerFactory());
    clientRef.current = client;
    return () => {
      clientRef.current = null;
      client.terminate();
    };
  }, [workerFactory]);

  const runTask = useCallback((type: string, payload: TRequest): Promise<TResponse> => {
    const client = clientRef.current;
    if (!client) return Promise.reject(new Error("Worker not initialized"));
    return client.run(type, payload);
  }, []);

  return { runTask };
}
