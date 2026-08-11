// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useRef, useState, useCallback } from "react";

export function useWorker<TRequest, TResponse>(workerFactory: () => Worker) {
  const workerRef = useRef<Worker | null>(null);
  const pendingTasks = useRef<Map<string, { resolve: (val: TResponse) => void; reject: (err: any) => void }>>(new Map());

  useEffect(() => {
    workerRef.current = workerFactory();
    
    workerRef.current.onmessage = (e) => {
      const { id, result, error } = e.data;
      const task = pendingTasks.current.get(id);
      if (task) {
        if (error) task.reject(error);
        else task.resolve(result);
        pendingTasks.current.delete(id);
      }
    };

    return () => {
      workerRef.current?.terminate();
    };
  }, [workerFactory]);

  const runTask = useCallback((type: string, payload: TRequest): Promise<TResponse> => {
    return new Promise((resolve, reject) => {
      if (!workerRef.current) {
        reject(new Error("Worker not initialized"));
        return;
      }
      const id = Math.random().toString(36).substring(2, 11);
      pendingTasks.current.set(id, { resolve, reject });
      workerRef.current.postMessage({ type, payload, id });
    });
  }, []);

  return { runTask };
}
