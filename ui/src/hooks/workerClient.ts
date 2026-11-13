// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// The part of a Worker the client uses, so a test can hand it a fake.
export interface WorkerLike {
  postMessage(message: unknown): void;
  terminate(): void;
  onmessage: ((e: MessageEvent) => void) | null;
  onerror: ((e: ErrorEvent) => void) | null;
  onmessageerror: ((e: MessageEvent) => void) | null;
}

interface Pending<T> {
  resolve: (value: T) => void;
  reject: (reason: Error) => void;
}

interface Reply<T> {
  id: number;
  result?: T;
  error?: string;
}

// WorkerClient matches each request to a worker with its reply, and settles
// every request it ever accepted.
//
// The hook it replaces listened only for replies. A worker that failed to load
// (a chunk the server could not find, a CSP refusal) or threw outside its own
// try/catch fires "error" instead, and that was never handled, so the caller's
// promise never settled and the dashboard showed its calculating state for
// good. Unmounting terminated the worker the same way, leaving any request in
// flight pending forever. Now an error rejects everything outstanding, marks
// the client broken so later calls fail at once, and terminate does the same.
export class WorkerClient<TResponse> {
  private readonly worker: WorkerLike;
  private readonly pending = new Map<number, Pending<TResponse>>();
  private nextId = 0;
  private failure: Error | null = null;

  constructor(worker: WorkerLike) {
    this.worker = worker;
    worker.onmessage = (e) => this.settle(e.data as Reply<TResponse>);
    worker.onerror = (e) => {
      e.preventDefault?.();
      this.fail(new Error(`Worker failed: ${e.message || "unknown error"}`));
    };
    worker.onmessageerror = () => this.fail(new Error("Worker reply could not be decoded"));
  }

  run(type: string, payload: unknown): Promise<TResponse> {
    if (this.failure) return Promise.reject(this.failure);
    const id = ++this.nextId;
    return new Promise<TResponse>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try {
        this.worker.postMessage({ type, payload, id });
      } catch (err) {
        this.pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  terminate(): void {
    this.worker.terminate();
    this.fail(new Error("Worker terminated"));
  }

  get size(): number {
    return this.pending.size;
  }

  private settle(reply: Reply<TResponse>): void {
    const task = this.pending.get(reply.id);
    if (!task) return;
    this.pending.delete(reply.id);
    if (reply.error !== undefined) task.reject(new Error(reply.error));
    else task.resolve(reply.result as TResponse);
  }

  private fail(err: Error): void {
    this.failure ??= err;
    const tasks = [...this.pending.values()];
    this.pending.clear();
    for (const task of tasks) task.reject(err);
  }
}
