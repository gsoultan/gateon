// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { WorkerClient, type WorkerLike } from "./workerClient";

class FakeWorker implements WorkerLike {
  onmessage: ((e: MessageEvent) => void) | null = null;
  onerror: ((e: ErrorEvent) => void) | null = null;
  onmessageerror: ((e: MessageEvent) => void) | null = null;
  posted: { type: string; payload: unknown; id: number }[] = [];
  terminated = false;

  postMessage(message: unknown): void {
    this.posted.push(message as { type: string; payload: unknown; id: number });
  }
  terminate(): void {
    this.terminated = true;
  }
  reply(data: unknown): void {
    this.onmessage?.({ data } as MessageEvent);
  }
  crash(message: string): void {
    this.onerror?.({ message, preventDefault() {} } as unknown as ErrorEvent);
  }
}

// Resolves to "pending" if p has not settled by the time queued microtasks run.
function state(p: Promise<unknown>): Promise<string> {
  return Promise.race([
    p.then(() => "resolved", () => "rejected"),
    Promise.resolve().then(() => Promise.resolve()).then(() => "pending"),
  ]);
}

describe("WorkerClient", () => {
  test("matches each reply to its request", async () => {
    const w = new FakeWorker();
    const c = new WorkerClient<number>(w);
    const a = c.run("a", 1);
    const b = c.run("b", 2);
    w.reply({ id: w.posted[1].id, result: 20 });
    w.reply({ id: w.posted[0].id, result: 10 });
    expect(await a).toBe(10);
    expect(await b).toBe(20);
    expect(c.size).toBe(0);
  });

  test("a task the worker reports as failed rejects with its message", async () => {
    const w = new FakeWorker();
    const c = new WorkerClient<number>(w);
    const p = c.run("x", null);
    w.reply({ id: w.posted[0].id, error: "Unknown worker task type: x" });
    await expect(p).rejects.toThrow("Unknown worker task type: x");
  });

  // Regression: the old hook never listened for "error", so a worker that
  // failed to load left every caller pending forever.
  test("a worker error rejects every request in flight and every later one", async () => {
    const w = new FakeWorker();
    const c = new WorkerClient<number>(w);
    const a = c.run("a", 1);
    const b = c.run("b", 2);
    w.crash("chunk not found");
    expect(await state(a)).toBe("rejected");
    expect(await state(b)).toBe("rejected");
    await expect(a).rejects.toThrow("chunk not found");
    await expect(c.run("c", 3)).rejects.toThrow("chunk not found");
    expect(c.size).toBe(0);
  });

  // Regression: unmounting terminated the worker but left its requests pending.
  test("terminate rejects what is in flight and stops the worker", async () => {
    const w = new FakeWorker();
    const c = new WorkerClient<number>(w);
    const p = c.run("a", 1);
    c.terminate();
    expect(w.terminated).toBe(true);
    expect(await state(p)).toBe("rejected");
    await expect(c.run("b", 2)).rejects.toThrow("terminated");
  });

  test("a reply that cannot be decoded fails the client", async () => {
    const w = new FakeWorker();
    const c = new WorkerClient<number>(w);
    const p = c.run("a", 1);
    w.onmessageerror?.({} as MessageEvent);
    expect(await state(p)).toBe("rejected");
  });

  test("ids are never reused", () => {
    const w = new FakeWorker();
    const c = new WorkerClient<number>(w);
    for (let i = 0; i < 1000; i++) void c.run("a", i);
    expect(new Set(w.posted.map((m) => m.id)).size).toBe(1000);
  });
});
