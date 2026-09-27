// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { api } from "../services/client";
import { retryUnlessAnswered } from "./useTraceHistory";

export interface Trace {
  id: string;
  operationName: string;
  serviceName: string;
  durationMs: number;
  timestamp: string;
  status: string;
  path: string;
  requestUri?: string;
  sourceIp: string;
  userAgent?: string;
  method?: string;
  referer?: string;
  ja4?: string;
  ja4h?: string;
  requestHeaders?: Record<string, string>;
  requestBody?: string;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
  recommendation?: string;
  reputation?: number;
  entrypointDelayMs?: number;
  routeDelayMs?: number;
  middlewareDelayMs?: number;
  serviceDelayMs?: number;
  /** The gateway that recorded it, in period-query results. */
  node?: string;
}

// Both through the generated client: the REST routes only wrapped these RPCs,
// and telemetry clamps the limit for either. The REST call also read an error
// body as an empty list, so the page's error state could never show; a failed
// call now rejects, and reaches it.

// fetchTraces lists recent traces without their headers and bodies.
export async function fetchTraces(limit: number): Promise<Trace[]> {
  const res = await api.listTraces({ limit, summary: true });
  return res.traces;
}

// fetchTrace loads one trace in full; timestamp locates it without a scan.
export async function fetchTrace(id: string, timestamp: string): Promise<Trace | null> {
  const res = await api.getTrace({ id, timestamp });
  return res.trace ?? null;
}

// active is false while the traces are not on screen -- another tab of the
// page is -- so the five-second poll stops rather than running for nothing.
export function useTraces(limit: number = 100, active: boolean = true) {
  return useQuery({
    queryKey: ["traces", limit],
    queryFn: () => fetchTraces(limit),
    refetchInterval: active ? 5000 : false,
    enabled: active,
  });
}

// useTrace loads one trace. Not with the dashboard's keepPreviousData: opening
// a second trace would show the first one's source, headers and bodies under
// the second one's name until it loaded.
export function useTrace(id?: string, timestamp?: string) {
  return useQuery({
    queryKey: ["trace", id, timestamp],
    queryFn: () => (id && timestamp ? fetchTrace(id, timestamp) : null),
    enabled: !!id && !!timestamp,
    placeholderData: undefined,
    retry: retryUnlessAnswered,
  });
}
