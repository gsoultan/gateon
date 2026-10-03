// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { HealthCheckType } from "../types/gateon";
import { honoursWeights } from "./canaryPolicy";

// What the service form shows has to be what the gateway does (ADR 0043,
// ADR 0047). These are the rules it shows them by, kept apart from the form so
// they can be tested.

function isL4(backendType: string | undefined): boolean {
  return backendType === "tcp" || backendType === "udp";
}

// showsWeights says whether target weights mean anything for this service.
// The gateway refuses differing weights where they would be ignored, so the
// form does not offer them there.
export function showsWeights(policy: string | undefined, backendType: string | undefined): boolean {
  return !isL4(backendType) && honoursWeights(policy);
}

// weightsToSave is what the form sends for each target's weight: what the
// operator set where weights are honoured, and 1 everywhere else, which is how
// those balancers treat every target anyway.
export function weightsToSave<T extends { weight: number }>(
  targets: T[],
  policy: string | undefined,
  backendType: string | undefined,
): T[] {
  if (showsWeights(policy, backendType)) return targets;
  return targets.map((t) => ({ ...t, weight: 1 }));
}

// healthCheckProblem mirrors the gateway's save-time refusal, so the form can
// say so before the request.
export function healthCheckProblem(type: HealthCheckType | undefined, path: string | undefined): string | null {
  if (type === HealthCheckType.HEALTH_CHECK_TYPE_HTTP && !(path ?? "").trim()) {
    return "An HTTP health check needs a path (for example /healthz). Choose Auto or TCP to check by connecting.";
  }
  return null;
}

// healthCheckBehaviour says, in one sentence, what the gateway will check.
export function healthCheckBehaviour(
  type: HealthCheckType | undefined,
  path: string | undefined,
  backendType: string | undefined,
): string {
  const p = (path ?? "").trim();
  const grpc = type === HealthCheckType.HEALTH_CHECK_TYPE_GRPC ||
    (type !== HealthCheckType.HEALTH_CHECK_TYPE_HTTP && type !== HealthCheckType.HEALTH_CHECK_TYPE_TCP &&
      type !== HealthCheckType.HEALTH_CHECK_TYPE_CUSTOM && backendType === "grpc");
  if (grpc) {
    return p ? `Each target's gRPC health service is asked about ${p}.` : "Each target's gRPC health service is asked about the server.";
  }
  if (type === HealthCheckType.HEALTH_CHECK_TYPE_TCP || !p) {
    return "Each target is checked by opening a TCP connection to it.";
  }
  return `Each target is sent GET ${p}; a 5xx or no answer counts as a failure.`;
}
