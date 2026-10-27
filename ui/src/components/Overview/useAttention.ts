// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMemo } from "react";
import { useEntryPoints, useMiddlewares, useRoutes, useServices } from "../../hooks/useGateon";
import { useGateonStatus } from "../../hooks/useGateonStatus";
import { useMetricsSnapshot } from "../../hooks/useMetricsSnapshot";
import { useRouteProblems } from "../../hooks/useRouteProblems";
import { useAllRouteStats } from "../../hooks/useRouteStats";
import { useSecurityPosture } from "../../hooks/useSecurityPosture";
import { deriveAttention, type AttentionItem } from "./attention";

/** Middleware types that count as protecting a route. */
const SECURITY_POLICY_TYPES = ["waf", "filesecurity", "ratelimit", "ipallowlist", "ipblocklist"];

/**
 * What needs attention right now. Every query here is one the Overview and the
 * sidebar already run, so a second subscriber costs no request: React Query
 * serves both from one cache entry.
 */
export function useAttention(): { items: AttentionItem[]; isLoading: boolean } {
  const stats = useAllRouteStats();
  const problems = useRouteProblems();
  const posture = useSecurityPosture();
  const metrics = useMetricsSnapshot();
  const status = useGateonStatus();
  const listeners = useEntryPoints({ page: 0, pageSize: 1 });
  const services = useServices({ page: 0, pageSize: 1 });
  const routes = useRoutes({ page: 0, pageSize: 1 });
  const policies = useMiddlewares({ page: 0, pageSize: 100 });

  const items = useMemo(() => {
    const loaded = listeners.data && services.data && routes.data && policies.data;
    const onboarding = loaded
      ? {
          listeners: listeners.data.totalCount ?? 0,
          services: services.data.totalCount ?? 0,
          routes: routes.data.totalCount ?? 0,
          protected: (policies.data.middlewares ?? []).some((m) => SECURITY_POLICY_TYPES.includes(m.type.toLowerCase())),
        }
      : undefined;
    return deriveAttention({
      routeStats: stats.data,
      routeProblems: problems.data,
      posture: posture.data,
      certificates: metrics.data?.tlsCertificates,
      status: status.data,
      onboarding,
    });
  }, [stats.data, problems.data, posture.data, metrics.data, status.data, listeners.data, services.data, routes.data, policies.data]);

  return { items, isLoading: stats.isLoading || problems.isLoading || posture.isLoading };
}
