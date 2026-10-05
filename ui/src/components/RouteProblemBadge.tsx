// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Badge, Tooltip } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";
import type { RouteProblem } from "../hooks/useRouteProblems";

/** What the route list says about a route that cannot serve as configured. */
export function routeProblemLabel(kind: RouteProblem["kind"]): { label: string; color: string; summary: string } {
  if (kind === "matches_nothing") {
    return { label: "MATCHES NOTHING", color: "orange", summary: "Its rule does not parse, so no request reaches it." };
  }
  return { label: "REFUSES REQUESTS", color: "red", summary: "It answers every request 503 until fixed." };
}

/**
 * The marker on a route that answers 503 or matches nothing (OPS-N4). After an
 * upgrade such a route used to look like every other until a request reached
 * it. The reason is configuration the operator wrote, shown as text.
 */
export function RouteProblemBadge({ problem }: { problem?: RouteProblem }) {
  if (!problem) return null;
  const { label, color, summary } = routeProblemLabel(problem.kind);
  return (
    <Tooltip label={`${summary} ${problem.reason}`} multiline w={320} withArrow>
      <Badge size="xs" color={color} variant="filled" leftSection={<IconAlertTriangle size={10} />} aria-label={`${label}: ${problem.reason}`}>
        {label}
      </Badge>
    </Tooltip>
  );
}
