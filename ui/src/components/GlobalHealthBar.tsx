// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMemo } from "react";
import { Group, Text, Tooltip } from "@mantine/core";
import {
  IconRoute,
  IconServer,
  IconActivity,
  IconPlugConnected,
  IconAlertTriangle,
} from "@tabler/icons-react";
import {
  useGateonStatus,
  usePathStats,
  useAggStats,
  useRequestsPerSecond,
} from "../hooks/useGateon";

// One decimal, as the counts are read at a glance. Kept local: utils/format
// carries date-fns, and this component is in the startup chunk.
const oneDecimal = (n: number) => (Number.isFinite(n) ? n.toFixed(1) : "0");

export function GlobalHealthBar({ wrap = false }: { wrap?: boolean }) {
  const { data: status } = useGateonStatus();
  const { data: pathStats } = usePathStats();
  const { data: aggStats } = useAggStats();
  const reqPerSec = useRequestsPerSecond();

  const reqsLabel = useMemo(() => {
    const totalReqs = pathStats?.reduce((s, p) => s + (p.requestCount ?? 0), 0) ?? 0;
    if (totalReqs >= 1_000_000) return `${oneDecimal(totalReqs / 1_000_000)}M`;
    if (totalReqs >= 1000) return `${oneDecimal(totalReqs / 1000)}K`;
    return String(totalReqs);
  }, [pathStats]);

  const stats = useMemo(() => {
    const s = [
      {
        icon: IconRoute,
        value: status?.routesCount ?? 0,
        label: "Routes",
        color: "var(--mantine-color-brand-6)",
      },
      {
        icon: IconServer,
        value: status?.servicesCount ?? 0,
        label: "Services",
        color: "var(--mantine-color-teal-6)",
      },
      {
        icon: IconActivity,
        value: reqPerSec > 0 ? `${reqPerSec}/s` : reqsLabel,
        label: reqPerSec > 0 ? "Req/s" : "Total Requests",
        color: "var(--mantine-color-orange-6)",
      },
      {
        icon: IconPlugConnected,
        value: aggStats?.activeConnections ?? 0,
        label: "Active Connections",
        color: "var(--mantine-color-blue-6)",
      },
    ];

    if ((aggStats?.openCircuits ?? 0) + (aggStats?.halfOpenCircuits ?? 0) > 0) {
      s.push({
        icon: IconAlertTriangle,
        value: (aggStats?.openCircuits ?? 0) + (aggStats?.halfOpenCircuits ?? 0),
        label: "Circuits OPEN / HALF-OPEN",
        color: "var(--mantine-color-red-6)",
      });
    }
    return s;
  }, [status, reqPerSec, reqsLabel, aggStats]);

  return (
    <Group gap={6} wrap={wrap ? "wrap" : "nowrap"} className="shrink-0">
      {stats.map(({ icon: Icon, value, label, color }) => (
        <Tooltip key={label} label={label} openDelay={500}>
          <Group
            gap={6}
            px={10}
            justify="center"
            wrap="nowrap"
            h={28}
            // The border used to be set as a colour and then overwritten by
            // the `border` shorthand, so every pill had a black outline.
            style={{
              borderRadius: 999,
              backgroundColor: "var(--mantine-color-default)",
              border: "1px solid var(--mantine-color-default-border)",
            }}
          >
            <Icon size={12} color={color} stroke={2.5} />
            <Text size="xs" fw={700} lh={1} className="tabular-nums">
              {value}
            </Text>
          </Group>
        </Tooltip>
      ))}
    </Group>
  );
}
