// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMemo } from "react";
import {
  Group,
  Text,
  Tooltip,
  useMantineColorScheme,
} from "@mantine/core";
import {
  IconRoute,
  IconServer,
  IconActivity,
  IconPlugConnected,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { safeToFixed } from "../utils/format";
import {
  useGateonStatus,
  usePathStats,
  useAggStats,
  useRequestsPerSecond,
} from "../hooks/useGateon";

export function GlobalHealthBar() {
  const { data: status } = useGateonStatus();
  const { data: pathStats } = usePathStats();
  const { data: aggStats } = useAggStats();
  const reqPerSec = useRequestsPerSecond();
  const { colorScheme } = useMantineColorScheme();

  const reqsLabel = useMemo(() => {
    const totalReqs = pathStats?.reduce((s, p) => s + (p.requestCount ?? 0), 0) ?? 0;
    if (totalReqs >= 1_000_000) return `${safeToFixed(totalReqs / 1_000_000, 1)}M`;
    if (totalReqs >= 1000) return `${safeToFixed(totalReqs / 1000, 1)}K`;
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

  const themeColors = useMemo(() => {
    const bg = colorScheme === "dark" ? "var(--mantine-color-dark-6)" : "var(--mantine-color-gray-1)";
    const borderColor = colorScheme === "dark" ? "var(--mantine-color-dark-4)" : "var(--mantine-color-gray-3)";
    return { bg, borderColor };
  }, [colorScheme]);

  return (
    <Group gap={6} wrap="nowrap" className="shrink-0">
      {stats.map(({ icon: Icon, value, label, color }) => (
        <Tooltip key={label} label={label} openDelay={500}>
          <Group
            gap={6}
            px={10}
            justify="center"
            wrap="nowrap"
            className="rounded-[20px] h-7"
            style={{ 
              backgroundColor: themeColors.bg,
              borderColor: themeColors.borderColor,
              border: '1px solid',
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
