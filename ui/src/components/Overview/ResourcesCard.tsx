// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Group, Progress, Stack, Text, Title } from "@mantine/core";
import { useAggStats } from "../../hooks/useAggStats";
import { useEntryPoints } from "../../hooks/useGateon";
import { useGateonStatus } from "../../hooks/useGateonStatus";
import { RESOURCE_RED_PERCENT } from "./attention";

/** Where a bar turns amber; red is RESOURCE_RED_PERCENT, shared with the attention list. */
export const RESOURCE_AMBER_PERCENT = 80;

export function resourceColor(percent: number | undefined): string {
  if (percent === undefined) return "gray";
  if (percent >= RESOURCE_RED_PERCENT) return "red";
  if (percent >= RESOURCE_AMBER_PERCENT) return "yellow";
  return "teal";
}

interface GaugeProps {
  label: string;
  percent: number | undefined;
  detail: string;
}

function Gauge({ label, percent, detail }: GaugeProps) {
  return (
    <Stack gap={4}>
      <Group justify="space-between" wrap="nowrap">
        <Text size="sm" fw={500}>
          {label}
        </Text>
        <Text size="sm" fw={600} style={{ fontVariantNumeric: "tabular-nums" }}>
          {percent === undefined ? "–" : `${Math.round(percent)}%`}
        </Text>
      </Group>
      <Progress value={percent ?? 0} color={resourceColor(percent)} size="sm" radius="xl" aria-label={`${label} ${percent === undefined ? "unknown" : `${Math.round(percent)} percent`}`} />
      <Text size="xs" c="dimmed">
        {detail}
      </Text>
    </Stack>
  );
}

const gb = (v: number | undefined) => (v === undefined ? "?" : v >= 10 ? `${Math.round(v)} GB` : `${v.toFixed(1)} GB`);

/**
 * What the gateway is using against what it has: CPU against its cores,
 * memory and disk against their totals, and open connections against the sum
 * of the listeners' caps. The same bar turns amber at 80 and red at 90; a red
 * row is also a row in Needs attention.
 */
export function ResourcesCard() {
  const { data: status } = useGateonStatus();
  const { data: agg } = useAggStats();
  const { data: listeners } = useEntryPoints({ page: 0, pageSize: 200 });

  const cap = (listeners?.entryPoints ?? []).reduce((sum, ep) => sum + (ep.maxConnections ?? 0), 0);
  const connections = agg?.activeConnections;
  const connectionPercent = cap > 0 && connections !== undefined ? (connections / cap) * 100 : undefined;

  return (
    <Card withBorder radius="md" padding="lg" h="100%">
      <Stack gap="md">
        <Title order={4}>Resources</Title>
        <Gauge label="CPU" percent={status?.cpuUsage} detail={status ? `${status.cpuCores ?? "?"} cores` : "Waiting for the gateway"} />
        <Gauge label="Memory" percent={status?.memoryUsagePercent} detail={status ? `of ${gb(status.memoryTotalGb)}` : "Waiting for the gateway"} />
        <Gauge
          label="Disk"
          percent={status?.storageUsagePercent}
          detail={status ? `${gb(status.storageUsageGb)} of ${gb(status.storageTotalGb)}` : "Waiting for the gateway"}
        />
        <Gauge
          label="Open connections"
          percent={connectionPercent}
          detail={
            connections === undefined
              ? "Waiting for stats"
              : cap > 0
                ? `${connections.toLocaleString()} of ${cap.toLocaleString()} across every listener`
                : `${connections.toLocaleString()} open; no listener sets a cap`
          }
        />
      </Stack>
    </Card>
  );
}
