// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Button, Card, Group, Stack, Text } from "@mantine/core";
import { useRouteStats } from "../hooks/useGateon";
import { useRouteStatsHistory } from "../hooks/useRouteStatsHistory";
import { safeToFixed } from "../utils/format";
import { Sparkline } from "./Sparkline";

export interface RouteStatsProps {
  routeId: string;
}

export function RouteStats({ routeId }: RouteStatsProps) {
  const { data: stats, isLoading, refetch } = useRouteStats(routeId);
  const reqHistory = useRouteStatsHistory(routeId);

  if (!stats || stats.length === 0) return null;

  return (
    <Stack gap="xs" mt="sm">
      <Group justify="space-between">
        <Group gap="xs">
          <Text size="sm" fw={700}>
            Target Metrics
          </Text>
          {reqHistory.length >= 2 && (
            <Sparkline data={reqHistory} width={60} height={20} color="var(--mantine-color-indigo-5)" />
          )}
        </Group>
        <Button size="compact-xs" variant="subtle" loading={isLoading} onClick={() => refetch()}>
          Refresh
        </Button>
      </Group>
      {stats.map(s => (
        <Card key={s.url} withBorder padding="xs">
          <Group justify="space-between" wrap="nowrap">
            <Stack gap={0} style={{ flex: 1, minWidth: 0 }}>
              <Text size="xs" truncate fw={500}>{s.url}</Text>
              <Group gap="sm">
                <Text size="xs" c={s.alive ? 'green' : 'red'}>{s.alive ? 'HEALTHY' : 'UNHEALTHY'}</Text>
                <Text size="xs">Reqs: {s.requestCount}</Text>
                <Text size="xs">Errs: {s.errorCount}</Text>
                <Text size="xs">Active: {s.activeConn}</Text>
                <Text size="xs">Avg Lat: {safeToFixed(s.avgLatencyMs ?? (s as any).avg_latency_ms, 2)}ms</Text>
                <Text size="xs" fw={700} c={s.alive ? 'green' : 'orange'}>
                  Circuit: {(s as any).circuitState ?? (s.alive ? 'CLOSED' : 'OPEN')}
                </Text>
              </Group>
              {s.statusCodes && Object.keys(s.statusCodes).length > 0 && (
                <Group gap="xs" mt={4}>
                  {Object.entries(s.statusCodes).map(([code, count]) => (
                    <Text key={code} size="xs" c="dimmed">{code}: {count}</Text>
                  ))}
                </Group>
              )}
            </Stack>
          </Group>
        </Card>
      ))}
    </Stack>
  )
}
