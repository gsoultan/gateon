import { Button, Card, Group, Stack, Text } from '@mantine/core'
import { useRouteStats } from '../hooks/useGateon'

export interface RouteStatsProps {
  routeId: string
}

export function RouteStats({ routeId }: RouteStatsProps) {
  const { data: stats, isLoading, refetch } = useRouteStats(routeId)

  if (!stats || stats.length === 0) return null

  return (
    <Stack gap="xs" mt="sm">
      <Group justify="space-between">
        <Text size="sm" fw={700}>Target Metrics (auto-refreshing):</Text>
        <Button size="compact-xs" variant="subtle" loading={isLoading} onClick={() => refetch()}>Refresh</Button>
      </Group>
      {stats.map(s => (
        <Card key={s.url} withBorder padding="xs">
          <Group justify="space-between" wrap="nowrap">
            <Stack gap={0} style={{ flex: 1, minWidth: 0 }}>
              <Text size="xs" truncate fw={500}>{s.url}</Text>
              <Group gap="sm">
                <Text size="xs" c={s.alive ? 'green' : 'red'}>{s.alive ? 'HEALTHY' : 'UNHEALTHY'}</Text>
                <Text size="xs">Reqs: {s.request_count}</Text>
                <Text size="xs">Errs: {s.error_count}</Text>
                <Text size="xs">Active: {s.active_conn}</Text>
                <Text size="xs">Avg Lat: {s.avg_latency_ms.toFixed(2)}ms</Text>
                <Text size="xs" fw={700} c={s.circuit_state === 'CLOSED' ? 'green' : 'orange'}>Circuit: {s.circuit_state}</Text>
              </Group>
              <Group gap="xs" mt={4}>
                {Object.entries(s.status_codes).map(([code, count]) => (
                  <Text key={code} size="xs" c="dimmed">{code}: {count}</Text>
                ))}
              </Group>
            </Stack>
          </Group>
        </Card>
      ))}
    </Stack>
  )
}
