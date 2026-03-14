import { Suspense, lazy } from 'react'
import { Card, Loader, Stack, Text, Grid, Title, Group } from '@mantine/core'
import { useGateonStatus } from '../hooks/useGateon'

const StatusCard = lazy(() => import("../components/StatusCard"));
const ServiceOverviewCards = lazy(
  () =>
    import("../components/ServiceOverviewCards").then((m) => ({
      default: m.ServiceOverviewCards,
    }))
);
const RouteList = lazy(() => import("../components/RouteList"));
const PathStatsTable = lazy(() => import('../components/PathStatsTable').then(m => ({ default: m.PathStatsTable })))
const LiveLogs = lazy(() => import('../components/LiveLogs'))
const LimitRejectionsCard = lazy(() => import('../components/LimitRejectionsCard').then(m => ({ default: m.LimitRejectionsCard })))

const STATUS_FALLBACK = <Text>Loading status...</Text>;
const ROUTE_LIST_FALLBACK = <Card withBorder h={200}><Loader /></Card>;
const LIVE_LOGS_FALLBACK = <Card withBorder h={300}><Loader /></Card>;

export default function Dashboard() {
  const { data: status } = useGateonStatus()

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="center">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>System Overview</Title>
          <Text c="dimmed" size="sm" fw={500}>Real-time status and metrics of your Gateon instances.</Text>
        </div>
      </Group>

      <Suspense fallback={STATUS_FALLBACK}>
        <StatusCard />
      </Suspense>

      <Suspense fallback={<Card withBorder h={120}><Loader /></Card>}>
        <ServiceOverviewCards />
      </Suspense>

      <Grid gutter="md">
        <Grid.Col span={{ base: 12, md: 8 }}>
          <Stack gap="md">
            <Suspense fallback={ROUTE_LIST_FALLBACK}>
              <RouteList limit={5} />
            </Suspense>
            <Suspense fallback={<Card withBorder h={200}><Loader /></Card>}>
              <PathStatsTable />
            </Suspense>
          </Stack>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <Stack gap="md">
            <Suspense fallback={<Card withBorder h={120}><Loader /></Card>}>
              <LimitRejectionsCard />
            </Suspense>
            <Suspense fallback={LIVE_LOGS_FALLBACK}>
              <LiveLogs height={500} />
            </Suspense>
          </Stack>
        </Grid.Col>
      </Grid>
    </Stack>
  )
}
