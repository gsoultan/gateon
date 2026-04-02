import { Suspense, lazy } from "react";
import {
  Card,
  Loader,
  Stack,
  Text,
  Grid,
  Title,
  Group,
  SimpleGrid,
  Paper,
  Skeleton,
  Box,
} from "@mantine/core";
import {
  IconActivity,
  IconAlertCircle,
  IconChartBar,
  IconTransferIn,
} from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import { useGateonStatus, useAggStatsHistory, useRequestsPerSecond } from "../hooks/useGateon";
import { Sparkline } from "../components/Sparkline";

const StatusCard = lazy(() => import("../components/StatusCard"));
const ServiceOverviewCards = lazy(() =>
  import("../components/ServiceOverviewCards").then((m) => ({
    default: m.ServiceOverviewCards,
  }))
);
const RouteList = lazy(() => import("../components/RouteList"));
const LimitRejectionsCard = lazy(() =>
  import("../components/LimitRejectionsCard").then((m) => ({
    default: m.LimitRejectionsCard,
  }))
);

const STATUS_FALLBACK = <Text>Loading status...</Text>;
const ROUTE_LIST_FALLBACK = (
  <Card withBorder h={200}>
    <Loader />
  </Card>
);

function formatCompact(num: number): string {
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toLocaleString();
}

export default function Dashboard() {
  const { data: status } = useGateonStatus();
  const { data: agg, requestRateHistory, isLoading: aggLoading } = useAggStatsHistory();
  const reqPerSec = useRequestsPerSecond();

  const totalRequests = agg?.total_requests ?? 0;
  const totalErrors = agg?.total_errors ?? 0;
  const errorRate =
    totalRequests > 0 ? ((totalErrors / totalRequests) * 100).toFixed(2) : "0.00";

  const trafficMetrics = [
    {
      label: "Total Requests",
      value: formatCompact(totalRequests),
      icon: IconTransferIn,
      color: "indigo" as const,
      description: "Cumulative requests since startup",
    },
    {
      label: "Total Errors",
      value: formatCompact(totalErrors),
      icon: IconAlertCircle,
      color: totalErrors > 0 ? ("red" as const) : ("gray" as const),
      description: "Failed or error responses",
    },
    {
      label: "Error Rate",
      value: `${errorRate}%`,
      icon: IconChartBar,
      color:
        parseFloat(errorRate) === 0
          ? ("green" as const)
          : parseFloat(errorRate) < 5
            ? ("yellow" as const)
            : ("red" as const),
      description: "Errors / total requests",
    },
    {
      label: "Requests/sec",
      value: reqPerSec > 0 ? reqPerSec.toFixed(1) : "—",
      icon: IconActivity,
      color: "teal" as const,
      description: "Current throughput (rolling)",
    },
  ];

  return (
    <Stack gap="xl">
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -0.5 }}>
            System Overview
          </Title>
          <Text c="dimmed" size="sm" fw={500} mt={4}>
            Real-time status and operational metrics
          </Text>
        </div>
      </Group>

      <Suspense fallback={STATUS_FALLBACK}>
        <StatusCard />
      </Suspense>

      {/* Traffic Metrics Row */}
      <Card
        shadow="sm"
        padding="lg"
        radius="lg"
        withBorder
        style={{
          background: "var(--mantine-color-body)",
          borderColor: "var(--mantine-color-default-border)",
        }}
      >
        <Group justify="space-between" mb="md">
          <Title order={5} fw={700} c="dimmed" style={{ letterSpacing: 1 }}>
            TRAFFIC METRICS
          </Title>
          {requestRateHistory.length >= 2 && (
            <Box style={{ opacity: 0.8 }}>
              <Sparkline
                data={requestRateHistory}
                width={120}
                height={28}
                color="var(--mantine-color-indigo-5)"
              />
            </Box>
          )}
        </Group>
        {aggLoading ? (
          <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
            {[1, 2, 3, 4].map((i) => (
              <Skeleton key={i} h={80} radius="md" />
            ))}
          </SimpleGrid>
        ) : (
          <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
            {trafficMetrics.map((m) => (
              <Paper
                key={m.label}
                p="md"
                radius="md"
                withBorder
                style={{
                  borderLeftWidth: 4,
                  borderLeftColor: `var(--mantine-color-${m.color}-6)`,
                  transition: "box-shadow 150ms ease, transform 100ms ease",
                }}
                className="dashboard-metric-card"
              >
                <Group gap="sm" wrap="nowrap">
                  <Box
                    p={8}
                    style={{
                      borderRadius: "var(--mantine-radius-md)",
                      backgroundColor: `var(--mantine-color-${m.color}-1)`,
                    }}
                  >
                    <m.icon
                      size={20}
                      color={`var(--mantine-color-${m.color}-6)`}
                    />
                  </Box>
                  <div style={{ minWidth: 0 }}>
                    <Text
                      size="xs"
                      c="dimmed"
                      fw={700}
                      style={{ textTransform: "uppercase", letterSpacing: 0.5 }}
                    >
                      {m.label}
                    </Text>
                    <Text size="xl" fw={800} c={`${m.color}.6`}>
                      {m.value}
                    </Text>
                    <Text size="xs" c="dimmed" lineClamp={1} title={m.description}>
                      {m.description}
                    </Text>
                  </div>
                </Group>
              </Paper>
            ))}
          </SimpleGrid>
        )}
      </Card>

      <Suspense fallback={<Card withBorder h={120}><Loader /></Card>}>
        <ServiceOverviewCards />
      </Suspense>

      <Grid gutter="lg">
        <Grid.Col span={{ base: 12, md: 8 }}>
          <Suspense fallback={ROUTE_LIST_FALLBACK}>
            <RouteList readOnly />
          </Suspense>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <Stack gap="md">
            <Suspense fallback={<Card withBorder h={120}><Loader /></Card>}>
              <LimitRejectionsCard />
            </Suspense>
            <Card
              shadow="xs"
              padding="lg"
              radius="lg"
              withBorder
              component={Link}
              to="/metrics"
              style={{
                textDecoration: "none",
                transition: "background-color 150ms ease",
              }}
            >
              <Group justify="space-between">
                <div>
                  <Text size="sm" fw={600}>
                    Metrics Dashboard
                  </Text>
                  <Text size="xs" c="dimmed">
                    Golden signals, latency percentiles, and middleware metrics
                  </Text>
                </div>
                <Text size="xs" c="teal" fw={600}>
                  Open →
                </Text>
              </Group>
            </Card>
            <Card
              shadow="xs"
              padding="lg"
              radius="lg"
              withBorder
              component={Link}
              to="/routes"
              style={{
                textDecoration: "none",
                transition: "background-color 150ms ease",
              }}
            >
              <Group justify="space-between">
                <div>
                  <Text size="sm" fw={600}>
                    Manage Routes
                  </Text>
                  <Text size="xs" c="dimmed">
                    View and edit all {status?.routes_count ?? 0} routes
                  </Text>
                </div>
                <Text size="xs" c="indigo" fw={600}>
                  View all →
                </Text>
              </Group>
            </Card>
          </Stack>
        </Grid.Col>
      </Grid>
    </Stack>
  );
}
