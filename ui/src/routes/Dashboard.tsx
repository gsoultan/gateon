import { Suspense, lazy, useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
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
  Select,
  TextInput,
  Badge,
  Table,
} from "@mantine/core";
import { BarChart, LineChart } from "@mantine/charts";
import {
  IconActivity,
  IconAlertCircle,
  IconChartBar,
  IconTransferIn,
  IconWorld,
  IconAddressBook,
  IconDeviceDesktop,
} from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import {
  useAggStatsHistory,
  useGateonStatus,
  useMetricsSnapshot,
  usePathStats,
  useRequestsPerSecond,
  useRoutes,
  useServices,
} from "../hooks/useGateon";
import type { RequestDeltaSample } from "../hooks/useGateon";
import { Sparkline } from "../components/Sparkline";
import type { PathStats, Route, Service } from "../types/gateon";
import { formatBytes, formatCompact } from "../utils/format";
import { TrafficMetricsGrid } from "../components/Dashboard/TrafficMetricsGrid";
import { DomainStatsTable } from "../components/Dashboard/DomainStatsTable";
import { DistributionCard } from "../components/Dashboard/DistributionCard";
import { CountryTrafficTable } from "../components/Dashboard/CountryTrafficTable";
import { QuickActions } from "../components/Dashboard/QuickActions";
import {
  TOP_GROUP_LIMIT,
  HOUR_MS,
  DAY_MS,
  DEFAULT_PORT_LABEL,
  OTHER_GROUP_LABEL,
  UNMATCHED_SERVICE_LABEL,
  UNMATCHED_ROUTER_LABEL,
  resolveTrafficRangeBounds,
  filterTrafficSamplesByRange,
  buildHourlyTrafficData,
  toTopGroupedData,
  buildTrafficByPathData,
  formatHourLabel,
  buildRouteMatchers,
  resolveRouterLabel,
  resolveServiceLabel,
  buildTrafficByServiceData,
  buildHourlyBandwidthData,
  buildBandwidthSummaries,
  buildBandwidthByRouterData,
  buildBandwidthByServiceData,
  buildTrafficByPortData,
} from "../utils/dashboard";
import type {
  TrafficFilterMode,
  TrafficRangePreset,
  TrafficRangeBounds,
  HourlyBandwidthDatum,
  BandwidthSummaryDatum,
  RouteMatcher,
} from "../utils/dashboard";

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

const TRAFFIC_FILTER_MODE_OPTIONS = [
  { value: "all", label: "All data" },
  { value: "date", label: "Specific date" },
  { value: "range", label: "Date range" },
];

const TRAFFIC_RANGE_PRESET_OPTIONS = [
  { value: "last24h", label: "Last 24 hours" },
  { value: "last7d", label: "Last 7 days" },
  { value: "last30d", label: "Last 30 days" },
  { value: "custom", label: "Custom range" },
];

type BandwidthDeltaSample = {
  ts: number;
  totalBytes: number;
  routerBytes: Record<string, number>;
  serviceBytes: Record<string, number>;
};


export default function Dashboard() {
  const { data: status } = useGateonStatus();
  const {
    data: agg,
    requestRateHistory,
    requestDeltaHistory,
    isLoading: aggLoading,
  } = useAggStatsHistory();
  const { data: pathStats, isLoading: pathStatsLoading } = usePathStats();
  const { data: routesResponse, isLoading: routesLoading } = useRoutes();
  const { data: servicesResponse, isLoading: servicesLoading } = useServices();
  const reqPerSec = useRequestsPerSecond();
  const { data: metricsSnap } = useMetricsSnapshot();
  const [trafficFilterMode, setTrafficFilterMode] = useState<TrafficFilterMode>("range");
  const [trafficDate, setTrafficDate] = useState("");
  const [trafficRangePreset, setTrafficRangePreset] = useState<TrafficRangePreset>("last24h");
  const [trafficRangeStart, setTrafficRangeStart] = useState("");
  const [trafficRangeEnd, setTrafficRangeEnd] = useState("");
  const previousPathStatsRef = useRef<Map<string, number> | null>(null);
  const [bandwidthDeltaHistory, setBandwidthDeltaHistory] = useState<BandwidthDeltaSample[]>([]);

  const trafficRangeBounds = useMemo(
    () =>
      resolveTrafficRangeBounds(
        trafficFilterMode,
        trafficDate,
        trafficRangePreset,
        trafficRangeStart,
        trafficRangeEnd,
      ),
    [
      trafficDate,
      trafficFilterMode,
      trafficRangeEnd,
      trafficRangePreset,
      trafficRangeStart,
      requestDeltaHistory,
    ],
  );

  useEffect(() => {
    if (!pathStats || pathStats.length === 0) {
      return;
    }

    const routeMatchers = buildRouteMatchers(routesResponse?.routes ?? []);
    const serviceNameById = new Map(
      (servicesResponse?.services ?? []).map((service) => [service.id, service.name]),
    );

    const currentTotals = new Map<string, number>();
    for (const stat of pathStats) {
      currentTotals.set(`${stat.host}:${stat.path}`, stat.bytes_total);
    }

    const previousTotals = previousPathStatsRef.current;
    previousPathStatsRef.current = currentTotals;

    if (previousTotals === null) {
      return;
    }

    let totalBytes = 0;
    const routerBytes = new Map<string, number>();
    const serviceBytes = new Map<string, number>();

    for (const stat of pathStats) {
      const key = `${stat.host}:${stat.path}`;
      const prevBytes = previousTotals.get(key) ?? 0;
      const deltaBytes = Math.max(0, stat.bytes_total - prevBytes);
      if (deltaBytes <= 0) {
        continue;
      }

      totalBytes += deltaBytes;
      const routerLabel = resolveRouterLabel(stat, routeMatchers);
      const serviceLabel = resolveServiceLabel(stat, routeMatchers, serviceNameById);
      routerBytes.set(routerLabel, (routerBytes.get(routerLabel) ?? 0) + deltaBytes);
      serviceBytes.set(serviceLabel, (serviceBytes.get(serviceLabel) ?? 0) + deltaBytes);
    }

    if (totalBytes <= 0) {
      return;
    }

    const sample: BandwidthDeltaSample = {
      ts: Date.now(),
      totalBytes,
      routerBytes: Object.fromEntries(routerBytes),
      serviceBytes: Object.fromEntries(serviceBytes),
    };
    setBandwidthDeltaHistory((prev) => [...prev, sample].slice(-100000));
  }, [pathStats, routesResponse?.routes, servicesResponse?.services]);

  const filteredTrafficSamples = useMemo(
    () => filterTrafficSamplesByRange(requestDeltaHistory, trafficRangeBounds),
    [requestDeltaHistory, trafficRangeBounds],
  );

  const filteredBandwidthSamples = useMemo(
    () => filterTrafficSamplesByRange(bandwidthDeltaHistory, trafficRangeBounds),
    [bandwidthDeltaHistory, trafficRangeBounds],
  );

  const hourlyTrafficData = useMemo(
    () => buildHourlyTrafficData(filteredTrafficSamples, trafficRangeBounds),
    [filteredTrafficSamples, trafficRangeBounds],
  );

  const hourlyBandwidthData = useMemo(
    () => buildHourlyBandwidthData(filteredBandwidthSamples, trafficRangeBounds),
    [filteredBandwidthSamples, trafficRangeBounds],
  );

  const bandwidthSummaries = useMemo(
    () => buildBandwidthSummaries(hourlyBandwidthData),
    [hourlyBandwidthData],
  );

  const trafficWindowLabel = useMemo(() => {
    if (trafficRangeBounds === null) {
      return `All captured samples (${requestDeltaHistory.length})`;
    }
    const startLabel = new Date(trafficRangeBounds.startTs).toLocaleDateString();
    const endLabel = new Date(Math.max(trafficRangeBounds.startTs, trafficRangeBounds.endTs - 1))
      .toLocaleDateString();
    return `${startLabel} → ${endLabel}`;
  }, [requestDeltaHistory.length, trafficRangeBounds]);

  const groupedTrafficLoading = pathStatsLoading || routesLoading || servicesLoading;
  const groupedBandwidthLoading = groupedTrafficLoading;

  const trafficByServiceData = buildTrafficByServiceData(
    pathStats ?? [],
    routesResponse?.routes ?? [],
    servicesResponse?.services ?? [],
  );
  const bandwidthByServiceData = buildBandwidthByServiceData(
    pathStats ?? [],
    routesResponse?.routes ?? [],
    servicesResponse?.services ?? [],
  );
  const bandwidthByRouterData = buildBandwidthByRouterData(pathStats ?? [], routesResponse?.routes ?? []);
  const trafficByPortData = buildTrafficByPortData(pathStats ?? []);
  const trafficByPathData = buildTrafficByPathData(pathStats ?? []);

  const ipDistributionData = useMemo(() => {
    if (!metricsSnap?.ip_metrics) return [];
    return metricsSnap.ip_metrics
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 5)
      .map((m) => ({ group: m.ip, requests: m.requests }));
  }, [metricsSnap]);

  const countryDistributionData = useMemo(() => {
    if (!metricsSnap?.country_metrics) return [];
    return metricsSnap.country_metrics
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 5)
      .map((m) => ({ group: m.country, name: m.country_name, requests: m.requests }));
  }, [metricsSnap]);

  const protocolDistributionData = useMemo(() => {
    if (!metricsSnap?.protocol_metrics) return [];
    return metricsSnap.protocol_metrics.map((m) => ({
      group: m.label.toUpperCase(),
      requests: m.value,
    }));
  }, [metricsSnap]);

  const domainDistributionData = useMemo(() => {
    if (!metricsSnap?.domain_metrics) return [];
    return metricsSnap.domain_metrics
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 5)
      .map((m) => ({ group: m.domain, requests: m.requests }));
  }, [metricsSnap]);

  const domainBandwidthData = useMemo(() => {
    if (!metricsSnap?.domain_metrics) return [];
    return metricsSnap.domain_metrics
      .sort((a, b) => b.bytes_in + b.bytes_out - (a.bytes_in + a.bytes_out))
      .slice(0, 5)
      .map((m) => ({ group: m.domain, requests: m.bytes_in + m.bytes_out }));
  }, [metricsSnap]);

  const groupedTrafficCharts = [
    {
      title: "By Service",
      description: "Requests mapped to service routes",
      color: "teal.6",
      data: trafficByServiceData,
    },
    {
      title: "By Port",
      description: "Requests grouped by host port",
      color: "orange.6",
      data: trafficByPortData,
    },
    {
      title: "By Path",
      description: "Most requested route paths",
      color: "grape.6",
      data: trafficByPathData,
    },
    {
      title: "By Domain",
      description: "Requests by target domain",
      color: "cyan.6",
      data: domainDistributionData,
    },
  ];

  const groupedBandwidthCharts = [
    {
      title: "By Service",
      description: "Bandwidth mapped to service routes",
      color: "teal.6",
      data: bandwidthByServiceData,
    },
    {
      title: "By Router",
      description: "Bandwidth mapped to router rules",
      color: "orange.6",
      data: bandwidthByRouterData,
    },
    {
      title: "By Domain",
      description: "Bandwidth by target domain",
      color: "cyan.6",
      data: domainBandwidthData,
    },
  ];

  const ipBandwidthData = useMemo(() => {
    if (!metricsSnap?.ip_metrics) return [];
    return metricsSnap.ip_metrics
      .sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out))
      .slice(0, 5)
      .map((m) => ({ group: m.ip, requests: m.bytes_in + m.bytes_out }));
  }, [metricsSnap]);

  const countryBandwidthData = useMemo(() => {
    if (!metricsSnap?.country_metrics) return [];
    return metricsSnap.country_metrics
      .sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out))
      .slice(0, 5)
      .map((m) => ({ group: m.country, name: m.country_name, requests: m.bytes_in + m.bytes_out }));
  }, [metricsSnap]);

  const totalRequests = agg?.total_requests ?? 0;
  const totalBandwidthBytes = agg?.total_bandwidth_bytes ?? 0;
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
      label: "Total Bandwidth",
      value: formatBytes(totalBandwidthBytes),
      icon: IconTransferIn,
      color: "blue" as const,
      description: "Cumulative ingress + egress bytes",
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

  const resetTrafficFilters = () => {
    setTrafficFilterMode("all");
    setTrafficDate("");
    setTrafficRangePreset("last24h");
    setTrafficRangeStart("");
    setTrafficRangeEnd("");
  };

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

      <SimpleGrid cols={{ base: 1, md: 3 }} spacing="xl">
        <Box style={{ gridColumn: "span 2" }}>
          <Suspense fallback={STATUS_FALLBACK}>
            <StatusCard />
          </Suspense>
        </Box>
        <Box>
          <QuickActions />
        </Box>
      </SimpleGrid>

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
          <SimpleGrid cols={{ base: 1, sm: 2, md: 3, lg: 5 }} spacing="md">
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} h={100} radius="md" />
            ))}
          </SimpleGrid>
        ) : (
          <TrafficMetricsGrid metrics={trafficMetrics} />
        )}
      </Card>

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
        <Group justify="space-between" mb="md" wrap="wrap">
          <Title order={5} fw={700} c="dimmed" style={{ letterSpacing: 1 }}>
            TRAFFIC BREAKDOWN
          </Title>
          <Text size="xs" c="dimmed" fw={600}>
            Top {TOP_GROUP_LIMIT - 1} groups + other bucket
          </Text>
        </Group>

        <SimpleGrid cols={{ base: 1, md: 3 }} spacing="md">
          {groupedTrafficCharts.map((chart) => (
            <Paper key={chart.title} p="md" radius="md" withBorder>
              <Text size="sm" fw={700}>
                {chart.title}
              </Text>
              <Text size="xs" c="dimmed" mb="sm">
                {chart.description}
              </Text>

              {groupedTrafficLoading && chart.data.length === 0 ? (
                <Skeleton h={180} radius="md" />
              ) : chart.data.length > 0 ? (
                <BarChart
                  h={180}
                  minWidth={0}
                  data={chart.data}
                  dataKey="group"
                  withLegend={false}
                  gridAxis="y"
                  tickLine="none"
                  series={[{ name: "requests", color: chart.color }]}
                  valueFormatter={(value) => `${Math.round(value)} req`}
                />
              ) : (
                <Text size="sm" c="dimmed">
                  Waiting for traffic samples.
                </Text>
              )}
            </Paper>
          ))}
        </SimpleGrid>
      </Card>

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
        <Group justify="space-between" mb="md" wrap="wrap">
          <Title order={5} fw={700} c="dimmed" style={{ letterSpacing: 1 }}>
            BANDWIDTH BREAKDOWN
          </Title>
          <Text size="xs" c="dimmed" fw={600}>
            Top {TOP_GROUP_LIMIT - 1} groups + other bucket
          </Text>
        </Group>

        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
          {groupedBandwidthCharts.map((chart) => (
            <Paper key={chart.title} p="md" radius="md" withBorder>
              <Text size="sm" fw={700}>
                {chart.title}
              </Text>
              <Text size="xs" c="dimmed" mb="sm">
                {chart.description}
              </Text>

              {groupedBandwidthLoading && chart.data.length === 0 ? (
                <Skeleton h={180} radius="md" />
              ) : chart.data.length > 0 ? (
                <BarChart
                  h={180}
                  minWidth={0}
                  data={chart.data}
                  dataKey="group"
                  withLegend={false}
                  gridAxis="y"
                  tickLine="none"
                  series={[{ name: "requests", color: chart.color }]}
                  valueFormatter={(value) => formatBytes(value)}
                />
              ) : (
                <Text size="sm" c="dimmed">
                  Waiting for bandwidth samples.
                </Text>
              )}
            </Paper>
          ))}
        </SimpleGrid>
      </Card>

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
        <Group justify="space-between" mb="md" wrap="wrap">
          <Title order={5} fw={700} c="dimmed" style={{ letterSpacing: 1 }}>
            IP & GEOGRAPHIC DISTRIBUTION
          </Title>
          <Text size="xs" c="dimmed" fw={600}>
            Real-time client metrics
          </Text>
        </Group>

        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
          <CountryTrafficTable
            title="Top Countries"
            subtitle="Request volume by country"
            data={countryDistributionData}
            totalRequests={totalRequests}
          />

          <DistributionCard
            title="Top Client IPs"
            subtitle="Requests by client IP address"
            data={ipDistributionData}
            color="cyan.6"
          />

          <DistributionCard
            title="Top Domains"
            subtitle="Requests by target domain"
            data={domainDistributionData}
            color="teal.6"
          />

          <DistributionCard
            title="Protocols"
            subtitle="HTTP/1.1 vs HTTP/2 vs HTTP/3"
            data={protocolDistributionData}
            color="indigo.6"
          />
        </SimpleGrid>

        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md" mt="md">
          <CountryTrafficTable
            title="Bandwidth by Country"
            subtitle="Total bytes by country"
            data={countryBandwidthData}
            totalRequests={totalBandwidthBytes}
            isBandwidth={true}
          />

          <DistributionCard
            title="Bandwidth by Domain"
            subtitle="Total bytes by target domain"
            data={domainBandwidthData}
            color="cyan.6"
            valueFormatter={(value) => formatBytes(value)}
          />

          <DistributionCard
            title="Bandwidth by IP"
            subtitle="Total bytes by client IP"
            data={ipBandwidthData}
            color="cyan.6"
            valueFormatter={(value) => formatBytes(value)}
          />
        </SimpleGrid>

        <Box mt="md">
          <DomainStatsTable metrics={metricsSnap?.hourly_domain_metrics ?? []} />
        </Box>
      </Card>

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
        <Group justify="space-between" mb="md" wrap="wrap">
          <Title order={5} fw={700} c="dimmed" style={{ letterSpacing: 1 }}>
            TRAFFIC PER HOUR
          </Title>
          <Text size="xs" c="dimmed" fw={600}>
            {trafficWindowLabel}
          </Text>
        </Group>

        <Group mb="md" gap="sm" align="end" wrap="wrap">
          <Select
            label="Filter"
            size="xs"
            w={150}
            data={TRAFFIC_FILTER_MODE_OPTIONS}
            value={trafficFilterMode}
            onChange={(value) => setTrafficFilterMode((value as TrafficFilterMode) ?? "all")}
          />

          {trafficFilterMode === "date" && (
            <TextInput
              label="Date"
              type="date"
              size="xs"
              w={170}
              value={trafficDate}
              onChange={(event) => setTrafficDate(event.currentTarget.value)}
            />
          )}

          {trafficFilterMode === "range" && (
            <>
              <Select
                label="Range"
                size="xs"
                w={180}
                data={TRAFFIC_RANGE_PRESET_OPTIONS}
                value={trafficRangePreset}
                onChange={(value) =>
                  setTrafficRangePreset((value as TrafficRangePreset) ?? "last24h")
                }
              />
              {trafficRangePreset === "custom" && (
                <>
                  <TextInput
                    label="Start"
                    type="date"
                    size="xs"
                    w={170}
                    value={trafficRangeStart}
                    onChange={(event) => setTrafficRangeStart(event.currentTarget.value)}
                  />
                  <TextInput
                    label="End"
                    type="date"
                    size="xs"
                    w={170}
                    value={trafficRangeEnd}
                    onChange={(event) => setTrafficRangeEnd(event.currentTarget.value)}
                  />
                </>
              )}
            </>
          )}

          <Button size="xs" variant="subtle" onClick={resetTrafficFilters}>
            Reset
          </Button>
        </Group>

        {aggLoading && requestRateHistory.length === 0 ? (
          <Skeleton h={240} radius="md" />
        ) : hourlyTrafficData.length > 0 ? (
          <BarChart
            h={240}
            minWidth={0}
            data={hourlyTrafficData}
            dataKey="hour"
            withLegend={false}
            gridAxis="xy"
            tickLine="none"
            series={[{ name: "requests", color: "indigo.6" }]}
            valueFormatter={(value) => `${Math.round(value)} req`}
          />
        ) : (
          <Paper p="md" radius="md" withBorder>
            <Text size="sm" c="dimmed">
              No traffic data for the selected date filter.
            </Text>
          </Paper>
        )}

        <Stack mt="lg" gap="md">
          <Group justify="space-between" wrap="wrap">
            <Text size="sm" fw={700}>
              BANDWIDTH PER HOUR
            </Text>
            <Text size="xs" c="dimmed">
              Total, router, and service hourly bandwidth
            </Text>
          </Group>

          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
            {bandwidthSummaries.map((summary) => (
              <Paper key={summary.label} p="sm" radius="md" withBorder>
                <Text size="xs" fw={700} c="dimmed" style={{ letterSpacing: 0.5 }}>
                  {summary.label}
                </Text>
                <Text size="xs" c="dimmed">
                  Max: <Text span fw={600}>{formatBytes(summary.max)}</Text>
                </Text>
                <Text size="xs" c="dimmed">
                  Min: <Text span fw={600}>{formatBytes(summary.min)}</Text>
                </Text>
                <Text size="xs" c="dimmed">
                  Avg: <Text span fw={600}>{formatBytes(summary.avg)}</Text>
                </Text>
              </Paper>
            ))}
          </SimpleGrid>

          {hourlyBandwidthData.length > 0 ? (
            <LineChart
              h={260}
              minWidth={0}
              data={hourlyBandwidthData}
              dataKey="hour"
              withLegend
              gridAxis="xy"
              tickLine="none"
              series={[
                { name: "totalBytes", color: "indigo.6", label: "Total" },
                { name: "routerBytes", color: "orange.6", label: "Router" },
                { name: "serviceBytes", color: "teal.6", label: "Service" },
              ]}
              valueFormatter={(value) => formatBytes(value)}
            />
          ) : (
            <Paper p="md" radius="md" withBorder>
              <Text size="sm" c="dimmed">
                No bandwidth data for the selected date filter.
              </Text>
            </Paper>
          )}
        </Stack>
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
