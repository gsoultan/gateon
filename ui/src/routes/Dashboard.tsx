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
} from "@mantine/core";
import { BarChart, LineChart } from "@mantine/charts";
import {
  IconActivity,
  IconAlertCircle,
  IconChartBar,
  IconTransferIn,
} from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import {
  useAggStatsHistory,
  useGateonStatus,
  usePathStats,
  useRequestsPerSecond,
  useRoutes,
  useServices,
} from "../hooks/useGateon";
import type { RequestDeltaSample } from "../hooks/useGateon";
import { Sparkline } from "../components/Sparkline";
import type { PathStats, Route, Service } from "../types/gateon";

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
const TOP_GROUP_LIMIT = 6;
const DEFAULT_PORT_LABEL = "default";
const OTHER_GROUP_LABEL = "Other";
const UNMATCHED_SERVICE_LABEL = "Unmatched";
const UNMATCHED_ROUTER_LABEL = "Unmatched";
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

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

type GroupedTrafficDatum = {
  group: string;
  requests: number;
};

type HourlyTrafficDatum = {
  hourStartTs: number;
  hour: string;
  requests: number;
};

type BandwidthDeltaSample = {
  ts: number;
  totalBytes: number;
  routerBytes: Record<string, number>;
  serviceBytes: Record<string, number>;
};

type HourlyBandwidthDatum = {
  hourStartTs: number;
  hour: string;
  totalBytes: number;
  routerBytes: number;
  serviceBytes: number;
};

type BandwidthSummaryDatum = {
  label: string;
  max: number;
  min: number;
  avg: number;
  color: string;
};

type TrafficFilterMode = "all" | "date" | "range";
type TrafficRangePreset = "last24h" | "last7d" | "last30d" | "custom";

type TrafficRangeBounds = {
  startTs: number;
  endTs: number;
};

function formatCompact(num: number): string {
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toLocaleString();
}

export function formatBytes(num: number): string {
  if (num >= 1024 * 1024 * 1024) return `${(num / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (num >= 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(1)} MB`;
  if (num >= 1024) return `${(num / 1024).toFixed(1)} KB`;
  return `${Math.round(num)} B`;
}

export function buildRequestTrendData(requestRateHistory: number[]) {
  return requestRateHistory.map((requests, index) => ({
    sample: `${index + 1}`,
    requests,
  }));
}

function parseDateInputToStartTs(value: string): number | null {
  if (!value) return null;
  const parsed = new Date(`${value}T00:00:00`);
  const ts = parsed.getTime();
  if (Number.isNaN(ts)) return null;
  return ts;
}

function formatHourLabel(ts: number): string {
  const date = new Date(ts);
  const month = `${date.getMonth() + 1}`.padStart(2, "0");
  const day = `${date.getDate()}`.padStart(2, "0");
  const hour = `${date.getHours()}`.padStart(2, "0");
  return `${month}/${day} ${hour}:00`;
}

export function resolveTrafficRangeBounds(
  mode: TrafficFilterMode,
  dateValue: string,
  rangePreset: TrafficRangePreset,
  customRangeStart: string,
  customRangeEnd: string,
  nowTs = Date.now(),
): TrafficRangeBounds | null {
  if (mode === "all") {
    return null;
  }

  if (mode === "date") {
    const startTs = parseDateInputToStartTs(dateValue);
    if (startTs === null) return null;
    return { startTs, endTs: startTs + DAY_MS };
  }

  if (rangePreset !== "custom") {
    const durationMs =
      rangePreset === "last24h" ? DAY_MS : rangePreset === "last7d" ? 7 * DAY_MS : 30 * DAY_MS;
    return {
      startTs: nowTs - durationMs,
      endTs: nowTs,
    };
  }

  const customStartTs = parseDateInputToStartTs(customRangeStart);
  const customEndTs = parseDateInputToStartTs(customRangeEnd);

  if (customStartTs === null && customEndTs === null) {
    return null;
  }

  const startTs = customStartTs ?? 0;
  const endTs = customEndTs !== null ? customEndTs + DAY_MS : nowTs;

  if (endTs <= startTs) {
    return null;
  }

  return { startTs, endTs };
}

export function filterTrafficSamplesByRange(
  samples: RequestDeltaSample[],
  range: TrafficRangeBounds | null,
): RequestDeltaSample[] {
  if (range === null) return samples;
  return samples.filter((sample) => sample.ts >= range.startTs && sample.ts < range.endTs);
}

export function buildHourlyTrafficData(
  samples: RequestDeltaSample[],
  range: TrafficRangeBounds | null = null,
): HourlyTrafficDatum[] {
  const grouped = new Map<number, number>();

  for (const sample of samples) {
    const hourStartTs = Math.floor(sample.ts / HOUR_MS) * HOUR_MS;
    grouped.set(hourStartTs, (grouped.get(hourStartTs) ?? 0) + sample.requests);
  }

  if (range) {
    const result: HourlyTrafficDatum[] = [];
    let currentTs = Math.floor(range.startTs / HOUR_MS) * HOUR_MS;
    const endTs = range.endTs;

    while (currentTs < endTs) {
      result.push({
        hourStartTs: currentTs,
        hour: formatHourLabel(currentTs),
        requests: grouped.get(currentTs) ?? 0,
      });
      currentTs += HOUR_MS;
    }
    return result;
  }

  return Array.from(grouped.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([hourStartTs, requests]) => ({
      hourStartTs,
      hour: formatHourLabel(hourStartTs),
      requests,
    }));
}

function toTopGroupedData(
  counters: Map<string, number>,
  limit = TOP_GROUP_LIMIT,
): GroupedTrafficDatum[] {
  const grouped = Array.from(counters.entries())
    .filter(([, requests]) => requests > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (grouped.length <= limit) {
    return grouped.map(([group, requests]) => ({ group, requests }));
  }

  const visible = grouped.slice(0, Math.max(1, limit - 1));
  const otherRequests = grouped
    .slice(Math.max(1, limit - 1))
    .reduce((sum, [, requests]) => sum + requests, 0);

  return [
    ...visible.map(([group, requests]) => ({ group, requests })),
    { group: OTHER_GROUP_LABEL, requests: otherRequests },
  ];
}

export function extractPortLabel(host: string): string {
  const trimmed = host.trim();
  if (!trimmed) return DEFAULT_PORT_LABEL;

  const ipv6PortMatch = trimmed.match(/^\[[^\]]+\]:(\d+)$/);
  if (ipv6PortMatch) return ipv6PortMatch[1];

  try {
    const parsed = new URL(trimmed.includes("://") ? trimmed : `http://${trimmed}`);
    if (parsed.port) return parsed.port;
  } catch {
    // Best effort fallback handled below.
  }

  const trailingPortMatch = trimmed.match(/:(\d+)$/);
  if (trailingPortMatch) return trailingPortMatch[1];
  return DEFAULT_PORT_LABEL;
}

export function buildTrafficByPathData(pathStats: PathStats[]): GroupedTrafficDatum[] {
  const grouped = new Map<string, number>();
  for (const stat of pathStats) {
    const path = stat.path || "/";
    grouped.set(path, (grouped.get(path) ?? 0) + stat.request_count);
  }
  return toTopGroupedData(grouped);
}

export function buildTrafficByPortData(pathStats: PathStats[]): GroupedTrafficDatum[] {
  const grouped = new Map<string, number>();
  for (const stat of pathStats) {
    const port = extractPortLabel(stat.host);
    grouped.set(port, (grouped.get(port) ?? 0) + stat.request_count);
  }
  return toTopGroupedData(grouped);
}

type RouteMatcher = {
  routeLabel: string;
  serviceId: string;
  hosts: string[];
  exactPaths: string[];
  pathPrefixes: string[];
};

function buildRouteMatchers(routes: Route[]): RouteMatcher[] {
  return routes.map((route) => ({
    routeLabel: route.name?.trim() || route.id,
    serviceId: route.service_id,
    hosts: Array.from(route.rule.matchAll(/Host\(`([^`]*)`\)/g), (m) => m[1]),
    exactPaths: Array.from(route.rule.matchAll(/Path\(`([^`]*)`\)/g), (m) => m[1]),
    pathPrefixes: Array.from(route.rule.matchAll(/PathPrefix\(`([^`]*)`\)/g), (m) => m[1]),
  }));
}

function scoreRouteMatch(stat: PathStats, matcher: RouteMatcher): number {
  if (matcher.hosts.length > 0 && !matcher.hosts.includes(stat.host)) {
    return -1;
  }

  let pathScore = 0;
  for (const exactPath of matcher.exactPaths) {
    if (stat.path === exactPath) {
      pathScore = Math.max(pathScore, 10_000 + exactPath.length);
    }
  }
  for (const prefix of matcher.pathPrefixes) {
    if (stat.path.startsWith(prefix)) {
      pathScore = Math.max(pathScore, prefix.length);
    }
  }

  if (matcher.exactPaths.length === 0 && matcher.pathPrefixes.length === 0) {
    pathScore = 1;
  }

  if (pathScore <= 0) return -1;
  return pathScore + (matcher.hosts.length > 0 ? 1_000 : 0);
}

function resolveServiceLabel(
  stat: PathStats,
  routeMatchers: RouteMatcher[],
  serviceNameById: Map<string, string>,
): string {
  let bestScore = -1;
  let bestServiceId: string | null = null;

  for (const matcher of routeMatchers) {
    const score = scoreRouteMatch(stat, matcher);
    if (score > bestScore) {
      bestScore = score;
      bestServiceId = matcher.serviceId;
    }
  }

  if (!bestServiceId) return UNMATCHED_SERVICE_LABEL;
  return serviceNameById.get(bestServiceId) ?? bestServiceId;
}

function resolveRouterLabel(stat: PathStats, routeMatchers: RouteMatcher[]): string {
  let bestScore = -1;
  let bestRouteLabel: string | null = null;

  for (const matcher of routeMatchers) {
    const score = scoreRouteMatch(stat, matcher);
    if (score > bestScore) {
      bestScore = score;
      bestRouteLabel = matcher.routeLabel;
    }
  }

  return bestRouteLabel ?? UNMATCHED_ROUTER_LABEL;
}

export function buildTrafficByServiceData(
  pathStats: PathStats[],
  routes: Route[],
  services: Service[],
): GroupedTrafficDatum[] {
  const routeMatchers = buildRouteMatchers(routes);
  const serviceNameById = new Map(services.map((service) => [service.id, service.name]));
  const grouped = new Map<string, number>();

  for (const stat of pathStats) {
    const serviceLabel = resolveServiceLabel(stat, routeMatchers, serviceNameById);
    grouped.set(serviceLabel, (grouped.get(serviceLabel) ?? 0) + stat.request_count);
  }

  return toTopGroupedData(grouped);
}

export function buildHourlyBandwidthData(
  samples: BandwidthDeltaSample[],
  range: TrafficRangeBounds | null = null,
): HourlyBandwidthDatum[] {
  const grouped = new Map<number, { totalBytes: number; routerBytes: number; serviceBytes: number }>();

  for (const sample of samples) {
    const hourStartTs = Math.floor(sample.ts / HOUR_MS) * HOUR_MS;
    const existing = grouped.get(hourStartTs) ?? {
      totalBytes: 0,
      routerBytes: 0,
      serviceBytes: 0,
    };
    const routerPeak = Object.values(sample.routerBytes).reduce((peak, value) => Math.max(peak, value), 0);
    const servicePeak = Object.values(sample.serviceBytes).reduce((peak, value) => Math.max(peak, value), 0);
    grouped.set(hourStartTs, {
      totalBytes: existing.totalBytes + sample.totalBytes,
      routerBytes: existing.routerBytes + routerPeak,
      serviceBytes: existing.serviceBytes + servicePeak,
    });
  }

  if (range) {
    const result: HourlyBandwidthDatum[] = [];
    let currentTs = Math.floor(range.startTs / HOUR_MS) * HOUR_MS;
    const endTs = range.endTs;

    while (currentTs < endTs) {
      const values = grouped.get(currentTs) ?? {
        totalBytes: 0,
        routerBytes: 0,
        serviceBytes: 0,
      };
      result.push({
        hourStartTs: currentTs,
        hour: formatHourLabel(currentTs),
        totalBytes: values.totalBytes,
        routerBytes: values.routerBytes,
        serviceBytes: values.serviceBytes,
      });
      currentTs += HOUR_MS;
    }
    return result;
  }

  return Array.from(grouped.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([hourStartTs, values]) => ({
      hourStartTs,
      hour: formatHourLabel(hourStartTs),
      totalBytes: values.totalBytes,
      routerBytes: values.routerBytes,
      serviceBytes: values.serviceBytes,
    }));
}

export function buildBandwidthSummaries(hourly: HourlyBandwidthDatum[]): BandwidthSummaryDatum[] {
  const toSummary = (
    label: string,
    color: string,
    selector: (row: HourlyBandwidthDatum) => number,
  ): BandwidthSummaryDatum => {
    if (hourly.length === 0) {
      return { label, max: 0, min: 0, avg: 0, color };
    }
    const values = hourly.map(selector);
    const total = values.reduce((sum, value) => sum + value, 0);
    return {
      label,
      max: Math.max(...values),
      min: Math.min(...values),
      avg: total / values.length,
      color,
    };
  };

  return [
    toSummary("Total", "indigo", (row) => row.totalBytes),
    toSummary("Router", "orange", (row) => row.routerBytes),
    toSummary("Service", "teal", (row) => row.serviceBytes),
  ];
}

export function buildBandwidthByRouterData(pathStats: PathStats[], routes: Route[]): GroupedTrafficDatum[] {
  const routeMatchers = buildRouteMatchers(routes);
  const grouped = new Map<string, number>();

  for (const stat of pathStats) {
    const routerLabel = resolveRouterLabel(stat, routeMatchers);
    grouped.set(routerLabel, (grouped.get(routerLabel) ?? 0) + stat.bytes_total);
  }

  return toTopGroupedData(grouped);
}

export function buildBandwidthByServiceData(
  pathStats: PathStats[],
  routes: Route[],
  services: Service[],
): GroupedTrafficDatum[] {
  const routeMatchers = buildRouteMatchers(routes);
  const serviceNameById = new Map(services.map((service) => [service.id, service.name]));
  const grouped = new Map<string, number>();

  for (const stat of pathStats) {
    const serviceLabel = resolveServiceLabel(stat, routeMatchers, serviceNameById);
    grouped.set(serviceLabel, (grouped.get(serviceLabel) ?? 0) + stat.bytes_total);
  }

  return toTopGroupedData(grouped);
}

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
    [trafficDate, trafficFilterMode, trafficRangeEnd, trafficRangePreset, trafficRangeStart],
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
    setBandwidthDeltaHistory((prev) => [...prev, sample].slice(-720));
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
  ];

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
          <SimpleGrid cols={{ base: 2, sm: 5 }} spacing="md">
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} h={80} radius="md" />
            ))}
          </SimpleGrid>
        ) : (
          <SimpleGrid cols={{ base: 2, sm: 5 }} spacing="md">
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
