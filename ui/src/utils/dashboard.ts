import type { RequestDeltaSample, AggStats, PathStats, CountryTraffic } from "../types/gateon";

export type GroupedTrafficDatum = {
  group: string;
  requests: number;
};

export type HourlyTrafficDatum = {
  hourStartTs: number;
  hour: string;
  requests: number;
};

export type TrafficFilterMode = "all" | "date" | "range";
export type TrafficRangePreset = "last24h" | "last7d" | "last30d" | "custom";

export type TrafficRangeBounds = {
  startTs: number;
  endTs: number;
};

export const TOP_GROUP_LIMIT = 6;
export const REFRESH_INTERVAL_MS = 5000;
export const HOUR_MS = 60 * 60 * 1000;
export const DAY_MS = 24 * HOUR_MS;

export const DEFAULT_PORT_LABEL = "default";
export const OTHER_GROUP_LABEL = "Other";
export const UNMATCHED_SERVICE_LABEL = "Unmatched";
export const UNMATCHED_ROUTER_LABEL = "Unmatched";

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

export function buildTrafficByPortData(pathStats: PathStats[]): GroupedTrafficDatum[] {
  const grouped = new Map<string, number>();
  for (const stat of pathStats) {
    const port = extractPortLabel(stat.host);
    grouped.set(port, (grouped.get(port) ?? 0) + stat.request_count);
  }
  return toTopGroupedData(grouped);
}

export type RouteMatcher = {
  routeLabel: string;
  serviceId: string;
  hosts: string[];
  exactPaths: string[];
  pathPrefixes: string[];
};

export function buildRouteMatchers(routes: Route[]): RouteMatcher[] {
  return routes.map((route) => ({
    routeLabel: route.name?.trim() || route.id,
    serviceId: route.service_id,
    hosts: Array.from(route.rule.matchAll(/Host\(`([^`]*)`\)/g), (m) => m[1]),
    exactPaths: Array.from(route.rule.matchAll(/Path\(`([^`]*)`\)/g), (m) => m[1]),
    pathPrefixes: Array.from(route.rule.matchAll(/PathPrefix\(`([^`]*)`\)/g), (m) => m[1]),
  }));
}

export function scoreRouteMatch(stat: PathStats, matcher: RouteMatcher): number {
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

export function resolveServiceLabel(
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

export function resolveRouterLabel(stat: PathStats, routeMatchers: RouteMatcher[]): string {
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

export function formatHourLabel(ts: number): string {
  const date = new Date(ts);
  return date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit", hour12: false });
}

export function parseDateInputToStartTs(value: string): number | null {
  if (!value) return null;
  const parsed = new Date(`${value}T00:00:00`);
  const ts = parsed.getTime();
  if (Number.isNaN(ts)) return null;
  return ts;
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

export function toTopGroupedData(
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

  return [...visible.map(([group, requests]) => ({ group, requests })), { group: "Other", requests: otherRequests }];
}

export function buildTrafficByPathData(pathStats: PathStats[]): GroupedTrafficDatum[] {
  const counters = new Map<string, number>();
  for (const p of pathStats) {
    counters.set(p.path, (counters.get(p.path) ?? 0) + p.request_count);
  }
  return toTopGroupedData(counters);
}

export function buildRequestTrendData(history: number[]) {
  return history.map((requests, index) => ({
    sample: (index + 1).toString(),
    requests,
  }));
}

export function buildHealthDistribution(agg: AggStats | undefined) {
  if (!agg) return [];
  return [
    {
      group: "Total",
      value: agg.total_targets,
      color: "blue.6",
    },
    {
      group: "Healthy",
      value: agg.healthy_targets,
      color: "teal.6",
    },
    {
      group: "At Risk",
      value: (agg.open_circuits ?? 0) + (agg.half_open_circuits ?? 0),
      color: "red.6",
    },
  ];
}

export function buildResourceDistribution(agg: AggStats | undefined) {
  if (!agg) return [];
  return [
    {
      name: "CPU",
      value: agg.cpu_usage,
      color: "blue",
    },
    {
      name: "Memory",
      value: agg.memory_usage,
      color: "indigo",
    },
  ];
}

export function buildRegionDistribution(countryTraffic: CountryTraffic[] | undefined) {
  if (!countryTraffic) return [];
  const counters = new Map<string, number>();
  for (const c of countryTraffic) {
    counters.set(c.country, (counters.get(c.country) ?? 0) + c.request_count);
  }
  return toTopGroupedData(counters, 5);
}

export function buildDeviceDistribution(agg: any) {
  // Mock distribution since it's not in agg stats yet
  return [
    { group: "Desktop", requests: 750, color: "blue.6" },
    { group: "Mobile", requests: 420, color: "cyan.6" },
    { group: "Tablet", requests: 80, color: "indigo.6" },
    { group: "Other", requests: 30, color: "gray.6" },
  ];
}

export function buildOSDistribution(agg: any) {
  // Mock distribution since it's not in agg stats yet
  return [
    { group: "Windows", requests: 550, color: "blue.7" },
    { group: "macOS", requests: 320, color: "gray.8" },
    { group: "Linux", requests: 210, color: "orange.7" },
    { group: "iOS", requests: 120, color: "teal.6" },
    { group: "Android", requests: 80, color: "green.6" },
  ];
}
