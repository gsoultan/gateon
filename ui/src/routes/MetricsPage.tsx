import {
  Stack,
  Title,
  Text,
  Group,
  SimpleGrid,
  Paper,
  Card,
  Badge,
  Table,
  Progress,
  Skeleton,
  ThemeIcon,
  Tooltip,
  RingProgress,
  Divider,
  Alert,
  Select,
  Button,
} from "@mantine/core";
import {
  IconActivity,
  IconAlertTriangle,
  IconArrowDown,
  IconArrowUp,
  IconCertificate,
  IconChartBar,
  IconClock,
  IconCloud,
  IconCpu,
  IconDatabase,
  IconFlame,
  IconGauge,
  IconHeartbeat,
  IconLock,
  IconNetwork,
  IconRefresh,
  IconServer,
  IconShield,
  IconShieldCheck,
  IconTransferIn,
} from "@tabler/icons-react";
import { useMetricsSnapshot } from "../hooks/useMetricsSnapshot";
import { useMemo, useState } from "react";
import type {
  GoldenSignals,
  RouteMetric,
  MiddlewareMetrics,
  TLSCertMetric,
  TargetMetric,
  SystemMetrics,
  LabeledCount,
} from "../types/metrics";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const idx = Math.min(i, units.length - 1);
  return `${(bytes / Math.pow(1024, idx)).toFixed(1)} ${units[idx]}`;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString(undefined, { maximumFractionDigits: 1 });
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

function formatLatency(ms: number): string {
  if (ms === 0) return "—";
  if (ms < 1) return `${(ms * 1000).toFixed(0)}µs`;
  if (ms < 1000) return `${ms.toFixed(1)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function errorRateColor(rate: number): string {
  if (rate === 0) return "green";
  if (rate < 1) return "teal";
  if (rate < 5) return "yellow";
  return "red";
}

function latencyColor(ms: number): string {
  if (ms === 0) return "gray";
  if (ms < 50) return "green";
  if (ms < 200) return "yellow";
  if (ms < 1000) return "orange";
  return "red";
}

function certExpiryColor(days: number): string {
  if (days < 7) return "red";
  if (days < 30) return "orange";
  if (days < 90) return "yellow";
  return "green";
}

// --- Section Components ---

function GoldenSignalsSection({ gs }: { gs: GoldenSignals }) {
  const cards = [
    {
      label: "Total Requests",
      value: formatNumber(gs.requests_total),
      icon: IconTransferIn,
      color: "indigo",
      description: "All HTTP requests processed",
    },
    {
      label: "Error Rate",
      value: `${gs.error_rate.toFixed(2)}%`,
      icon: IconAlertTriangle,
      color: errorRateColor(gs.error_rate),
      description: `${formatNumber(gs.errors_total)} errors of ${formatNumber(gs.requests_total)} requests`,
    },
    {
      label: "Avg Latency",
      value: formatLatency(gs.avg_latency_ms),
      icon: IconClock,
      color: latencyColor(gs.avg_latency_ms),
      description: "Mean request duration",
    },
    {
      label: "P95 Latency",
      value: formatLatency(gs.p95_latency_ms),
      icon: IconGauge,
      color: latencyColor(gs.p95_latency_ms),
      description: "95th percentile response time",
    },
    {
      label: "P99 Latency",
      value: formatLatency(gs.p99_latency_ms),
      icon: IconFlame,
      color: latencyColor(gs.p99_latency_ms),
      description: "99th percentile response time",
    },
    {
      label: "In-Flight",
      value: formatNumber(gs.in_flight_total),
      icon: IconActivity,
      color: "cyan",
      description: "Currently processing requests",
    },
    {
      label: "Traffic In",
      value: formatBytes(gs.bytes_in_total),
      icon: IconArrowDown,
      color: "blue",
      description: "Total inbound bytes",
    },
    {
      label: "Traffic Out",
      value: formatBytes(gs.bytes_out_total),
      icon: IconArrowUp,
      color: "violet",
      description: "Total outbound bytes",
    },
  ];

  return (
    <Card shadow="sm" padding="lg" radius="lg" withBorder>
      <Group justify="space-between" mb="md">
        <Group gap="xs">
          <ThemeIcon variant="light" color="indigo" size="md" radius="md">
            <IconChartBar size={16} />
          </ThemeIcon>
          <Title order={5} fw={700}>
            Golden Signals
          </Title>
        </Group>
        <Badge variant="dot" color="green" size="sm">
          Live
        </Badge>
      </Group>
      <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
        {cards.map((c) => (
          <Paper
            key={c.label}
            p="md"
            radius="md"
            withBorder
            style={{
              borderLeftWidth: 4,
              borderLeftColor: `var(--mantine-color-${c.color}-6)`,
            }}
          >
            <Group gap="sm" wrap="nowrap">
              <ThemeIcon
                variant="light"
                color={c.color}
                size="lg"
                radius="md"
              >
                <c.icon size={18} />
              </ThemeIcon>
              <div style={{ minWidth: 0 }}>
                <Text
                  size="xs"
                  c="dimmed"
                  fw={700}
                  style={{ textTransform: "uppercase", letterSpacing: 0.5 }}
                >
                  {c.label}
                </Text>
                <Text size="xl" fw={800} c={`${c.color}.6`}>
                  {c.value}
                </Text>
                <Text size="xs" c="dimmed" lineClamp={1} title={c.description}>
                  {c.description}
                </Text>
              </div>
            </Group>
          </Paper>
        ))}
      </SimpleGrid>
    </Card>
  );
}

function LatencyPercentilesCard({ gs }: { gs: GoldenSignals }) {
  const items = [
    { label: "P50", value: gs.p50_latency_ms, color: "green" },
    { label: "P95", value: gs.p95_latency_ms, color: "yellow" },
    { label: "P99", value: gs.p99_latency_ms, color: "red" },
    { label: "Avg", value: gs.avg_latency_ms, color: "blue" },
  ];
  const maxVal = Math.max(...items.map((i) => i.value), 1);

  return (
    <Card shadow="sm" padding="lg" radius="lg" withBorder>
      <Group gap="xs" mb="md">
        <ThemeIcon variant="light" color="orange" size="md" radius="md">
          <IconGauge size={16} />
        </ThemeIcon>
        <Title order={5} fw={700}>
          Latency Distribution
        </Title>
      </Group>
      <Stack gap="sm">
        {items.map((item) => (
          <div key={item.label}>
            <Group justify="space-between" mb={4}>
              <Text size="sm" fw={600}>
                {item.label}
              </Text>
              <Text size="sm" fw={700} c={`${item.color}.6`}>
                {formatLatency(item.value)}
              </Text>
            </Group>
            <Progress
              value={(item.value / maxVal) * 100}
              color={item.color}
              size="lg"
              radius="md"
            />
          </div>
        ))}
      </Stack>
    </Card>
  );
}

function RouteMetricsSection({ routes }: { routes: RouteMetric[] | null }) {
  const [routeFilter, setRouteFilter] = useState<string | null>(null);

  const sorted = useMemo(
    () => [...(routes ?? [])].sort((a, b) => b.requests - a.requests),
    [routes],
  );

  const routeOptions = useMemo(
    () =>
      Array.from(
        new Set(
          sorted
            .map((route) => route.route)
            .filter((route): route is string => Boolean(route)),
        ),
      ).sort((a, b) => a.localeCompare(b)),
    [sorted],
  );

  const filteredRoutes = useMemo(
    () =>
      routeFilter
        ? sorted.filter((route) => route.route === routeFilter)
        : sorted,
    [sorted, routeFilter],
  );

  return (
    <Card shadow="sm" padding="lg" radius="lg" withBorder>
      <Group gap="xs" mb="md">
        <ThemeIcon variant="light" color="blue" size="md" radius="md">
          <IconNetwork size={16} />
        </ThemeIcon>
        <Title order={5} fw={700}>
          Per-Route Metrics
        </Title>
        <Badge size="sm" variant="light" color="gray">
          {sorted.length} routes
        </Badge>
      </Group>

      {sorted.length === 0 ? (
        <Text c="dimmed" size="sm" ta="center" py="xl">
          No route metrics available yet. Metrics appear after traffic is
          processed.
        </Text>
      ) : (
        <Stack gap="sm">
          <Group justify="space-between" align="flex-end" wrap="wrap">
            <Select
              label="Route"
              placeholder="Filter by route"
              data={routeOptions}
              value={routeFilter}
              onChange={setRouteFilter}
              searchable
              clearable
              w={320}
            />
            <Button
              variant="subtle"
              size="xs"
              disabled={!routeFilter}
              onClick={() => setRouteFilter(null)}
            >
              Clear filter
            </Button>
          </Group>

          {filteredRoutes.length === 0 ? (
            <Text c="dimmed" size="sm" ta="center" py="xl">
              No metrics found for the selected route.
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={700}>
              <Table striped highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Route</Table.Th>
                    <Table.Th>Service</Table.Th>
                    <Table.Th style={{ textAlign: "right" }}>Requests</Table.Th>
                    <Table.Th style={{ textAlign: "right" }}>Errors</Table.Th>
                    <Table.Th style={{ textAlign: "right" }}>Error Rate</Table.Th>
                    <Table.Th style={{ textAlign: "right" }}>Avg Latency</Table.Th>
                    <Table.Th style={{ textAlign: "right" }}>In-Flight</Table.Th>
                    <Table.Th>Failures / Reasons</Table.Th>
                    <Table.Th>Status Codes</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {filteredRoutes.map((r) => (
                    <Table.Tr key={r.route}>
                      <Table.Td>
                        <Text size="sm" fw={600} lineClamp={1}>
                          {r.route}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" c="dimmed" lineClamp={1}>
                          {r.service || "—"}
                        </Text>
                      </Table.Td>
                      <Table.Td style={{ textAlign: "right" }}>
                        <Text size="sm" fw={600}>
                          {formatNumber(r.requests)}
                        </Text>
                      </Table.Td>
                      <Table.Td style={{ textAlign: "right" }}>
                        <Text
                          size="sm"
                          fw={600}
                          c={r.errors > 0 ? "red" : "dimmed"}
                        >
                          {formatNumber(r.errors)}
                        </Text>
                      </Table.Td>
                      <Table.Td style={{ textAlign: "right" }}>
                        <Badge
                          size="sm"
                          variant="light"
                          color={errorRateColor(r.error_rate)}
                        >
                          {r.error_rate.toFixed(1)}%
                        </Badge>
                      </Table.Td>
                      <Table.Td style={{ textAlign: "right" }}>
                        <Text size="sm" c={latencyColor(r.avg_latency_ms)}>
                          {formatLatency(r.avg_latency_ms)}
                        </Text>
                      </Table.Td>
                      <Table.Td style={{ textAlign: "right" }}>
                        <Text size="sm">{r.in_flight}</Text>
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4}>
                          {r.failures && r.failures.length > 0 ? (
                            r.failures.map((f) => (
                              <Tooltip key={f.label} label={f.label}>
                                <Badge size="xs" variant="outline" color="red">
                                  {f.label}: {formatNumber(f.value)}
                                </Badge>
                              </Tooltip>
                            ))
                          ) : (
                            <Text size="xs" c="dimmed">
                              —
                            </Text>
                          )}
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4} wrap="wrap">
                          {Object.entries(r.status_codes)
                            .sort(([a], [b]) => a.localeCompare(b))
                            .map(([code, count]) => (
                              <Tooltip
                                key={code}
                                label={`${code}: ${formatNumber(count)} requests`}
                              >
                                <Badge
                                  size="xs"
                                  variant="light"
                                  color={
                                    code.startsWith("2")
                                      ? "green"
                                      : code.startsWith("3")
                                        ? "blue"
                                        : code.startsWith("4")
                                          ? "yellow"
                                          : "red"
                                  }
                                >
                                  {code}: {formatNumber(count)}
                                </Badge>
                              </Tooltip>
                            ))}
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </Stack>
      )}
    </Card>
  );
}

function MiddlewareCard({
  title,
  icon: Icon,
  color,
  children,
}: {
  title: string;
  icon: React.ElementType;
  color: string;
  children: React.ReactNode;
}) {
  return (
    <Paper p="md" radius="md" withBorder>
      <Group gap="xs" mb="sm">
        <ThemeIcon variant="light" color={color} size="sm" radius="md">
          <Icon size={14} />
        </ThemeIcon>
        <Text size="sm" fw={700}>
          {title}
        </Text>
      </Group>
      {children}
    </Paper>
  );
}

function LabeledCountList({ items }: { items: LabeledCount[] | null }) {
  if (!items || items.length === 0) {
    return (
      <Text size="xs" c="dimmed">
        None recorded
      </Text>
    );
  }
  return (
    <Stack gap={4}>
      {items.map((item) => (
        <Group key={item.label} justify="space-between">
          <Text size="xs" c="dimmed">
            {item.label}
          </Text>
          <Badge size="xs" variant="filled" color="red">
            {formatNumber(item.value)}
          </Badge>
        </Group>
      ))}
    </Stack>
  );
}

function MiddlewareMetricsSection({ mw }: { mw: MiddlewareMetrics }) {
  const cacheTotal = mw.cache_hits + mw.cache_misses;
  const retriesTotal = mw.retries_success + mw.retries_failure;
  const turnstileTotal = mw.turnstile_pass + mw.turnstile_fail;

  return (
    <Card shadow="sm" padding="lg" radius="lg" withBorder>
      <Group gap="xs" mb="md">
        <ThemeIcon variant="light" color="grape" size="md" radius="md">
          <IconShield size={16} />
        </ThemeIcon>
        <Title order={5} fw={700}>
          Middleware Metrics
        </Title>
      </Group>
      <SimpleGrid cols={{ base: 1, sm: 2, md: 3, lg: 4 }} spacing="md">
        <MiddlewareCard title="Rate Limiting" icon={IconShield} color="red">
          <LabeledCountList items={mw.rate_limit_rejected} />
        </MiddlewareCard>

        <MiddlewareCard title="WAF Blocks" icon={IconShieldCheck} color="orange">
          <LabeledCountList items={mw.waf_blocked} />
        </MiddlewareCard>

        <MiddlewareCard title="Cache" icon={IconDatabase} color="teal">
          {cacheTotal > 0 ? (
            <Stack gap="xs">
              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  Hit Rate
                </Text>
                <Text size="sm" fw={700} c="teal">
                  {mw.cache_hit_rate.toFixed(1)}%
                </Text>
              </Group>
              <Progress value={mw.cache_hit_rate} color="teal" size="sm" radius="md" />
              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  Hits: {formatNumber(mw.cache_hits)}
                </Text>
                <Text size="xs" c="dimmed">
                  Misses: {formatNumber(mw.cache_misses)}
                </Text>
              </Group>
            </Stack>
          ) : (
            <Text size="xs" c="dimmed">
              No cache activity
            </Text>
          )}
        </MiddlewareCard>

        <MiddlewareCard title="Auth Failures" icon={IconLock} color="red">
          <LabeledCountList items={mw.auth_failures} />
        </MiddlewareCard>

        <MiddlewareCard title="Compression" icon={IconCloud} color="blue">
          {mw.compress_bytes_in > 0 ? (
            <Stack gap="xs">
              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  Ratio
                </Text>
                <Text size="sm" fw={700} c="blue">
                  {mw.compression_ratio.toFixed(1)}%
                </Text>
              </Group>
              <Progress
                value={mw.compression_ratio}
                color="blue"
                size="sm"
                radius="md"
              />
              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  In: {formatBytes(mw.compress_bytes_in)}
                </Text>
                <Text size="xs" c="dimmed">
                  Out: {formatBytes(mw.compress_bytes_out)}
                </Text>
              </Group>
            </Stack>
          ) : (
            <Text size="xs" c="dimmed">
              No compressed responses
            </Text>
          )}
        </MiddlewareCard>

        <MiddlewareCard title="Turnstile" icon={IconShieldCheck} color="cyan">
          {turnstileTotal > 0 ? (
            <Stack gap="xs">
              <Group justify="space-between">
                <Text size="xs" c="green">
                  Pass: {formatNumber(mw.turnstile_pass)}
                </Text>
                <Text size="xs" c="red">
                  Fail: {formatNumber(mw.turnstile_fail)}
                </Text>
              </Group>
              <Progress
                value={
                  turnstileTotal > 0
                    ? (mw.turnstile_pass / turnstileTotal) * 100
                    : 0
                }
                color="green"
                size="sm"
                radius="md"
              />
            </Stack>
          ) : (
            <Text size="xs" c="dimmed">
              No challenges recorded
            </Text>
          )}
        </MiddlewareCard>

        <MiddlewareCard title="GeoIP Blocks" icon={IconNetwork} color="orange">
          <LabeledCountList items={mw.geoip_blocked} />
        </MiddlewareCard>

        <MiddlewareCard title="Retries" icon={IconRefresh} color="violet">
          {retriesTotal > 0 ? (
            <Group justify="space-between">
              <Text size="xs" c="green">
                Success: {formatNumber(mw.retries_success)}
              </Text>
              <Text size="xs" c="red">
                Failed: {formatNumber(mw.retries_failure)}
              </Text>
            </Group>
          ) : (
            <Text size="xs" c="dimmed">
              No retries triggered
            </Text>
          )}
        </MiddlewareCard>
      </SimpleGrid>

      <Divider my="md" />
      <Group gap="xl">
        <Group gap="xs">
          <Text size="xs" c="dimmed">
            HMAC Failures:
          </Text>
          <Badge
            size="xs"
            variant="light"
            color={mw.hmac_failures > 0 ? "red" : "gray"}
          >
            {formatNumber(mw.hmac_failures)}
          </Badge>
        </Group>
        <Group gap="xs">
          <Text size="xs" c="dimmed">
            Config Reloads:
          </Text>
          <Badge size="xs" variant="light" color="blue">
            {formatNumber(mw.config_reloads)}
          </Badge>
        </Group>
        <Group gap="xs">
          <Text size="xs" c="dimmed">
            Cache Invalidations:
          </Text>
          <Badge size="xs" variant="light" color="orange">
            {formatNumber(mw.cache_invalidations)}
          </Badge>
        </Group>
      </Group>
    </Card>
  );
}

function TLSCertificatesSection({ certs }: { certs: TLSCertMetric[] | null }) {
  if (!certs || certs.length === 0) {
    return (
      <Card shadow="sm" padding="lg" radius="lg" withBorder>
        <Group gap="xs" mb="md">
          <ThemeIcon variant="light" color="green" size="md" radius="md">
            <IconCertificate size={16} />
          </ThemeIcon>
          <Title order={5} fw={700}>
            TLS Certificates
          </Title>
        </Group>
        <Text c="dimmed" size="sm" ta="center" py="md">
          No TLS certificates configured or loaded.
        </Text>
      </Card>
    );
  }

  const sorted = [...certs].sort((a, b) => a.days_remaining - b.days_remaining);
  const expiringSoon = sorted.filter((c) => c.days_remaining < 30);

  return (
    <Card shadow="sm" padding="lg" radius="lg" withBorder>
      <Group justify="space-between" mb="md">
        <Group gap="xs">
          <ThemeIcon variant="light" color="green" size="md" radius="md">
            <IconCertificate size={16} />
          </ThemeIcon>
          <Title order={5} fw={700}>
            TLS Certificates
          </Title>
          <Badge size="sm" variant="light" color="gray">
            {certs.length}
          </Badge>
        </Group>
        {expiringSoon.length > 0 && (
          <Badge color="orange" variant="filled" size="sm">
            {expiringSoon.length} expiring soon
          </Badge>
        )}
      </Group>
      {expiringSoon.length > 0 && (
        <Alert
          color="orange"
          icon={<IconAlertTriangle size={16} />}
          mb="md"
          radius="md"
        >
          {expiringSoon.length} certificate(s) expire within 30 days. Renew
          them to avoid service disruption.
        </Alert>
      )}
      <SimpleGrid cols={{ base: 1, sm: 2, md: 3 }} spacing="md">
        {sorted.map((cert) => {
          const color = certExpiryColor(cert.days_remaining);
          const expiryDate = new Date(cert.expiry_epoch * 1000);
          return (
            <Paper key={`${cert.domain}-${cert.cert_name}`} p="md" radius="md" withBorder>
              <Group justify="space-between" mb="xs">
                <div style={{ minWidth: 0 }}>
                  <Text size="sm" fw={700} lineClamp={1}>
                    {cert.domain || cert.cert_name}
                  </Text>
                  {cert.domain && cert.cert_name && cert.domain !== cert.cert_name && (
                    <Text size="xs" c="dimmed" lineClamp={1}>
                      {cert.cert_name}
                    </Text>
                  )}
                </div>
                <RingProgress
                  size={48}
                  thickness={5}
                  roundCaps
                  sections={[
                    {
                      value: Math.min(
                        (cert.days_remaining / 365) * 100,
                        100
                      ),
                      color,
                    },
                  ]}
                  label={
                    <Text ta="center" size="xs" fw={700} c={color}>
                      {Math.floor(cert.days_remaining)}
                    </Text>
                  }
                />
              </Group>
              <Text size="xs" c="dimmed">
                Expires: {expiryDate.toLocaleDateString()}
              </Text>
              <Badge
                size="xs"
                variant="light"
                color={color}
                mt={4}
                fullWidth
              >
                {cert.days_remaining < 0
                  ? "EXPIRED"
                  : `${Math.floor(cert.days_remaining)} days remaining`}
              </Badge>
            </Paper>
          );
        })}
      </SimpleGrid>
    </Card>
  );
}

function TargetHealthSection({ targets }: { targets: TargetMetric[] | null }) {
  if (!targets || targets.length === 0) {
    return (
      <Card shadow="sm" padding="lg" radius="lg" withBorder>
        <Group gap="xs" mb="md">
          <ThemeIcon variant="light" color="teal" size="md" radius="md">
            <IconHeartbeat size={16} />
          </ThemeIcon>
          <Title order={5} fw={700}>
            Target Health
          </Title>
        </Group>
        <Text c="dimmed" size="sm" ta="center" py="md">
          No backend targets with health data available.
        </Text>
      </Card>
    );
  }

  const healthy = targets.filter((t) => t.healthy).length;
  const total = targets.length;
  const healthPct = total > 0 ? (healthy / total) * 100 : 0;

  return (
    <Card shadow="sm" padding="lg" radius="lg" withBorder>
      <Group justify="space-between" mb="md">
        <Group gap="xs">
          <ThemeIcon variant="light" color="teal" size="md" radius="md">
            <IconHeartbeat size={16} />
          </ThemeIcon>
          <Title order={5} fw={700}>
            Target Health
          </Title>
          <Badge size="sm" variant="light" color="gray">
            {total} targets
          </Badge>
        </Group>
        <Badge
          size="sm"
          variant="filled"
          color={healthPct === 100 ? "green" : healthPct > 50 ? "yellow" : "red"}
        >
          {healthy}/{total} healthy
        </Badge>
      </Group>
      <Progress
        value={healthPct}
        color={healthPct === 100 ? "green" : healthPct > 50 ? "yellow" : "red"}
        size="md"
        radius="md"
        mb="md"
      />
      <Table.ScrollContainer minWidth={500}>
        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Target</Table.Th>
              <Table.Th>Route</Table.Th>
              <Table.Th style={{ textAlign: "center" }}>Status</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Active Conn</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {targets.map((t) => (
              <Table.Tr key={`${t.route}-${t.target}`}>
                <Table.Td>
                  <Text size="sm" fw={500} lineClamp={1}>
                    {t.target}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" c="dimmed" lineClamp={1}>
                    {t.route}
                  </Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "center" }}>
                  <Badge
                    size="sm"
                    variant="filled"
                    color={t.healthy ? "green" : "red"}
                  >
                    {t.healthy ? "Healthy" : "Unhealthy"}
                  </Badge>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="sm">{t.active_conn}</Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Card>
  );
}

function SystemMetricsSection({ sys }: { sys: SystemMetrics }) {
  const items = [
    {
      label: "Uptime",
      value: formatDuration(sys.uptime_seconds),
      icon: IconClock,
      color: "green",
      description: `${sys.uptime_seconds.toFixed(0)}s total`,
    },
    {
      label: "Goroutines",
      value: formatNumber(sys.goroutines),
      icon: IconCpu,
      color: sys.goroutines > 10000 ? "orange" : "blue",
      description: "Active Go routines",
    },
    {
      label: "Heap Memory",
      value: formatBytes(sys.memory_alloc_bytes),
      icon: IconDatabase,
      color: "violet",
      description: "Current heap allocation",
    },
    {
      label: "Total Allocated",
      value: formatBytes(sys.memory_total_alloc_bytes),
      icon: IconServer,
      color: "grape",
      description: "Cumulative allocations",
    },
    {
      label: "System Memory",
      value: formatBytes(sys.memory_sys_bytes),
      icon: IconServer,
      color: "indigo",
      description: "Memory obtained from OS",
    },
  ];

  return (
    <Card shadow="sm" padding="lg" radius="lg" withBorder>
      <Group gap="xs" mb="md">
        <ThemeIcon variant="light" color="blue" size="md" radius="md">
          <IconCpu size={16} />
        </ThemeIcon>
        <Title order={5} fw={700}>
          System Metrics
        </Title>
      </Group>
      <SimpleGrid cols={{ base: 2, sm: 3, md: 5 }} spacing="md">
        {items.map((item) => (
          <Paper key={item.label} p="md" radius="md" withBorder ta="center">
            <ThemeIcon
              variant="light"
              color={item.color}
              size="lg"
              radius="xl"
              mx="auto"
              mb="xs"
            >
              <item.icon size={18} />
            </ThemeIcon>
            <Text size="lg" fw={800} c={`${item.color}.6`}>
              {item.value}
            </Text>
            <Text size="xs" fw={600} c="dimmed" mt={2}>
              {item.label}
            </Text>
            <Text size="xs" c="dimmed" mt={2}>
              {item.description}
            </Text>
          </Paper>
        ))}
      </SimpleGrid>
    </Card>
  );
}

// --- Loading Skeleton ---

function MetricsSkeleton() {
  return (
    <Stack gap="lg">
      <Skeleton h={200} radius="lg" />
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Skeleton h={200} radius="lg" />
        <Skeleton h={200} radius="lg" />
      </SimpleGrid>
      <Skeleton h={300} radius="lg" />
      <Skeleton h={200} radius="lg" />
    </Stack>
  );
}

// --- Main Page ---

export default function MetricsPage() {
  const { data, isLoading, error } = useMetricsSnapshot();

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -0.5 }}>
            Metrics Dashboard
          </Title>
          <Text c="dimmed" size="sm" fw={500} mt={4}>
            Real-time Prometheus metrics — golden signals, per-route breakdown,
            middleware counters, TLS certificates, and system health.
          </Text>
        </div>
        <Badge variant="dot" color={isLoading ? "yellow" : "green"} size="lg">
          {isLoading ? "Loading..." : "Live"}
        </Badge>
      </Group>

      {error && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />} radius="md">
          Failed to load metrics: {error.message}
        </Alert>
      )}

      {isLoading && !data ? (
        <MetricsSkeleton />
      ) : data ? (
        <Stack gap="lg">
          <GoldenSignalsSection gs={data.golden_signals} />

          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <LatencyPercentilesCard gs={data.golden_signals} />
            <SystemMetricsSection sys={data.system} />
          </SimpleGrid>

          <RouteMetricsSection routes={data.route_metrics} />
          <MiddlewareMetricsSection mw={data.middleware} />

          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <TLSCertificatesSection certs={data.tls_certificates} />
            <TargetHealthSection targets={data.targets} />
          </SimpleGrid>
        </Stack>
      ) : null}
    </Stack>
  );
}
