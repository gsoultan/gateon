// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  Title,
  Text,
  Card,
  Table,
  Badge,
  Group,
  Stack,
  ActionIcon,
  Tooltip,
  Paper,
  Box,
  Divider,
  ScrollArea,
  Code,
  TextInput,
  Select,
  Button,
  Pagination,
  CopyButton,
  UnstyledButton,
  Skeleton,
  Center,
  Tabs,
} from "@mantine/core";
import {
  IconSearch,
  IconRefresh,
  IconExternalLink,
  IconTimeline,
  IconCircleCheck,
  IconCircleX,
  IconCopy,
  IconCheck,
  IconClock,
  IconFingerprint,
  IconRoute,
  IconInfoCircle,
  IconActivity,
  IconHistory,
  IconArchive,
} from "@tabler/icons-react";
import { lazy, Suspense, useState, useMemo, useTransition } from "react";

import { useTraces } from "../hooks/useGateon";
import { safeToFixed } from "../utils/format";
import { useTableDensity } from "../hooks/useTableDensity";
import { useUrlFilters } from "../hooks/useUrlFilters";
import type { Trace } from "../hooks/useGateon";
import TraceVisualizer from "../components/Diagnostics/TraceVisualizer";
import { QueryError } from "../components/QueryError";
import TraceDetailsModal from "../components/Traces/TraceDetailsModal";
import { getDurationColor, getStatusColor, isSuccessStatus } from "../components/Traces/traceFormat";
import { hourPeriod, type Period } from "../components/Traces/tracePeriods";

// The History and Archive tabs load when first opened: most visits to this
// page are for the live view.
const TraceHistoryPanel = lazy(() => import("../components/Traces/TraceHistoryPanel"));
const TraceArchivePanel = lazy(() => import("../components/Traces/TraceArchivePanel"));

type TracesTab = "live" | "history" | "archive";
const asTab = (v: string | undefined): TracesTab => (v === "history" || v === "archive" ? v : "live");

// urlPeriod reads the History tab's period from the URL, if it holds one.
function urlPeriod(from?: string, to?: string): Period | null {
  if (!from || !to) return null;
  const p = { from: new Date(from), to: new Date(to) };
  return Number.isNaN(p.from.getTime()) || Number.isNaN(p.to.getTime()) ? null : p;
}

const PAGE_SIZE = 20;

export default function TracesPage() {
  // URL-synced filters make a filtered trace view bookmarkable/shareable; local
  // state (seeded from the URL) keeps typing responsive while we mirror to the URL.
  const [filters, setFilters] = useUrlFilters<{ q: string; route: string; tab: string; from: string; to: string }>();
  const tab = asTab(filters.tab);
  const { data: traces = [], isLoading, isError, error, refetch } = useTraces(100, tab === "live");
  const density = useTableDensity();
  const [search, setSearch] = useState(filters.q ?? "");
  const [deferredSearch, setDeferredSearch] = useState(filters.q ?? "");
  const [routeFilter, setRouteFilter] = useState<string | null>(
    filters.route ?? null,
  );
  const [page, setPage] = useState(1);
  const [isPending, startTransition] = useTransition();

  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [visualizerOpened, setVisualizerOpened] = useState(false);
  
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null);
  const [selectedTraceTs, setSelectedTraceTs] = useState<string | null>(null);
  const [detailsOpened, setDetailsOpened] = useState(false);

  const showTab = (next: string | null) => setFilters({ tab: next === "live" ? undefined : (next ?? undefined) });
  const viewHour = (periodStart: string) => {
    const p = hourPeriod(periodStart);
    if (p) setFilters({ tab: "history", from: p.from.toISOString(), to: p.to.toISOString() });
  };

  const openVisualizer = (ip: string) => {
    if (!ip || ip === "-" || ip === "127.0.0.1") return;
    setSelectedIp(ip);
    setVisualizerOpened(true);
  };

  const openDetails = (trace: Trace) => {
    setSelectedTraceId(trace.id);
    setSelectedTraceTs(trace.timestamp);
    setDetailsOpened(true);
  };

  const routeOptions = useMemo(
    () =>
      Array.from(
        new Set(
          traces
            .map((trace) => trace.path)
            .filter((path): path is string => Boolean(path)),
        ),
      ).sort((a, b) => a.localeCompare(b)),
    [traces],
  );

  const handleSearchChange = (val: string) => {
    setSearch(val);
    setPage(1);
    setFilters({ q: val });
    startTransition(() => {
      setDeferredSearch(val);
    });
  };

  const filteredTraces = useMemo(() => {
    return traces.filter((t) => {
      if (routeFilter && t.path !== routeFilter) return false;
      if (!deferredSearch) return true;

      const lower = deferredSearch.toLowerCase();
      return (
        t.id.toLowerCase().includes(lower) ||
        t.operationName.toLowerCase().includes(lower) ||
        t.serviceName.toLowerCase().includes(lower) ||
        t.sourceIp.toLowerCase().includes(lower) ||
        t.path.toLowerCase().includes(lower) ||
        t.status.toLowerCase().includes(lower)
      );
    });
  }, [traces, deferredSearch, routeFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredTraces.length / PAGE_SIZE));
  const paginatedTraces = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return filteredTraces.slice(start, start + PAGE_SIZE);
  }, [filteredTraces, page]);

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Stack gap={0}>
          <Group gap="sm" align="center">
            <Title order={2}>Distributed Tracing</Title>
            {tab === "live" && traces.length > 0 && (
              <Badge variant="light" size="lg" radius="sm">
                {traces.length} Total
              </Badge>
            )}
          </Group>
          <Text c="dimmed">
            Monitor and visualize end-to-end request flows across your
            microservices.
          </Text>
        </Stack>
        <Group>
          {tab === "live" && (
            <Stack gap={0} align="flex-end">
              <Button
                leftSection={<IconRefresh size={16} />}
                variant="light"
                loading={isLoading}
                onClick={() => refetch()}
              >
                Refresh
              </Button>
              <Text size="xs" c="dimmed" mt={4}>
                Auto-refreshes every 5s
              </Text>
            </Stack>
          )}
          <Tooltip label="Open in Jaeger">
            <ActionIcon variant="light" color="blue" size="lg" component="a" href="#" onClick={(e) => e.preventDefault()}>
              <IconExternalLink size={20} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* keepMounted off: a tab that is not showing is not mounted, so the
          archive is not listed and no period is queried until they are. */}
      <Tabs value={tab} onChange={showTab} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="live" leftSection={<IconActivity size={16} />}>Live</Tabs.Tab>
          <Tabs.Tab value="history" leftSection={<IconHistory size={16} />}>History</Tabs.Tab>
          <Tabs.Tab value="archive" leftSection={<IconArchive size={16} />}>Archive</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="live" pt="md">
          <Stack gap="lg">
            <Card withBorder padding="md">
              <Stack gap="md">
                <Group justify="space-between">
                  <TextInput
                    placeholder="Search traces by ID, service, or path..."
                    leftSection={<IconSearch size={16} />}
                    value={search}
                    onChange={(e) => handleSearchChange(e.currentTarget.value)}
                    style={{ flex: 1 }}
                    rightSection={isPending ? <Text size="xs">...</Text> : null}
                  />
                  <Select
                    placeholder="Route path"
                    data={routeOptions}
                    value={routeFilter}
                    onChange={(value) => {
                      setRouteFilter(value);
                      setPage(1);
                      setFilters({ route: value ?? undefined });
                    }}
                    searchable
                    clearable
                    w={{ base: "100%", sm: 350 }}
                    renderOption={({ option }) => (
                      <Tooltip label={option.value} position="right" withArrow openDelay={400}>
                        <Text size="xs" truncate="end" style={{ maxWidth: '100%' }}>
                          {option.value}
                        </Text>
                      </Tooltip>
                    )}
                  />
                  <Button
                    variant="subtle"
                    size="xs"
                    disabled={!search && !routeFilter}
                    onClick={() => {
                      handleSearchChange("");
                      setRouteFilter(null);
                      setFilters({ q: undefined, route: undefined });
                    }}
                  >
                    Clear filters
                  </Button>
                </Group>

                <ScrollArea>
                  <Table
                    {...density}
                    highlightOnHover
                    striped
                    style={{ opacity: isPending ? 0.7 : 1, transition: 'opacity 0.2s' }}
                  >
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th><Group gap={4}><IconFingerprint size={14} /> ID</Group></Table.Th>
                        <Table.Th>Method</Table.Th>
                        <Table.Th>Service</Table.Th>
                        <Table.Th><Group gap={4}><IconRoute size={14} /> Source IP</Group></Table.Th>
                        <Table.Th>Path</Table.Th>
                        <Table.Th><Group gap={4}><IconClock size={14} /> Duration</Group></Table.Th>
                        <Table.Th>Status</Table.Th>
                        <Table.Th>Timestamp</Table.Th>
                        <Table.Th>Actions</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {isError ? (
                        <QueryError error={error} what="traces" onRetry={() => refetch()} />
                      ) : isLoading ? (
                        Array.from({ length: 5 }).map((_, i) => (
                          <Table.Tr key={i}>
                            <Table.Td><Skeleton height={20} radius="xl" /></Table.Td>
                            <Table.Td><Skeleton height={20} radius="xl" /></Table.Td>
                            <Table.Td><Skeleton height={20} radius="xl" /></Table.Td>
                            <Table.Td><Skeleton height={20} radius="xl" /></Table.Td>
                            <Table.Td><Skeleton height={20} radius="xl" /></Table.Td>
                            <Table.Td><Skeleton height={20} radius="xl" /></Table.Td>
                            <Table.Td><Skeleton height={20} radius="xl" /></Table.Td>
                            <Table.Td><Skeleton height={20} radius="xl" /></Table.Td>
                            <Table.Td><Skeleton height={20} radius="xl" /></Table.Td>
                          </Table.Tr>
                        ))
                      ) : (
                        paginatedTraces.map((trace) => (
                        <Table.Tr key={trace.id}>
                          <Table.Td>
                            <Group gap="xs" wrap="nowrap">
                              <Tooltip label={trace.id} withArrow>
                                <Code color="blue.1" c="blue.8">
                                  {trace.id.substring(0, 8)}...
                                </Code>
                              </Tooltip>
                              <CopyButton value={trace.id} timeout={2000}>
                                {({ copied, copy }) => (
                                  <ActionIcon variant="subtle" color={copied ? 'teal' : 'gray'} onClick={copy} size="sm">
                                    {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
                                  </ActionIcon>
                                )}
                              </CopyButton>
                            </Group>
                          </Table.Td>
                          <Table.Td>
                            <Badge variant="outline" color="blue" size="xs">
                              {trace.method || "-"}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Badge variant="dot" color="blue" size="sm">{trace.serviceName}</Badge>
                          </Table.Td>
                          <Table.Td>
                            <Tooltip label={trace.sourceIp && trace.sourceIp !== "-" ? "Click to visualize IP route" : ""}>
                              <UnstyledButton 
                                onClick={() => openVisualizer(trace.sourceIp)}
                                disabled={!trace.sourceIp || trace.sourceIp === "-"}
                              >
                                <Text 
                                  size="sm" 
                                  ff="monospace" 
                                  c={trace.sourceIp && trace.sourceIp !== "-" ? "blue.6" : "inherit"}
                                  style={{ 
                                    textDecoration: trace.sourceIp && trace.sourceIp !== "-" ? "underline" : "none",
                                    textUnderlineOffset: '2px',
                                    textDecorationStyle: 'dotted'
                                  }}
                                >
                                  {trace.sourceIp || "-"}
                                </Text>
                              </UnstyledButton>
                            </Tooltip>
                          </Table.Td>
                          <Table.Td>
                            <Tooltip label={trace.requestUri || trace.path} multiline maw={400} withArrow>
                              <Text size="xs" c="dimmed" truncate="end" maw={200}>
                                {trace.path}
                              </Text>
                            </Tooltip>
                          </Table.Td>
                          <Table.Td>
                            <Badge 
                              variant="light" 
                              color={getDurationColor(trace.durationMs)}
                              radius="sm"
                            >
                              {trace.durationMs < 1
                                ? safeToFixed(trace.durationMs, 3)
                                : safeToFixed(trace.durationMs, 2)}
                              ms
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Badge 
                              variant="filled" 
                              color={getStatusColor(trace.status)}
                              leftSection={
                                isSuccessStatus(trace.status) ? (
                                  <IconCircleCheck size={14} />
                                ) : (
                                  <IconCircleX size={14} />
                                )
                              }
                            >
                              {trace.status}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Tooltip label={new Date(trace.timestamp).toLocaleString()}>
                              <Text size="xs" c="dimmed">
                                {new Date(trace.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                              </Text>
                            </Tooltip>
                          </Table.Td>
                          <Table.Td>
                            <ActionIcon variant="subtle" onClick={() => openDetails(trace)} title="View details">
                              <IconInfoCircle size={16} />
                            </ActionIcon>
                          </Table.Td>
                        </Table.Tr>
                      )))}
                      {filteredTraces.length === 0 && !isLoading && (
                        <Table.Tr>
                          <Table.Td colSpan={9}>
                            <Center py="xl">
                              <Stack align="center" gap="xs">
                                <IconSearch size={40} stroke={1.5} color="var(--mantine-color-dimmed)" />
                                <Text fw={500} c="dimmed">No traces found</Text>
                                <Text size="xs" c="dimmed">Try adjusting your search or filters</Text>
                              </Stack>
                            </Center>
                          </Table.Td>
                        </Table.Tr>
                      )}
                    </Table.Tbody>
                  </Table>
                </ScrollArea>

                {filteredTraces.length > PAGE_SIZE && (
                  <Group justify="space-between" align="center" pt="md" style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}>
                    <Text size="xs" c="dimmed">
                      Showing {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, filteredTraces.length)} of {filteredTraces.length}
                    </Text>
                    <Pagination total={totalPages} value={page} onChange={setPage} size="sm" radius="md" />
                  </Group>
                )}
              </Stack>
            </Card>

            <Paper withBorder p="xl" radius="md">
              <Stack align="center" gap="sm">
                <IconTimeline size={48} stroke={1.5} color="var(--mantine-color-blue-6)" />
                <Title order={3}>Live Trace Visualization</Title>
                <Text c="dimmed" ta="center" style={{ maxWidth: 500 }}>
                  Gateon is currently exporting telemetry via OpenTelemetry Protocol (OTLP).
                  For full visualization of spans and child relationships, we recommend
                  integrating with a dedicated store like Jaeger or Honeycomb.
                </Text>
                <Box mt="md" w="100%">
                   <Divider label="Visualization Preview" labelPosition="center" mb="xl" />
                   <Stack gap="xs" style={{ maxWidth: 800, margin: '0 auto' }}>
                      <Paper withBorder p="sm" radius="md" style={{ backgroundColor: "light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))", borderLeft: '4px solid var(--mantine-color-blue-6)' }}>
                         <Group justify="space-between">
                            <Group gap="xs">
                              <Badge size="sm" color="blue" variant="filled">GATEWAY</Badge>
                              <Text size="sm" fw={500}>ingress-request</Text>
                            </Group>
                            <Text size="xs" fw={700} c="blue">42.4ms</Text>
                         </Group>
                         <Box mt="xs" style={{ height: 6, backgroundColor: "light-dark(var(--mantine-color-gray-2), var(--mantine-color-dark-4))", borderRadius: 3, overflow: 'hidden' }}>
                            <Box style={{ width: '100%', height: '100%', backgroundColor: "var(--mantine-color-blue-6)" }} />
                         </Box>
                      </Paper>

                      <Paper withBorder p="sm" radius="md" ml={40} style={{ backgroundColor: "light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))", borderLeft: '4px solid var(--mantine-color-violet-6)' }}>
                         <Group justify="space-between">
                            <Group gap="xs">
                              <Badge size="sm" color="violet" variant="filled">AUTH-MW</Badge>
                              <Text size="sm" fw={500}>validate-token</Text>
                            </Group>
                            <Text size="xs" fw={700} c="violet">8.2ms</Text>
                         </Group>
                         <Box mt="xs" style={{ height: 6, backgroundColor: "light-dark(var(--mantine-color-gray-2), var(--mantine-color-dark-4))", borderRadius: 3, overflow: 'hidden' }}>
                            <Group justify="flex-start" h="100%" gap={0}>
                              <Box style={{ width: '10%', height: '100%' }} />
                              <Box style={{ width: '20%', height: '100%', backgroundColor: "var(--mantine-color-violet-6)" }} />
                            </Group>
                         </Box>
                      </Paper>

                      <Paper withBorder p="sm" radius="md" ml={80} style={{ backgroundColor: "light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))", borderLeft: '4px solid var(--mantine-color-teal-6)' }}>
                         <Group justify="space-between">
                            <Group gap="xs">
                              <Badge size="sm" color="teal" variant="filled">USER-SVC</Badge>
                              <Text size="sm" fw={500}>fetch-profile</Text>
                            </Group>
                            <Text size="xs" fw={700} c="teal">25.1ms</Text>
                         </Group>
                         <Box mt="xs" style={{ height: 6, backgroundColor: "light-dark(var(--mantine-color-gray-2), var(--mantine-color-dark-4))", borderRadius: 3, overflow: 'hidden' }}>
                            <Group justify="flex-start" h="100%" gap={0}>
                              <Box style={{ width: '35%', height: '100%' }} />
                              <Box style={{ width: '60%', height: '100%', backgroundColor: "var(--mantine-color-teal-6)" }} />
                            </Group>
                         </Box>
                      </Paper>
                   </Stack>
                </Box>
              </Stack>
            </Paper>
          </Stack>
        </Tabs.Panel>

        <Tabs.Panel value="history" pt="md">
          <Suspense fallback={<Skeleton height={320} radius="md" />}>
            <TraceHistoryPanel
              initialPeriod={urlPeriod(filters.from, filters.to)}
              onPeriodChange={(p) => setFilters({ from: p.from.toISOString(), to: p.to.toISOString() })}
            />
          </Suspense>
        </Tabs.Panel>

        <Tabs.Panel value="archive" pt="md">
          <Suspense fallback={<Skeleton height={320} radius="md" />}>
            <TraceArchivePanel onViewHour={viewHour} />
          </Suspense>
        </Tabs.Panel>
      </Tabs>

      <TraceVisualizer 
        opened={visualizerOpened} 
        onClose={() => setVisualizerOpened(false)} 
        targetIp={selectedIp || ""} 
      />

      <TraceDetailsModal
        traceId={selectedTraceId}
        timestamp={selectedTraceTs}
        opened={detailsOpened}
        onClose={() => setDetailsOpened(false)}
      />
    </Stack>
  );
}
