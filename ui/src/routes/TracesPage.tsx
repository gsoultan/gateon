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
  HoverCard,
  UnstyledButton,
  Skeleton,
  Center,
  Modal,
  Grid,
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
  IconArrowRight,
  IconInfoCircle,
} from "@tabler/icons-react";
import { useState, useMemo, useTransition } from "react";

import { useTraces } from "../hooks/useGateon";
import type { Trace } from "../hooks/useGateon";
import TraceVisualizer from "../components/Diagnostics/TraceVisualizer";

const PAGE_SIZE = 20;

const getStatusColor = (status: string) => {
  const code = parseInt(status);
  if (isNaN(code)) {
    return status === "success" ? "green" : "red";
  }
  if (code >= 200 && code < 300) return "green";
  if (code >= 300 && code < 400) return "blue";
  if (code >= 400 && code < 500) return "orange";
  if (code >= 500) return "red";
  return "gray";
};

const getDurationColor = (duration: number) => {
  if (duration < 50) return "teal";
  if (duration < 200) return "blue";
  if (duration < 500) return "orange";
  return "red";
};

export default function TracesPage() {
  const { data: traces = [], isLoading, refetch } = useTraces();
  const [search, setSearch] = useState("");
  const [deferredSearch, setDeferredSearch] = useState("");
  const [routeFilter, setRouteFilter] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [isPending, startTransition] = useTransition();

  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [visualizerOpened, setVisualizerOpened] = useState(false);
  const [selectedTrace, setSelectedTrace] = useState<Trace | null>(null);
  const [detailsOpened, setDetailsOpened] = useState(false);

  const openVisualizer = (ip: string) => {
    if (!ip || ip === "-" || ip === "127.0.0.1") return;
    setSelectedIp(ip);
    setVisualizerOpened(true);
  };

  const openDetails = (trace: Trace) => {
    setSelectedTrace(trace);
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
        t.operation_name.toLowerCase().includes(lower) ||
        t.service_name.toLowerCase().includes(lower) ||
        t.source_ip.toLowerCase().includes(lower) ||
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
            {traces.length > 0 && (
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
          <Tooltip label="Open in Jaeger">
            <ActionIcon variant="light" color="blue" size="lg" component="a" href="#" onClick={(e) => e.preventDefault()}>
              <IconExternalLink size={20} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

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
              }}
            >
              Clear filters
            </Button>
          </Group>

          <ScrollArea>
            <Table 
              highlightOnHover 
              verticalSpacing="sm" 
              striped
              style={{ opacity: isPending ? 0.7 : 1, transition: 'opacity 0.2s' }}
            >
              <Table.Thead>
                <Table.Tr>
                  <Table.Th><Group gap={4}><IconFingerprint size={14} /> ID</Group></Table.Th>
                  <Table.Th>Method</Table.Th>
                  <Table.Th>Operation</Table.Th>
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
                {isLoading ? (
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
                      <Text fw={600} size="sm">{trace.operation_name}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="dot" color="blue" size="sm">{trace.service_name}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Tooltip label={trace.source_ip && trace.source_ip !== "-" ? "Click to visualize IP route" : ""}>
                        <UnstyledButton 
                          onClick={() => openVisualizer(trace.source_ip)}
                          disabled={!trace.source_ip || trace.source_ip === "-"}
                        >
                          <Text 
                            size="sm" 
                            ff="monospace" 
                            c={trace.source_ip && trace.source_ip !== "-" ? "blue.6" : "inherit"}
                            style={{ 
                              textDecoration: trace.source_ip && trace.source_ip !== "-" ? "underline" : "none",
                              textUnderlineOffset: '2px',
                              textDecorationStyle: 'dotted'
                            }}
                          >
                            {trace.source_ip || "-"}
                          </Text>
                        </UnstyledButton>
                      </Tooltip>
                    </Table.Td>
                    <Table.Td>
                      <Tooltip label={trace.request_uri || trace.path} multiline maw={400} withArrow>
                        <Text size="xs" c="dimmed" truncate="end" maw={200}>
                          {trace.path}
                        </Text>
                      </Tooltip>
                    </Table.Td>
                    <Table.Td>
                      <Badge 
                        variant="light" 
                        color={getDurationColor(trace.duration_ms)}
                        radius="sm"
                      >
                        {trace.duration_ms < 1
                          ? trace.duration_ms.toFixed(3)
                          : trace.duration_ms.toFixed(2)}
                        ms
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Badge 
                        variant="filled" 
                        color={getStatusColor(trace.status)}
                        leftSection={
                          trace.status === "success" || (parseInt(trace.status) >= 200 && parseInt(trace.status) < 400) ? (
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
                    <Table.Td colSpan={10}>
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
                <Paper withBorder p="sm" radius="md" style={{ backgroundColor: "var(--mantine-color-gray-0)", borderLeft: '4px solid var(--mantine-color-blue-6)' }}>
                   <Group justify="space-between">
                      <Group gap="xs">
                        <Badge size="sm" color="blue" variant="filled">GATEWAY</Badge>
                        <Text size="sm" fw={500}>ingress-request</Text>
                      </Group>
                      <Text size="xs" fw={700} c="blue">42.4ms</Text>
                   </Group>
                   <Box mt="xs" style={{ height: 6, backgroundColor: "var(--mantine-color-gray-2)", borderRadius: 3, overflow: 'hidden' }}>
                      <Box style={{ width: '100%', height: '100%', backgroundColor: "var(--mantine-color-blue-6)" }} />
                   </Box>
                </Paper>

                <Paper withBorder p="sm" radius="md" ml={40} style={{ backgroundColor: "var(--mantine-color-gray-0)", borderLeft: '4px solid var(--mantine-color-violet-6)' }}>
                   <Group justify="space-between">
                      <Group gap="xs">
                        <Badge size="sm" color="violet" variant="filled">AUTH-MW</Badge>
                        <Text size="sm" fw={500}>validate-token</Text>
                      </Group>
                      <Text size="xs" fw={700} c="violet">8.2ms</Text>
                   </Group>
                   <Box mt="xs" style={{ height: 6, backgroundColor: "var(--mantine-color-gray-2)", borderRadius: 3, overflow: 'hidden' }}>
                      <Group justify="flex-start" h="100%" gap={0}>
                        <Box style={{ width: '10%', height: '100%' }} />
                        <Box style={{ width: '20%', height: '100%', backgroundColor: "var(--mantine-color-violet-6)" }} />
                      </Group>
                   </Box>
                </Paper>

                <Paper withBorder p="sm" radius="md" ml={80} style={{ backgroundColor: "var(--mantine-color-gray-0)", borderLeft: '4px solid var(--mantine-color-teal-6)' }}>
                   <Group justify="space-between">
                      <Group gap="xs">
                        <Badge size="sm" color="teal" variant="filled">USER-SVC</Badge>
                        <Text size="sm" fw={500}>fetch-profile</Text>
                      </Group>
                      <Text size="xs" fw={700} c="teal">25.1ms</Text>
                   </Group>
                   <Box mt="xs" style={{ height: 6, backgroundColor: "var(--mantine-color-gray-2)", borderRadius: 3, overflow: 'hidden' }}>
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
      <TraceVisualizer 
        opened={visualizerOpened} 
        onClose={() => setVisualizerOpened(false)} 
        targetIp={selectedIp || ""} 
      />

      <Modal
        opened={detailsOpened}
        onClose={() => setDetailsOpened(false)}
        title={<Text fw={700}>Trace Details</Text>}
        size="lg"
      >
        {selectedTrace && (
          <Stack gap="md">
            <Paper withBorder p="sm" bg="gray.0">
              <Group justify="space-between">
                <Text size="sm" fw={700} c="dimmed">TRACE ID</Text>
                <Code color="blue.1" c="blue.8">{selectedTrace.id}</Code>
              </Group>
            </Paper>

            <Grid columns={2}>
              <Grid.Col span={1}>
                <Stack gap={4}>
                  <Text size="xs" fw={700} c="dimmed">METHOD</Text>
                  <Badge variant="filled" color="blue">{selectedTrace.method || "N/A"}</Badge>
                </Stack>
              </Grid.Col>
              <Grid.Col span={1}>
                <Stack gap={4}>
                  <Text size="xs" fw={700} c="dimmed">STATUS</Text>
                  <Badge 
                    variant="filled" 
                    color={getStatusColor(selectedTrace.status)}
                  >
                    {selectedTrace.status}
                  </Badge>
                </Stack>
              </Grid.Col>
            </Grid>

            <Stack gap={4}>
              <Text size="xs" fw={700} c="dimmed">REQUEST URI</Text>
              <Paper withBorder p="xs" bg="gray.0">
                <Text size="sm" style={{ wordBreak: 'break-all' }}>
                  {selectedTrace.request_uri || selectedTrace.path}
                </Text>
              </Paper>
            </Stack>

            <Divider />

            <Grid columns={2}>
              <Grid.Col span={1}>
                <Stack gap={4}>
                  <Text size="xs" fw={700} c="dimmed">SOURCE IP</Text>
                  <Text size="sm" ff="monospace">{selectedTrace.source_ip || "-"}</Text>
                </Stack>
              </Grid.Col>
              <Grid.Col span={1}>
                <Stack gap={4}>
                  <Text size="xs" fw={700} c="dimmed">DURATION</Text>
                  <Text size="sm">{selectedTrace.duration_ms.toFixed(3)} ms</Text>
                </Stack>
              </Grid.Col>
            </Grid>

            <Divider />

            <Stack gap={4}>
              <Text size="xs" fw={700} c="dimmed">USER AGENT</Text>
              <Text size="sm" c="dimmed" style={{ wordBreak: 'break-all' }}>
                {selectedTrace.user_agent || "N/A"}
              </Text>
            </Stack>

            <Stack gap={4}>
              <Text size="xs" fw={700} c="dimmed">REFERER</Text>
              <Text size="sm" c="dimmed" style={{ wordBreak: 'break-all' }}>
                {selectedTrace.referer || "N/A"}
              </Text>
            </Stack>

            <Stack gap={4}>
              <Text size="xs" fw={700} c="dimmed">TIMESTAMP</Text>
              <Text size="sm">{new Date(selectedTrace.timestamp).toLocaleString()}</Text>
            </Stack>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
