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
} from "@mantine/core";
import {
  IconSearch,
  IconRefresh,
  IconExternalLink,
  IconTimeline,
  IconCircleCheck,
  IconCircleX,
} from "@tabler/icons-react";
import { useState, useMemo, useTransition } from "react";

import { useTraces } from "../hooks/useGateon";
import TraceVisualizer from "../components/Diagnostics/TraceVisualizer";

const PAGE_SIZE = 20;

export default function TracesPage() {
  const { data: traces = [], isLoading, refetch } = useTraces();
  const [search, setSearch] = useState("");
  const [deferredSearch, setDeferredSearch] = useState("");
  const [routeFilter, setRouteFilter] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [isPending, startTransition] = useTransition();

  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [visualizerOpened, setVisualizerOpened] = useState(false);

  const openVisualizer = (ip: string) => {
    if (!ip || ip === "-" || ip === "127.0.0.1") return;
    setSelectedIp(ip);
    setVisualizerOpened(true);
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
          <Title order={2}>Distributed Tracing</Title>
          <Text c="dimmed">
            Monitor and visualize end-to-end request flows across your
            microservices.
          </Text>
        </Stack>
        <Group>
          <Button
            leftSection={<IconRefresh size={16} />}
            variant="light"
            loading={isLoading}
            onClick={() => refetch()}
          >
            Refresh
          </Button>
          <Tooltip label="Open in Jaeger">
            <ActionIcon variant="light" color="blue" size="lg">
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
            <Table highlightOnHover verticalSpacing="sm" style={{ opacity: isPending ? 0.7 : 1, transition: 'opacity 0.2s' }}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>ID</Table.Th>
                  <Table.Th>Operation</Table.Th>
                  <Table.Th>Service</Table.Th>
                  <Table.Th>Source IP</Table.Th>
                  <Table.Th>Path</Table.Th>
                  <Table.Th>Duration</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Timestamp</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {paginatedTraces.map((trace) => (
                  <Table.Tr key={trace.id}>
                    <Table.Td>
                      <Code color="blue.1" c="blue.8">
                        {trace.id}
                      </Code>
                    </Table.Td>
                    <Table.Td>
                      <Text fw={500}>{trace.operation_name}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light">{trace.service_name}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Tooltip label={trace.source_ip && trace.source_ip !== "-" ? "Click to visualize IP route" : ""}>
                        <Text 
                          size="sm" 
                          ff="monospace" 
                          style={{ 
                            cursor: trace.source_ip && trace.source_ip !== "-" ? "pointer" : "default",
                            color: trace.source_ip && trace.source_ip !== "-" ? "var(--mantine-color-blue-6)" : "inherit"
                          }}
                          onClick={() => openVisualizer(trace.source_ip)}
                        >
                          {trace.source_ip || "-"}
                        </Text>
                      </Tooltip>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed">
                        {trace.path}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {trace.duration_ms < 1
                        ? trace.duration_ms.toFixed(3)
                        : trace.duration_ms.toFixed(2)}
                      ms
                    </Table.Td>
                    <Table.Td>
                      {trace.status === "success" ? (
                        <IconCircleCheck color="green" size={20} />
                      ) : (
                        <IconCircleX color="red" size={20} />
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs">{new Date(trace.timestamp).toLocaleString()}</Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
                {filteredTraces.length === 0 && !isLoading && (
                  <Table.Tr>
                    <Table.Td colSpan={8} style={{ textAlign: "center" }}>
                      <Text c="dimmed">No traces found.</Text>
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
          <Box mt="md">
             <Divider label="Visualization Preview" labelPosition="center" mb="xl" />
             <Stack gap="xs" style={{ minWidth: 600 }}>
                <Paper withBorder p="xs" style={{ backgroundColor: "rgba(0,0,0,0.02)" }}>
                   <Group gap="xs">
                      <Badge size="xs" color="blue">GATEWAY</Badge>
                      <div style={{ flex: 1, height: 8, backgroundColor: "#339af0", borderRadius: 4 }} />
                      <Text size="xs">42ms</Text>
                   </Group>
                </Paper>
                <Paper withBorder p="xs" ml={40} style={{ backgroundColor: "rgba(0,0,0,0.02)" }}>
                   <Group gap="xs">
                      <Badge size="xs" color="violet">AUTH-MW</Badge>
                      <div style={{ flex: 0.2, height: 8, backgroundColor: "#7950f2", borderRadius: 4 }} />
                      <Text size="xs">8ms</Text>
                   </Group>
                </Paper>
                <Paper withBorder p="xs" ml={80} style={{ backgroundColor: "rgba(0,0,0,0.02)" }}>
                   <Group gap="xs">
                      <Badge size="xs" color="teal">USER-SVC</Badge>
                      <div style={{ flex: 0.6, height: 8, backgroundColor: "#0ca678", borderRadius: 4 }} />
                      <Text size="xs">25ms</Text>
                   </Group>
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
    </Stack>
  );
}
