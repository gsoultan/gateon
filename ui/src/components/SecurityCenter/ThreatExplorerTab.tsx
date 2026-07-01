import React, { useEffect, useMemo, useState } from "react";
import {
  Card,
  Group,
  Stack,
  Text,
  Badge,
  Table,
  TextInput,
  Select,
  ActionIcon,
  Button,
  Loader,
  Alert,
  Tooltip,
  Center,
  Pagination,
  ThemeIcon,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconSearch,
  IconShieldCheck,
  IconMap2,
  IconAlertTriangle,
  IconRefresh,
  IconUserCheck,
  IconBrain,
  IconRobot,
  IconUsers,
  IconBug,
  IconShieldLock,
  IconBolt,
} from "@tabler/icons-react";
import { useSecurityThreats, useRemoveMitigation } from "../../hooks/useGateon";
import { useTableDensity } from "../../hooks/useTableDensity";
import { SecurityAnomalyModal } from "../SecurityAnomalyModal";
import TraceVisualizer from "../Diagnostics/TraceVisualizer";
import type { Anomaly } from "../../types/gateon";
import { format } from "date-fns";
import { getSeverityColor } from "../../utils/security";
import { notifications } from "@mantine/notifications";

const PAGE_SIZE = 15;

export function ThreatExplorerTab() {
  const { data, isLoading, error, refetch } = useSecurityThreats(1000);
  const density = useTableDensity();
  const removeMitigation = useRemoveMitigation();
  const [unmitigating, setUnmitigating] = useState<string | null>(null);
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const [traceIp, setTraceIp] = useState<string>("");
  const [traceOpened, { open: openTrace, close: closeTrace }] = useDisclosure(false);

  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string | null>("all");
  const [mitigatedFilter, setMitigatedFilter] = useState<string | null>("all");
  const [page, setPage] = useState(1);

  const filteredThreats = useMemo(() => {
    if (!data?.threats) return [];
    return data.threats
      .filter((t) => {
        const source = t.source || "";
        const description = t.description || "";
        const type = t.type || "";

        const matchesSearch =
          source.toLowerCase().includes(search.toLowerCase()) ||
          description.toLowerCase().includes(search.toLowerCase()) ||
          type.toLowerCase().includes(search.toLowerCase());

        const matchesCategory =
          categoryFilter === "all" || t.category === categoryFilter;

        const matchesMitigated =
          mitigatedFilter === "all" ||
          (mitigatedFilter === "mitigated" && t.mitigated) ||
          (mitigatedFilter === "detected" && !t.mitigated);

        return matchesSearch && matchesCategory && matchesMitigated;
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [data?.threats, search, categoryFilter, mitigatedFilter]);

  const categories = useMemo(() => {
    if (!data?.threats) return [];
    const cats = new Set(data.threats.map((t) => t.category).filter((c): c is string => !!c));
    return ["all", ...Array.from(cats)];
  }, [data?.threats]);

  // Reset to the first page whenever the filtered result set changes (new filter,
  // search term, or refreshed data) so the user never lands on an empty page.
  useEffect(() => {
    setPage(1);
  }, [search, categoryFilter, mitigatedFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredThreats.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pagedThreats = filteredThreats.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE,
  );

  const getThreatIcon = (type: string) => {
    const t = type.toLowerCase();
    if (t.includes('waf') || t.includes('sqli') || t.includes('xss')) return <IconShieldLock size={16} />;
    if (t.includes('bot') || t.includes('scanner')) return <IconRobot size={16} />;
    if (t.includes('brute') || t.includes('impossible_travel')) return <IconUsers size={16} />;
    if (t.includes('exploit') || t.includes('rce') || t.includes('lfi')) return <IconBug size={16} />;
    if (t.includes('entropy') || t.includes('fingerprint')) return <IconBolt size={16} />;
    return <IconAlertTriangle size={16} />;
  };

  const handleUnmitigate = async (e: React.MouseEvent, ip: string) => {
    e.stopPropagation();
    setUnmitigating(ip);
    try {
      await removeMitigation.mutateAsync(ip);
      notifications.show({
        title: 'Mitigation Removed',
        message: `IP ${ip} has been unmitigated.`,
        color: 'green',
      });
      refetch();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to remove mitigation';
      notifications.show({
        title: 'Error',
        message: message,
        color: 'red',
      });
    } finally {
      setUnmitigating(null);
    }
  };

  const handleRowClick = (anomaly: Anomaly) => {
    setSelectedAnomaly(anomaly);
    open();
  };

  const handleTraceClick = (e: React.MouseEvent, ip: string) => {
    e.stopPropagation();
    setTraceIp(ip);
    openTrace();
  };

  if (isLoading) {
    return (
      <Center py="xl">
        <Loader size="lg" />
      </Center>
    );
  }

  if (error) {
    return (
      <Alert color="red" title="Error" icon={<IconAlertTriangle />}>
        Failed to load threats: {(error as Error).message}
      </Alert>
    );
  }

  return (
    <Stack gap="md">
      <Card withBorder radius="md" p="md">
        <Group justify="space-between" mb="md">
          <Group gap="sm" grow style={{ flex: 1 }}>
            <TextInput
              placeholder="Search by IP, type or description..."
              leftSection={<IconSearch size={16} />}
              value={search}
              onChange={(e) => setSearch(e.currentTarget.value)}
            />
            <Select
              placeholder="Category"
              data={categories.map(c => ({ value: c, label: c === 'all' ? 'All Categories' : c.toUpperCase() }))}
              value={categoryFilter}
              onChange={setCategoryFilter}
            />
            <Select
              placeholder="Status"
              data={[
                { value: "all", label: "All Status" },
                { value: "mitigated", label: "Mitigated Only" },
                { value: "detected", label: "Detected Only" },
              ]}
              value={mitigatedFilter}
              onChange={setMitigatedFilter}
            />
          </Group>
          <Button variant="light" leftSection={<IconRefresh size={16} />} onClick={() => refetch()}>
            Refresh
          </Button>
        </Group>

        <Table.ScrollContainer minWidth={800}>
          <Table {...density} highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Timestamp</Table.Th>
                <Table.Th>Source</Table.Th>
                <Table.Th>Type / Category</Table.Th>
                <Table.Th>Severity</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {filteredThreats.length > 0 ? (
                pagedThreats.map((threat, index) => (
                  <Table.Tr key={index} style={{ cursor: 'pointer' }} onClick={() => handleRowClick(threat)}>
                    <Table.Td>
                      <Text size="xs" c="dimmed">
                        {format(new Date(threat.timestamp), 'MMM d, HH:mm:ss')}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        <Text size="sm" fw={700} ff="monospace">{threat.source}</Text>
                        <Tooltip label="Trace Visualizer">
                          <ActionIcon variant="subtle" size="xs" onClick={(e) => handleTraceClick(e, threat.source)}>
                            <IconMap2 size={12} />
                          </ActionIcon>
                        </Tooltip>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="sm" wrap="nowrap">
                        <ThemeIcon 
                          variant="light" 
                          color={getSeverityColor(threat.severity)} 
                          size="md" 
                          radius="md"
                        >
                          {getThreatIcon(threat.type)}
                        </ThemeIcon>
                        <Stack gap={0}>
                          <Group gap={4}>
                            <Text size="sm" fw={600}>{threat.type.replace(/_/g, ' ').toUpperCase()}</Text>
                            {threat.recommendation?.includes("Smart Insight:") && (
                              <Tooltip label="Deep intelligence analysis available">
                                <Badge size="xs" color="blue" variant="outline" p={4} style={{ borderStyle: 'dashed' }}>
                                  <IconBrain size={10} />
                                </Badge>
                              </Tooltip>
                            )}
                          </Group>
                          <Text size="xs" c="dimmed">{threat.category || 'N/A'}</Text>
                        </Stack>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Badge color={getSeverityColor(threat.severity)} variant="filled" size="sm">
                        {threat.severity}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      {threat.mitigated ? (
                        <Badge color="teal" leftSection={<IconShieldCheck size={12} />} variant="light">
                          Mitigated
                        </Badge>
                      ) : (
                        <Badge color="orange" leftSection={<IconAlertTriangle size={12} />} variant="light">
                          Detected
                        </Badge>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs">
                        <Button variant="subtle" size="xs" onClick={() => handleRowClick(threat)}>
                          Details
                        </Button>
                        {threat.mitigated && (
                          <Tooltip label="Unmitigate / Whitelist">
                            <ActionIcon 
                              variant="light" 
                              color="blue" 
                              size="sm" 
                              onClick={(e) => handleUnmitigate(e, threat.source)}
                              loading={unmitigating === threat.source}
                            >
                              <IconUserCheck size={14} />
                            </ActionIcon>
                          </Tooltip>
                        )}
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))
              ) : (
                <Table.Tr>
                  <Table.Td colSpan={6}>
                    <Text ta="center" py="xl" c="dimmed">No threats match your filters.</Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>

        {filteredThreats.length > PAGE_SIZE && (
          <Group justify="space-between" align="center" mt="md">
            <Text size="xs" c="dimmed">
              Showing {(currentPage - 1) * PAGE_SIZE + 1}–
              {Math.min(currentPage * PAGE_SIZE, filteredThreats.length)} of{" "}
              {filteredThreats.length}
            </Text>
            <Pagination
              total={totalPages}
              value={currentPage}
              onChange={setPage}
              size="sm"
              radius="md"
            />
          </Group>
        )}
      </Card>

      <SecurityAnomalyModal
        anomaly={selectedAnomaly}
        opened={opened}
        onClose={close}
      />

      <TraceVisualizer
        opened={traceOpened}
        onClose={closeTrace}
        targetIp={traceIp}
      />
    </Stack>
  );
}
