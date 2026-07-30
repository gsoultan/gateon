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
  Tabs,
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
import { usePermissions } from "../../hooks/usePermissions";

const PAGE_SIZE = 15;

export function ThreatExplorerTab() {
  const { canWrite } = usePermissions();
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string | null>("all");
  const [mitigatedFilter, setMitigatedFilter] = useState<string | null>("detected");
  const [mitigationSubTab, setMitigationSubTab] = useState<string | null>("user");
  const [page, setPage] = useState(1);

  const { data, isLoading, error, refetch } = useSecurityThreats({
    limit: PAGE_SIZE,
    offset: (page - 1) * PAGE_SIZE,
    search,
    category: categoryFilter || "all",
    status: (mitigatedFilter === "mitigated") 
      ? (mitigationSubTab === "user" ? "user_mitigated" : "ip_mitigated")
      : (mitigatedFilter || "all"),
  });

  const density = useTableDensity();
  const removeMitigation = useRemoveMitigation();
  const [unmitigating, setUnmitigating] = useState<string | null>(null);
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const [traceIp, setTraceIp] = useState<string>("");
  const [traceOpened, { open: openTrace, close: closeTrace }] = useDisclosure(false);

  const threats = data?.threats || [];
  const totalCount = data?.totalCount || 0;

  const categories = useMemo(() => {
    if (!threats) return ["all"];
    const cats = new Set(threats.map((t) => t.category).filter((c): c is string => !!c));
    return ["all", ...Array.from(cats)];
  }, [threats]);

  // Reset to the first page whenever the search or filters change
  useEffect(() => {
    setPage(1);
  }, [search, categoryFilter, mitigatedFilter]);

  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  const getThreatIcon = (type: string, category?: string) => {
    const t = type.toLowerCase();
    const cat = (category || "").toLowerCase();
    
    if (t.includes('waf') || t.includes('sqli') || t.includes('xss') || cat === 'injection') return <IconShieldLock size={16} />;
    if (t.includes('bot') || t.includes('scanner') || cat === 'scanner') return <IconRobot size={16} />;
    if (t.includes('brute') || t.includes('impossible_travel')) return <IconUsers size={16} />;
    if (t.includes('exploit') || t.includes('rce') || t.includes('lfi') || cat === 'malware') return <IconBug size={16} />;
    if (cat === 'dlp' || t.includes('leak')) return <IconShieldCheck size={16} />;
    if (cat === 'dos' || t.includes('ddos') || t.includes('flood')) return <IconBolt size={16} />;
    return <IconAlertTriangle size={16} />;
  };

  const handleUnmitigate = async (e: React.MouseEvent, threat: Anomaly) => {
    e.stopPropagation();
    const id = threat.source;
    setUnmitigating(id);
    try {
      await removeMitigation.mutateAsync({ source: threat.source, ja4h: threat.ja4h });
      notifications.show({
        title: 'Mitigation Removed',
        message: `Mitigation for ${threat.source} has been removed.`,
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
      <Group justify="space-between" align="flex-end">
        <Tabs value={mitigatedFilter} onChange={setMitigatedFilter} variant="pills" radius="md">
          <Tabs.List>
            <Tabs.Tab value="detected" leftSection={<IconAlertTriangle size={16} />}>Active Threats</Tabs.Tab>
            <Tabs.Tab value="mitigated" leftSection={<IconShieldCheck size={16} />}>Mitigated List</Tabs.Tab>
            <Tabs.Tab value="all">Historical Logs</Tabs.Tab>
          </Tabs.List>
        </Tabs>

        {mitigatedFilter === "mitigated" && (
          <Tabs value={mitigationSubTab} onChange={setMitigationSubTab} variant="outline" radius="md">
            <Tabs.List>
              <Tabs.Tab value="user" leftSection={<IconUserCheck size={16} />}>User Mitigations</Tabs.Tab>
              <Tabs.Tab value="ip" leftSection={<IconShieldLock size={16} />}>IP Mitigations</Tabs.Tab>
            </Tabs.List>
          </Tabs>
        )}
      </Group>

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
                <Table.Th>URL</Table.Th>
                <Table.Th>Type / Category</Table.Th>
                <Table.Th>Severity</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {threats.length > 0 ? (
                threats.map((threat, index) => (
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
                      <Tooltip label={threat.request_uri || '/'}>
                        <Text size="xs" c="dimmed" style={{ maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {threat.request_uri || '/'}
                        </Text>
                      </Tooltip>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="sm" wrap="nowrap">
                        <ThemeIcon 
                          variant="light" 
                          color={getSeverityColor(threat.severity)} 
                          size="md" 
                          radius="md"
                        >
                          {getThreatIcon(threat.type, threat.category)}
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
                          <Group gap={4}>
                            <Badge size="xs" variant="light" color="gray">{threat.category || 'N/A'}</Badge>
                            <Text size="xs" c="dimmed" truncate maw={200}>{threat.description}</Text>
                          </Group>
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
                              onClick={(e) => handleUnmitigate(e, threat)}
                              loading={unmitigating === threat.source}
                              disabled={!canWrite}
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
                  <Table.Td colSpan={7}>
                    <Text ta="center" py="xl" c="dimmed">No threats match your filters.</Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>

        {totalCount > PAGE_SIZE && (
          <Group justify="space-between" align="center" mt="md">
            <Text size="xs" c="dimmed">
              Showing {(page - 1) * PAGE_SIZE + 1}–
              {Math.min(page * PAGE_SIZE, totalCount)} of{" "}
              {totalCount}
            </Text>
            <Pagination
              total={totalPages}
              value={page}
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
