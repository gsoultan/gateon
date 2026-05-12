import React, { useMemo, useState } from "react";
import {
  Card,
  Group,
  Stack,
  Text,
  Title,
  Badge,
  Table,
  ScrollArea,
  Paper,
  ThemeIcon,
  SimpleGrid,
  Loader,
  Box,
  Alert,
  Tooltip,
  TextInput,
  Select,
} from "@mantine/core";
import {
  DonutChart,
  BarChart,
} from "@mantine/charts";
import { useDisclosure } from "@mantine/hooks";
import {
  IconShieldCheck,
  IconShieldExclamation,
  IconWorld,
  IconClock,
  IconAlertTriangle,
  IconSearch,
  IconFilter,
  IconBug,
  IconLock,
  IconShieldOff,
} from "@tabler/icons-react";
import { useSecurityThreats, useRemoveMitigation } from "../hooks/useGateon";
import type { Anomaly } from "../types/gateon";
import { SecurityAnomalyModal } from "../components/SecurityAnomalyModal";

const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const color =
    severity === "critical"
      ? "red"
      : severity === "high"
      ? "orange"
      : severity === "medium"
      ? "yellow"
      : "blue";
  return (
    <Badge color={color} variant="filled" size="sm">
      {severity.toUpperCase()}
    </Badge>
  );
};

export default function MitigatedAttacksPage() {
  const { data, isLoading, error } = useSecurityThreats(1000); // Get more for better stats
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  
  const [confirmOpened, { open: openConfirm, close: closeConfirm }] = useDisclosure(false);
  const [ipToRemove, setIpToRemove] = useState<string | null>(null);
  
  const removeMitigation = useRemoveMitigation();
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string | null>("all");

  const mitigatedAttacks = useMemo(() => {
    if (!data?.threats) return [];
    return data.threats.filter(t => t.mitigated);
  }, [data?.threats]);

  const filteredAttacks = useMemo(() => {
    return mitigatedAttacks.filter(attack => {
      const matchesSearch = 
        attack.source.toLowerCase().includes(search.toLowerCase()) ||
        attack.description.toLowerCase().includes(search.toLowerCase()) ||
        attack.type.toLowerCase().includes(search.toLowerCase());
      
      const matchesCategory = 
        categoryFilter === "all" || 
        attack.category === categoryFilter;

      return matchesSearch && matchesCategory;
    }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [mitigatedAttacks, search, categoryFilter]);

  const categoryStats = useMemo(() => {
    const stats: Record<string, number> = {};
    mitigatedAttacks.forEach(a => {
      const cat = a.category || "general";
      stats[cat] = (stats[cat] || 0) + 1;
    });
    return Object.entries(stats).map(([name, value]) => ({
      name,
      value,
      color: getCategoryColor(name),
    }));
  }, [mitigatedAttacks]);

  const timeSeriesStats = useMemo(() => {
    const stats: Record<string, number> = {};
    // Group by hour for the last 24 hours
    const now = new Date();
    for (let i = 0; i < 24; i++) {
      const d = new Date(now.getTime() - i * 3600000);
      const key = d.getHours() + ":00";
      stats[key] = 0;
    }

    mitigatedAttacks.forEach(a => {
      const d = new Date(a.timestamp);
      if (now.getTime() - d.getTime() < 86400000) {
        const key = d.getHours() + ":00";
        if (stats[key] !== undefined) {
          stats[key]++;
        }
      }
    });

    return Object.entries(stats).reverse().map(([time, attacks]) => ({
      time,
      attacks,
    }));
  }, [mitigatedAttacks]);

  if (isLoading) {
    return (
      <Box p="xl" style={{ display: "flex", justifyContent: "center" }}>
        <Loader size="xl" />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert color="red" title="Error" icon={<IconAlertTriangle />}>
        Failed to load security threats: {(error as Error).message}
      </Alert>
    );
  }

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Stack gap={0}>
          <Title order={2}>Mitigated Attacks</Title>
          <Text c="dimmed" size="sm">
            Detailed list and statistics of attacks successfully blocked by Gateon.
          </Text>
        </Stack>
        <Badge size="lg" color="teal" leftSection={<IconShieldCheck size={14} />}>
          {mitigatedAttacks.length} Total Mitigations
        </Badge>
      </Group>

      <SimpleGrid cols={{ base: 1, md: 3 }} spacing="lg">
        <Paper withBorder p="md" radius="md">
          <Text size="xs" c="dimmed" fw={700} mb="md">ATTACKS BY CATEGORY</Text>
          <Box h={200}>
            {categoryStats.length > 0 ? (
               <DonutChart 
                data={categoryStats} 
                withLabelsLine 
                labelsType="percent" 
                withLabels 
                size={160}
                thickness={20}
              />
            ) : (
              <Text c="dimmed" ta="center" pt="xl">No data available</Text>
            )}
          </Box>
        </Paper>

        <Paper withBorder p="md" radius="md" style={{ gridColumn: "span 2" }}>
          <Text size="xs" c="dimmed" fw={700} mb="md">MITIGATIONS OVER TIME (LAST 24H)</Text>
          <Box h={200}>
             <BarChart
              h={200}
              data={timeSeriesStats}
              dataKey="time"
              series={[{ name: 'attacks', color: 'teal.6' }]}
              tickLine="none"
              gridAxis="xy"
            />
          </Box>
        </Paper>
      </SimpleGrid>

      <Card withBorder radius="md" p="md">
        <Stack gap="md">
          <Group justify="space-between">
            <Title order={4}>Attack History</Title>
            <Group>
              <TextInput
                placeholder="Search by IP, type..."
                leftSection={<IconSearch size={14} />}
                value={search}
                onChange={(e) => setSearch(e.currentTarget.value)}
                size="xs"
              />
              <Select
                placeholder="Category"
                leftSection={<IconFilter size={14} />}
                data={[
                  { value: "all", label: "All Categories" },
                  { value: "sqli", label: "SQL Injection" },
                  { value: "xss", label: "Cross-Site Scripting" },
                  { value: "rce", label: "Remote Code Execution" },
                  { value: "lfi", label: "Local File Inclusion" },
                  { value: "bot", label: "Bot Activity" },
                  { value: "geoip_block", label: "GeoIP Block" },
                  { value: "protocol", label: "Protocol Violation" },
                  { value: "general", label: "General" },
                ]}
                value={categoryFilter}
                onChange={setCategoryFilter}
                size="xs"
              />
            </Group>
          </Group>

          <ScrollArea h={500}>
            <Table verticalSpacing="sm" highlightOnHover>
              <Table.Thead bg="var(--mantine-color-default-hover)">
                <Table.Tr>
                  <Table.Th>Attack Type</Table.Th>
                  <Table.Th>Category</Table.Th>
                  <Table.Th>Severity</Table.Th>
                  <Table.Th>Source IP</Table.Th>
                  <Table.Th>Target URI</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Time</Table.Th>
                  <Table.Th>Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {filteredAttacks.length === 0 ? (
                  <Table.Tr>
                    <Table.Td colSpan={7}>
                      <Text ta="center" py="xl" c="dimmed">No mitigated attacks match your filters.</Text>
                    </Table.Td>
                  </Table.Tr>
                ) : (
                  filteredAttacks.map((attack, index) => (
                    <Table.Tr 
                      key={index} 
                      onClick={() => { setSelectedAnomaly(attack); open(); }}
                      style={{ cursor: 'pointer' }}
                    >
                      <Table.Td>
                        <Group gap="xs">
                          <ThemeIcon color="red" variant="light" size="sm">
                            <IconBug size={14} />
                          </ThemeIcon>
                          <Stack gap={0}>
                            <Text size="sm" fw={600}>{attack.type}</Text>
                            <Text size="xs" c="dimmed" lineClamp={1}>{attack.description}</Text>
                          </Stack>
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Badge variant="outline" size="xs">{attack.category || "general"}</Badge>
                      </Table.Td>
                      <Table.Td>
                        <SeverityBadge severity={attack.severity} />
                      </Table.Td>
                      <Table.Td>
                        <Group gap="xs">
                          {attack.country_code && (
                            <img 
                              src={`https://flagcdn.com/16x12/${attack.country_code.toLowerCase()}.png`} 
                              alt={attack.country_name}
                            />
                          )}
                          <Text size="sm" ff="monospace">{attack.source}</Text>
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Text size="xs" ff="monospace" lineClamp={1} title={attack.request_uri}>
                          {attack.request_uri || "/"}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Badge color="teal" variant="light" size="xs">{attack.action_taken || "blocked"}</Badge>
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4} wrap="nowrap">
                          <IconClock size={12} />
                          <Text size="xs">{new Date(attack.timestamp).toLocaleString()}</Text>
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Tooltip label="Remove mitigation (Allow IP)">
                          <ActionIcon 
                            color="red" 
                            variant="subtle" 
                            onClick={(e) => {
                              e.stopPropagation();
                              setIpToRemove(attack.source);
                              openConfirm();
                            }}
                            loading={removeMitigation.isPending && ipToRemove === attack.source}
                          >
                            <IconShieldOff size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Table.Td>
                    </Table.Tr>
                  ))
                )}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Stack>
      </Card>

      <SecurityAnomalyModal 
        anomaly={selectedAnomaly}
        opened={opened}
        onClose={close}
      />

      <Modal
        opened={confirmOpened}
        onClose={closeConfirm}
        title={<Text fw={700}>Confirm Mitigation Removal</Text>}
        centered
        size="sm"
      >
        <Stack gap="md">
          <Alert color="red" icon={<IconAlertTriangle size={16} />}>
            Are you sure you want to remove the mitigation for IP <b>{ipToRemove}</b>? 
            This will allow the IP to access your services again.
          </Alert>
          <Group justify="flex-end" gap="sm">
            <Button variant="default" onClick={closeConfirm}>Cancel</Button>
            <Button 
              color="red" 
              onClick={() => {
                if (ipToRemove) {
                  removeMitigation.mutate(ipToRemove, {
                    onSuccess: () => {
                      closeConfirm();
                      setIpToRemove(null);
                    }
                  });
                }
              }}
              loading={removeMitigation.isPending}
            >
              Confirm Removal
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}

function getCategoryColor(category: string): string {
  switch (category) {
    case "sqli": return "red.6";
    case "xss": return "orange.6";
    case "rce": return "grape.6";
    case "bot": return "indigo.6";
    case "geoip_block": return "blue.6";
    case "protocol": return "cyan.6";
    default: return "gray.6";
  }
}
