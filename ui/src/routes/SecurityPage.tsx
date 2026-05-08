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
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconShieldExclamation,
  IconFingerprint,
  IconWorld,
  IconClock,
  IconInfoCircle,
  IconAlertTriangle,
  IconShieldCheck,
  IconLock,
  IconMap2,
} from "@tabler/icons-react";
import { useSecurityThreats } from "../hooks/useGateon";
import type { Anomaly } from "../types/gateon";
import { SecurityAnomalyModal } from "../components/SecurityAnomalyModal";
import TraceVisualizer from "../components/Diagnostics/TraceVisualizer";

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

export default function SecurityPage() {
  const { data, isLoading, error } = useSecurityThreats(100);
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const [traceIp, setTraceIp] = useState<string>("");
  const [traceOpened, { open: openTrace, close: closeTrace }] = useDisclosure(false);

  const handleRowClick = (anomaly: Anomaly) => {
    setSelectedAnomaly(anomaly);
    open();
  };

  const handleTraceClick = (e: React.MouseEvent, ip: string) => {
    e.stopPropagation();
    setTraceIp(ip);
    openTrace();
  };

  const sortedThreats = useMemo(() => {
    if (!data?.threats) return [];
    return [...data.threats].sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      if (timeA !== timeB) return timeB - timeA;
      return a.type.localeCompare(b.type) || a.source.localeCompare(b.source);
    });
  }, [data?.threats]);

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

  const threats = sortedThreats;
  const mitigatedIpsCount = new Set(threats.filter(t => t.mitigated).map(t => t.source)).size;

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Stack gap={0}>
          <Title order={2}>Security Insights</Title>
          <Text c="dimmed" size="sm">
            Recent security anomalies and potential threats detected by the system.
          </Text>
        </Stack>
        <Group>
          <Badge size="lg" color={threats.length > 0 ? "orange" : "teal"} leftSection={threats.length > 0 ? <IconShieldExclamation size={14} /> : <IconShieldCheck size={14} />}>
            {threats.length} Events Detected
          </Badge>
          <Tooltip label="Advanced protections are configured in Settings > Global WAF">
            <Badge variant="outline" color="blue" leftSection={<IconInfoCircle size={14} />}>
              Advanced Protection Active
            </Badge>
          </Tooltip>
        </Group>
      </Group>

      <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }}>
        <Paper withBorder p="md" radius="md">
          <Group justify="space-between">
            <Text size="xs" c="dimmed" fw={700}>THREAT LEVEL</Text>
            <IconShieldExclamation size={16} color="var(--mantine-color-red-6)" />
          </Group>
          <Title order={3} mt="xs">
            {threats.some(t => t.severity === "critical" || t.severity === "high") ? "High" : threats.length > 0 ? "Elevated" : "Normal"}
          </Title>
        </Paper>
        <Paper withBorder p="md" radius="md">
          <Group justify="space-between">
            <Text size="xs" c="dimmed" fw={700}>ADVANCED DETECTION</Text>
            <IconShieldCheck size={16} color="var(--mantine-color-teal-6)" />
          </Group>
          <Group gap={4} mt="xs">
            <Tooltip label="Data Loss Prevention"><Badge size="xs" variant="dot">DLP</Badge></Tooltip>
            <Tooltip label="Ransomware Protection"><Badge size="xs" variant="dot">RANSOM</Badge></Tooltip>
            <Tooltip label="Bot Management"><Badge size="xs" variant="dot">BOT</Badge></Tooltip>
            <Tooltip label="API Schema Validation"><Badge size="xs" variant="dot">API</Badge></Tooltip>
          </Group>
        </Paper>
        <Paper withBorder p="md" radius="md">
          <Group justify="space-between">
            <Text size="xs" c="dimmed" fw={700}>UNIQUE SOURCES</Text>
            <IconWorld size={16} color="var(--mantine-color-blue-6)" />
          </Group>
          <Title order={3} mt="xs">
            {new Set(threats.map(t => t.source)).size} IPs
          </Title>
        </Paper>
        <Paper withBorder p="md" radius="md">
          <Group justify="space-between">
            <Text size="xs" c="dimmed" fw={700}>MITIGATED SOURCES</Text>
            <IconShieldCheck size={16} color="var(--mantine-color-teal-6)" />
          </Group>
          <Title order={3} mt="xs">
            {mitigatedIpsCount} IPs
          </Title>
        </Paper>
      </SimpleGrid>

      <Card withBorder radius="md" p={0}>
        <ScrollArea h={600}>
          <Table verticalSpacing="sm" horizontalSpacing="md" highlightOnHover>
            <Table.Thead bg="var(--mantine-color-default-hover)">
              <Table.Tr>
                <Table.Th>Event</Table.Th>
                <Table.Th>Severity</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Target</Table.Th>
                <Table.Th>Source IP</Table.Th>
                <Table.Th>Location</Table.Th>
                <Table.Th>Recommendation</Table.Th>
                <Table.Th>Fingerprints (JA3/JA4+)</Table.Th>
                <Table.Th>Time</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {threats.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={9}>
                    <Text ta="center" py="xl" c="dimmed">No security threats detected recently.</Text>
                  </Table.Td>
                </Table.Tr>
              ) : (
                threats.map((threat) => (
                  <Table.Tr 
                    key={`${threat.type}-${threat.source}-${threat.timestamp}`}
                    onClick={() => handleRowClick(threat)}
                    style={{ cursor: 'pointer' }}
                  >
                    <Table.Td>
                      <Group gap="sm">
                        <ThemeIcon color="red" variant="light" size="sm">
                          <IconLock size={14} />
                        </ThemeIcon>
                        <Stack gap={0}>
                          <Text size="sm" fw={600}>{threat.type}</Text>
                          <Text size="xs" c="dimmed">{threat.description}</Text>
                        </Stack>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <SeverityBadge severity={threat.severity} />
                    </Table.Td>
                    <Table.Td>
                      {threat.mitigated ? (
                        <Badge color="teal" variant="light" size="xs" leftSection={<IconShieldCheck size={10} />}>
                          Mitigated
                        </Badge>
                      ) : (
                        <Badge color="red" variant="light" size="xs" leftSection={<IconShieldExclamation size={10} />}>
                          Active
                        </Badge>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Stack gap={2}>
                        {threat.route_id && (
                          <Badge size="xs" variant="light" color="gray" radius="xs" tt="none">
                            Route: {threat.route_id}
                          </Badge>
                        )}
                        <Text size="xs" ff="monospace" style={{ wordBreak: 'break-all', maxWidth: '200px' }}>
                          {threat.request_uri || "-"}
                        </Text>
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs" wrap="nowrap">
                        <Text 
                          size="sm" 
                          ff="monospace" 
                          c="brand" 
                          fw={600}
                          style={{ cursor: 'pointer', borderBottom: '1px dashed var(--mantine-color-brand-6)' }}
                          onClick={(e) => handleTraceClick(e, threat.source)}
                        >
                          {threat.source}
                        </Text>
                        <Tooltip label="Visual Trace">
                          <IconMap2 
                            size={14} 
                            style={{ cursor: 'pointer', opacity: 0.6 }} 
                            onClick={(e) => handleTraceClick(e, threat.source)}
                          />
                        </Tooltip>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs">
                        {threat.country_code && (
                          <img 
                            src={`https://flagcdn.com/16x12/${threat.country_code.toLowerCase()}.png`} 
                            alt={threat.country_name}
                          />
                        )}
                        <Text size="sm">{threat.country_name || "Unknown"}</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" style={{ maxWidth: 250 }}>{threat.recommendation}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Stack gap={4}>
                        {threat.ja3 && (
                          <Tooltip label={`JA3: ${threat.ja3}`}>
                            <Badge variant="outline" size="xs" ff="monospace" style={{ maxWidth: 100 }}>
                              JA3: {threat.ja3.substring(0, 8)}...
                            </Badge>
                          </Tooltip>
                        )}
                        {threat.ja4 && (
                          <Tooltip label={`JA4+: ${threat.ja4}`}>
                            <Badge variant="light" color="violet" size="xs" ff="monospace" style={{ maxWidth: 100 }}>
                              JA4: {threat.ja4.substring(0, 8)}...
                            </Badge>
                          </Tooltip>
                        )}
                        {!threat.ja3 && !threat.ja4 && <Text size="xs" c="dimmed">N/A</Text>}
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs" wrap="nowrap">
                        <IconClock size={12} color="var(--mantine-color-gray-5)" />
                        <Text size="xs" c="dimmed">
                          {new Date(threat.timestamp).toLocaleString()}
                        </Text>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
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
