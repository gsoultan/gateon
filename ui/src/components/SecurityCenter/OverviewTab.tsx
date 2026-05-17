import React, { useState } from 'react';
import { 
  Grid, 
  Card, 
  Text, 
  Title, 
  Group, 
  Stack, 
  Badge, 
  ThemeIcon, 
  SimpleGrid, 
  RingProgress, 
  Center, 
  Paper, 
  Box, 
  Table, 
  Button 
} from '@mantine/core';
import { DonutChart } from '@mantine/charts';
import { IconShieldCheck, IconActivity, IconHistory, IconFingerprint, IconArrowUpRight, IconRefresh, IconClock } from '@tabler/icons-react';
import { format } from 'date-fns';
import { useAnimateValue } from '../../hooks/useAnimateValue';
import { useDisclosure } from '@mantine/hooks';
import { SecurityAnomalyModal } from '../SecurityAnomalyModal';
import TraceVisualizer from '../Diagnostics/TraceVisualizer';
import type { MetricsSnapshot, SecurityThreat, DonutChartDataItem } from '../../types/metrics';
import type { Anomaly } from '../../types/gateon';

import { getSeverityColor } from '../../utils/security';

const AnimatedTitle = ({ value, suffix = "" }: { value: number; suffix?: string }) => {
  const animatedValue = useAnimateValue(value);
  return <Title order={3}>{animatedValue}{suffix}</Title>;
};

interface OverviewTabProps {
  metrics: MetricsSnapshot | null;
  securityScore: number;
  scoreColor: string;
  threatTypeData: DonutChartDataItem[];
  totalThreats: number;
}

export function OverviewTab({ 
  metrics, 
  securityScore, 
  scoreColor, 
  threatTypeData, 
  totalThreats,
}: OverviewTabProps) {
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const [traceIp, setTraceIp] = useState<string>("");
  const [traceOpened, { open: openTrace, close: closeTrace }] = useDisclosure(false);

  const handleRowClick = (anomaly: SecurityThreat) => {
    // Convert SecurityThreat to Anomaly for the modal if needed, or update modal to accept both
    const mappedAnomaly: Anomaly = {
      id: anomaly.id,
      type: anomaly.type,
      severity: anomaly.severity,
      description: anomaly.details,
      timestamp: anomaly.timestamp,
      source: anomaly.source_ip,
      recommendation: "Investigate source IP and associated traffic patterns.",
      country_code: anomaly.country_code,
      ja3: anomaly.ja3,
      ja4: anomaly.ja4,
      score: anomaly.score,
      route_id: anomaly.route_id,
      request_uri: anomaly.request_uri,
      mitigated: anomaly.mitigated,
      category: anomaly.category,
      action_taken: anomaly.action_taken,
    };
    setSelectedAnomaly(mappedAnomaly);
    open();
  };

  const handleTraceClick = (e: React.MouseEvent, ip: string) => {
    e.stopPropagation();
    setTraceIp(ip);
    openTrace();
  };

  return (
    <Stack gap="lg">
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
          <Group justify="space-between">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Security Posture</Text>
              <AnimatedTitle value={securityScore} suffix="%" />
            </Stack>
            <RingProgress
              size={60}
              thickness={6}
              roundCaps
              sections={[{ value: securityScore, color: scoreColor }]}
              label={
                <Center>
                  <IconShieldCheck size={18} color={`var(--mantine-color-${scoreColor}-6)`} />
                </Center>
              }
            />
          </Group>
          <Text size="xs" c="dimmed" mt="sm">
            Based on {metrics?.active_suspicious_sessions || 0} active sessions
          </Text>
        </Card>

        <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
          <Group justify="space-between">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Global Threat Score</Text>
              <AnimatedTitle value={metrics?.security?.global_threat_score || 0} />
            </Stack>
            <ThemeIcon size="xl" color="orange" variant="light" radius="md">
              <IconActivity size={24} />
            </ThemeIcon>
          </Group>
          <Group gap={4} mt="sm">
            <IconHistory size={14} color="orange" />
            <Text size="xs" c="dimmed">Deterministic anomaly estimation</Text>
          </Group>
        </Card>

        <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
          <Group justify="space-between">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Mitigated Today</Text>
              <AnimatedTitle value={metrics?.middleware?.mitigated_threats?.reduce((a: any, b: any) => a + b.value, 0) || 0} />
            </Stack>
            <ThemeIcon color="teal" variant="light" size="lg" radius="md">
              <IconShieldCheck size={20} />
            </ThemeIcon>
          </Group>
          <Group gap={4} mt="sm">
            <IconArrowUpRight size={14} color="teal" />
            <Text size="xs" c="teal" fw={700}>Active</Text>
            <Text size="xs" c="dimmed">defense operational</Text>
          </Group>
        </Card>

        <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
          <Group justify="space-between">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Reputation Status</Text>
              <Title order={3}>Good</Title>
            </Stack>
            <ThemeIcon color="blue" variant="light" size="lg" radius="md">
              <IconFingerprint size={20} />
            </ThemeIcon>
          </Group>
          <Group gap={4} mt="sm">
            <Text size="xs" c="dimmed">Global fingerprinting active</Text>
          </Group>
        </Card>
      </SimpleGrid>

      <Grid>
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Card withBorder radius="md">
            <Title order={4} mb="md">Mitigation Funnel Efficiency</Title>
            <Stack gap="xs">
              {(() => {
                const xdpDrops = metrics?.middleware?.ebpf_dropped_packets?.reduce((a, b) => a + b.value, 0) || 0;
                const wafBlocks = metrics?.middleware?.waf_blocked?.reduce((a, b) => a + b.value, 0) || 0;
                const rateLimits = metrics?.middleware?.rate_limit_rejected?.reduce((a, b) => a + b.value, 0) || 0;
                const geoipBlocks = metrics?.middleware?.geoip_blocked?.reduce((a, b) => a + b.value, 0) || 0;
                const authFailures = metrics?.middleware?.auth_failures?.reduce((a, b) => a + b.value, 0) || 0;
                const turnstileFails = metrics?.middleware?.turnstile_fail || 0;
                const hmacFailures = metrics?.middleware?.hmac_failures || 0;
                const errors = metrics?.golden_signals?.errors_total || 0;
                const requestsTotal = metrics?.golden_signals?.requests_total || 0;

                const totalIngress = requestsTotal + xdpDrops;
                // Calculate allowed traffic by subtracting all mitigations and errors from the requests that reached the server.
                const allowed = Math.max(0, requestsTotal - wafBlocks - rateLimits - geoipBlocks - authFailures - turnstileFails - hmacFailures - errors);

                const steps = [
                  { label: "Total Ingress", value: totalIngress, color: "blue" },
                  { label: "XDP/eBPF Drop", value: xdpDrops, color: "red" },
                  { label: "WAF Block", value: wafBlocks, color: "orange" },
                  { label: "Rate Limit", value: rateLimits, color: "yellow" },
                ];

                if (geoipBlocks > 0) steps.push({ label: "GeoIP Block", value: geoipBlocks, color: "indigo" });
                if (authFailures > 0) steps.push({ label: "Auth Failures", value: authFailures, color: "cyan" });
                if (turnstileFails > 0) steps.push({ label: "Turnstile Fail", value: turnstileFails, color: "violet" });
                if (hmacFailures > 0) steps.push({ label: "HMAC Fail", value: hmacFailures, color: "gray" });
                if (errors > 0) steps.push({ label: "Server Errors", value: errors, color: "pink" });

                steps.push({ label: "Allowed (Passed)", value: allowed, color: "teal" });

                return steps;
              })().map((step, _, allSteps) => {
                const totalValue = allSteps[0].value || 1;
                return (
                  <Box key={step.label}>
                    <Group justify="space-between" mb={4}>
                      <Text size="sm" fw={500}>{step.label}</Text>
                      <Text size="sm" c="dimmed">{step.value.toLocaleString()}</Text>
                    </Group>
                    <Box h={8} style={{ borderRadius: '100px', overflow: 'hidden' }} bg="light-dark(var(--mantine-color-gray-1), var(--mantine-color-dark-4))">
                      <Box 
                        h="100%" 
                        bg={step.color} 
                        style={{ 
                          width: `${Math.min(100, (step.value / totalValue) * 100)}%`,
                          borderRadius: "inherit",
                          transition: "width 1s ease-in-out"
                        }} 
                      />
                    </Box>
                  </Box>
                );
              })}
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Card withBorder radius="md" h="100%">
            <Title order={4} mb="md">Threat Distribution</Title>
            <Box h={200} w="100%" style={{ minWidth: 0 }}>
              <DonutChart
                h={200}
                minWidth={0}
                thickness={20}
                data={threatTypeData}
                withTooltip
                chartLabel={`${totalThreats} Total`}
                tooltipDataSource="segment"
                animationDuration={1200}
                strokeWidth={2}
                withPadding
                paddingAngle={4}
              />
            </Box>
            <Stack gap="xs" mt="md">
              {threatTypeData.slice(0, 3).map((item) => (
                <Group key={item.name} justify="space-between">
                  <Group gap="xs">
                    <Box w={10} h={10} style={{ borderRadius: '50%', backgroundColor: `var(--mantine-color-${item.color.split('.')[0]}-7)` }} />
                    <Text size="sm">{item.name}</Text>
                  </Group>
                  <Text size="sm" fw={700}>{item.value}</Text>
                </Group>
              ))}
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      <Card withBorder radius="md">
        <Group justify="space-between" mb="md">
          <Title order={4}>Recent Critical Events</Title>
          <Button size="xs" variant="light" leftSection={<IconRefresh size={14} />}>View All</Button>
        </Group>
        <Table.ScrollContainer minWidth={600}>
          <Table verticalSpacing="md" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Event / Type</Table.Th>
                <Table.Th>Source IP</Table.Th>
                <Table.Th>Severity</Table.Th>
                <Table.Th>Time</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {metrics?.security?.recent_anomalies?.slice(0, 5).map((a: SecurityThreat) => (
                <Table.Tr key={a.id} style={{ cursor: 'pointer' }} onClick={() => handleRowClick(a)}>
                  <Table.Td>
                    <Stack gap={0}>
                      <Text size="sm" fw={700}>{(a.type || 'Unknown').replace(/_/g, ' ').toUpperCase()}</Text>
                      <Text size="xs" c="dimmed" maw={300} truncate="end">{a.details}</Text>
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      <Badge size="xs" variant="outline">{a.country_code || 'XX'}</Badge>
                      <Text size="sm" fw={500} ff="monospace" onClick={(e) => handleTraceClick(e, a.source_ip)} style={{ cursor: 'pointer', textDecoration: 'underline' }}>{a.source_ip}</Text>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={getSeverityColor(a.severity)} variant="filled" size="sm">
                      {a.severity}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4} wrap="nowrap">
                      <IconClock size={12} color="gray" />
                      <Text size="xs" c="dimmed">{a.timestamp ? format(new Date(a.timestamp), 'HH:mm:ss') : 'N/A'}</Text>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
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
