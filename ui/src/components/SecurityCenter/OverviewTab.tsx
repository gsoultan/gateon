import React from 'react';
import { Grid, Card, Text, Title, Group, Stack, Badge, ThemeIcon, SimpleGrid, RingProgress, Center, Paper, Box, Avatar, Table, Button } from '@mantine/core';
import { DonutChart } from '@mantine/charts';
import { IconShieldCheck, IconActivity, IconHistory, IconTarget, IconFingerprint, IconArrowUpRight, IconMapPin, IconShieldOff, IconLock, IconRefresh } from '@tabler/icons-react';
import { format } from 'date-fns';
import { useAnimateValue } from '../../hooks/useAnimateValue';
import { useDisclosure } from '@mantine/hooks';
import { SecurityAnomalyModal } from '../SecurityAnomalyModal';
import TraceVisualizer from '../Diagnostics/TraceVisualizer';

import { getThreatColor, getSeverityColor } from '../../utils/security';

const AnimatedTitle = ({ value, suffix = "" }: { value: number; suffix?: string }) => {
  const animatedValue = useAnimateValue(value);
  return <Title order={3}>{animatedValue}{suffix}</Title>;
};

interface OverviewTabProps {
  metrics: any;
  securityScore: number;
  scoreColor: string;
  threatTypeData: any[];
  totalThreats: number;
}

export function OverviewTab({ 
  metrics, 
  securityScore, 
  scoreColor, 
  threatTypeData, 
  totalThreats,
}: OverviewTabProps) {
  const [selectedAnomaly, setSelectedAnomaly] = React.useState<any>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const [traceIp, setTraceIp] = React.useState<string>("");
  const [traceOpened, { open: openTrace, close: closeTrace }] = useDisclosure(false);

  const handleRowClick = (anomaly: any) => {
    setSelectedAnomaly(anomaly);
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
              {[
                { label: "Total Ingress", value: metrics?.golden_signals?.requests_total || 0, color: "blue" },
                { label: "XDP/eBPF Drop", value: metrics?.middleware?.ebpf_dropped_packets?.reduce((a: any, b: any) => a + b.value, 0) || 0, color: "red" },
                { label: "WAF Block", value: metrics?.middleware?.waf_blocked?.reduce((a: any, b: any) => a + b.value, 0) || 0, color: "orange" },
                { label: "Rate Limit", value: metrics?.middleware?.rate_limit_rejected?.reduce((a: any, b: any) => a + b.value, 0) || 0, color: "yellow" },
                { label: "Allowed (200 OK)", value: metrics?.golden_signals?.requests_total ? (metrics?.golden_signals?.requests_total - metrics?.golden_signals?.errors_total) : 0, color: "teal" },
              ].map((step) => (
                <Box key={step.label}>
                  <Group justify="space-between" mb={4}>
                    <Text size="sm" fw={500}>{step.label}</Text>
                    <Text size="sm" c="dimmed">{step.value.toLocaleString()}</Text>
                  </Group>
                  <Paper h={8} radius="xl" bg="light-dark(var(--mantine-color-gray-1), var(--mantine-color-dark-4))">
                    <Box 
                      h="100%" 
                      bg={step.color} 
                      style={{ 
                        width: `${metrics?.golden_signals?.requests_total ? Math.min(100, (step.value / metrics.golden_signals.requests_total) * 100) : 0}%`,
                        borderRadius: "inherit",
                        transition: "width 1s ease-in-out"
                      }} 
                    />
                  </Paper>
                </Box>
              ))}
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Card withBorder radius="md" h="100%">
            <Title order={4} mb="md">Threat Distribution</Title>
            <Center h={200}>
              <DonutChart
                size={160}
                thickness={20}
                data={threatTypeData}
                withTooltip
                chartLabel={`${totalThreats} Total`}
                tooltipDataSource="segment"
              />
            </Center>
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
              {metrics?.security?.recent_anomalies?.slice(0, 5).map((a: any) => (
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

const IconClock = ({ size, color }: { size: number; color: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
  </svg>
);
