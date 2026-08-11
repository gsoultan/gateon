// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
  Box, 
  Table, 
  Button,
  Skeleton,
} from '@mantine/core';
import { DonutChart } from '@mantine/charts';
import { 
  IconShieldCheck, 
  IconShieldOff, 
  IconActivity, 
  IconFingerprint, 
  IconRefresh, 
  IconClock,
  IconCpu,
  IconBrain,
  IconRobot,
  IconUsers,
  IconBug,
  IconShieldLock,
  IconBolt,
  IconAlertTriangle,
} from '@tabler/icons-react';
import { Alert, Anchor, Tooltip } from '@mantine/core';
import { Link } from '@tanstack/react-router';
import { safeFormatDate, safeToLocaleString } from '../../utils/format';
import { useAnimateValue } from '../../hooks/useAnimateValue';
import { useDisclosure } from '@mantine/hooks';
import { SecurityAnomalyModal } from '../SecurityAnomalyModal';
import TraceVisualizer from '../Diagnostics/TraceVisualizer';
import { useSecurityPosture } from '../../hooks/useSecurityPosture';
import type { MetricsSnapshot, SecurityThreat, DonutChartDataItem } from '../../types/metrics';
import type { Anomaly } from '../../types/gateon';

import { getSeverityColor } from '../../utils/security';

const AnimatedTitle = ({ value, suffix = "" }: { value: number; suffix?: string }) => {
  const animatedValue = useAnimateValue(value);
  return <Title order={3}>{animatedValue}{suffix}</Title>;
};

interface OverviewTabProps {
  metrics: MetricsSnapshot | null | undefined;
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

  const getThreatIcon = (type: string) => {
    const t = type.toLowerCase();
    if (t.includes('waf') || t.includes('sqli') || t.includes('xss')) return <IconShieldLock size={16} />;
    if (t.includes('bot') || t.includes('scanner')) return <IconRobot size={16} />;
    if (t.includes('brute') || t.includes('impossibleTravel')) return <IconUsers size={16} />;
    if (t.includes('exploit') || t.includes('rce') || t.includes('lfi')) return <IconBug size={16} />;
    if (t.includes('entropy') || t.includes('fingerprint')) return <IconBolt size={16} />;
    return <IconAlertTriangle size={16} />;
  };

  const handleRowClick = (anomaly: SecurityThreat) => {
    // Convert SecurityThreat to Anomaly for the modal if needed, or update modal to accept both
    const mappedAnomaly: Anomaly = {
      id: anomaly.id,
      type: anomaly.type,
      severity: anomaly.severity,
      description: anomaly.details,
      timestamp: anomaly.timestamp,
      source: anomaly.sourceIp,
      recommendation: anomaly.recommendation || "Investigate source IP and associated traffic patterns.",
      countryCode: anomaly.countryCode,
      ja3: anomaly.ja3,
      ja4: anomaly.ja4,
      score: anomaly.score,
      routeId: anomaly.routeId,
      requestUri: anomaly.requestUri,
      mitigated: anomaly.mitigated,
      category: anomaly.category,
      actionTaken: anomaly.actionTaken,
      requestHeaders: anomaly.requestHeaders,
      requestBody: anomaly.requestBody,
      responseHeaders: anomaly.responseHeaders,
      responseBody: anomaly.responseBody,
      userAgent: anomaly.userAgent,
      httpMethod: anomaly.httpMethod,
      confidence: anomaly.confidence,
      entropy: anomaly.entropy,
      clusterSize: anomaly.clusterSize,
    };
    setSelectedAnomaly(mappedAnomaly);
    open();
  };

  const handleTraceClick = (e: React.MouseEvent, ip: string) => {
    e.stopPropagation();
    setTraceIp(ip);
    openTrace();
  };

  const { data: posture } = useSecurityPosture();
  const wafEnabled = posture?.waf?.enabled;

  const funnelStages = React.useMemo(() => {
    const f = metrics?.mitigationFunnel;
    const ingress = f?.httpIngress || 0;
    const stages: { label: string; value: number; color: string }[] = [
      { label: "HTTP Ingress", value: ingress, color: "blue" },
      { label: "WAF Block", value: f?.wafBlocked || 0, color: "orange" },
      { label: "Fast-Path Block", value: f?.fastPathBlocked || 0, color: "red" },
      { label: "Rate Limit", value: f?.rateLimited || 0, color: "yellow" },
    ];
    if ((f?.botBlocked || 0) > 0) stages.push({ label: "Bot Mitigation", value: f!.botBlocked, color: "pink" });
    if ((f?.fileSecurityBlocked || 0) > 0) stages.push({ label: "File Security", value: f!.fileSecurityBlocked, color: "red" });
    if ((f?.deceptionBlocked || 0) > 0) stages.push({ label: "Deception/Trap", value: f!.deceptionBlocked, color: "grape" });
    if ((f?.advancedSecurityBlocked || 0) > 0) stages.push({ label: "Advanced Sec", value: f!.advancedSecurityBlocked, color: "dark" });
    if ((f?.geoipBlocked || 0) > 0) stages.push({ label: "GeoIP Block", value: f!.geoipBlocked, color: "indigo" });
    if ((f?.authFailures || 0) > 0) stages.push({ label: "Auth Failures", value: f!.authFailures, color: "cyan" });
    if ((f?.turnstileFailures || 0) > 0) stages.push({ label: "Turnstile Fail", value: f!.turnstileFailures, color: "violet" });
    if ((f?.hmacFailures || 0) > 0) stages.push({ label: "HMAC Fail", value: f!.hmacFailures, color: "gray" });
    stages.push({ label: "Allowed (Passed)", value: f?.allowed || 0, color: "teal" });
    return { stages, ingress };
  }, [metrics?.mitigationFunnel]);

  return (
    <Stack gap="lg">
      {wafEnabled === false && (
        <Alert
          color="orange"
          variant="light"
          icon={<IconShieldOff size={18} />}
          title="Web Application Firewall is disabled"
        >
          <Group justify="space-between" wrap="nowrap" gap="md">
            <Text size="sm">
              Your routes are not being inspected by the WAF, so WAF block counts will
              read 0. Enable <strong>Protect all routes</strong> to run OWASP CRS plus
              malware &amp; ransomware detection on every route.
            </Text>
            <Anchor component={Link} to="/settings" fw={600} style={{ whiteSpace: 'nowrap' }}>
              Open Settings
            </Anchor>
          </Group>
        </Alert>
      )}
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 3, xl: 5 }}>
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
            Overall health based on active sessions and detected threats. Higher is better.
          </Text>
        </Card>

        <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
          <Group justify="space-between">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Global Threat Score</Text>
              <AnimatedTitle value={metrics?.security?.globalThreatScore || 0} />
            </Stack>
            <ThemeIcon size="xl" color="orange" variant="light" radius="md">
              <IconActivity size={24} />
            </ThemeIcon>
          </Group>
          <Text size="xs" c="dimmed" mt="sm">
            Real-time estimate of system-wide risk level. Lower is safer.
          </Text>
        </Card>

        <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
          <Group justify="space-between">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Kernel Protection</Text>
              <Title order={3}>{posture?.ebpf?.attached ? 'Active' : 'Inactive'}</Title>
            </Stack>
            <ThemeIcon color={posture?.ebpf?.attached ? 'teal' : 'gray'} variant="light" size="lg" radius="md">
              <IconCpu size={20} />
            </ThemeIcon>
          </Group>
          <Text size="xs" c="dimmed" mt="sm">
            Hardware-accelerated filtering (eBPF). Stops attacks before they reach the CPU.
          </Text>
        </Card>

        <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
          <Group justify="space-between">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Mitigated in 24h</Text>
              <AnimatedTitle value={metrics?.security?.mitigatedToday ?? 0} />
            </Stack>
            <ThemeIcon color="teal" variant="light" size="lg" radius="md">
              <IconShieldCheck size={20} />
            </ThemeIcon>
          </Group>
          <Text size="xs" c="dimmed" mt="sm">
            Number of malicious requests successfully blocked or challenged.
          </Text>
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
          <Text size="xs" c="dimmed" mt="sm">
            Analysis of client behavioral patterns and user identification.
          </Text>
        </Card>
      </SimpleGrid>

      <Grid>
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Card withBorder radius="md">
            <Title order={4} mb="md">Mitigation Funnel Efficiency</Title>
            <Stack gap="xs">
              {(() => {
                const { stages, ingress } = funnelStages;
                const denom = ingress || 1;
                return stages.map((step) => (
                  <Box key={step.label}>
                    <Group justify="space-between" mb={4}>
                      <Text size="sm" fw={500}>{step.label}</Text>
                      <Text size="sm" c="dimmed">{safeToLocaleString(step.value)}</Text>
                    </Group>
                    <Box h={8} style={{ borderRadius: '100px', overflow: 'hidden' }} bg="light-dark(var(--mantine-color-gray-1), var(--mantine-color-dark-4))">
                      <Box
                        h="100%"
                        bg={step.color}
                        style={{
                          width: `${Math.min(100, (step.value / denom) * 100)}%`,
                          borderRadius: "inherit",
                          transition: "width 1s ease-in-out"
                        }}
                      />
                    </Box>
                  </Box>
                ));
              })()}
            </Stack>
            {/* Separate, differently-scoped indicators: 5xx are failures of
                already-allowed traffic; XDP drops are packet-level (not requests). */}
            {((metrics?.mitigationFunnel?.serverErrors || 0) > 0 ||
              (metrics?.mitigationFunnel?.xdpPacketsDropped || 0) > 0) && (
              <Group gap="lg" mt="md" pt="sm" style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}>
                <Group gap={6}>
                  <Text size="xs" c="dimmed">Server Errors (5xx of allowed):</Text>
                  <Text size="xs" fw={600} c="pink">
                    {(metrics?.mitigationFunnel?.serverErrors || 0).toLocaleString()}
                  </Text>
                </Group>
                <Group gap={6}>
                  <Text size="xs" c="dimmed">XDP/eBPF packets dropped:</Text>
                  <Text size="xs" fw={600} c="red">
                    {(metrics?.mitigationFunnel?.xdpPacketsDropped || 0).toLocaleString()}
                  </Text>
                </Group>
              </Group>
            )}
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Card withBorder radius="md" h="100%">
            <Title order={4} mb="md">Threat Distribution</Title>
            <Box h={200} w="100%" style={{ minWidth: 0 }}>
              <DonutChart
                h={200}
                thickness={20}
                data={threatTypeData}
                withTooltip
                chartLabel={`${totalThreats} Total`}
                tooltipDataSource="segment"
                strokeWidth={2}
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
              {!metrics ? (
                Array(5).fill(0).map((_, i) => (
                  <Table.Tr key={i}>
                    <Table.Td><Skeleton height={20} radius="sm" /></Table.Td>
                    <Table.Td><Skeleton height={20} radius="sm" /></Table.Td>
                    <Table.Td><Skeleton height={20} radius="sm" /></Table.Td>
                    <Table.Td><Skeleton height={20} radius="sm" /></Table.Td>
                  </Table.Tr>
                ))
              ) : metrics.security?.recentAnomalies?.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={4}>
                    <Text ta="center" py="xl" c="dimmed">No recent critical events.</Text>
                  </Table.Td>
                </Table.Tr>
              ) : (
                metrics.security?.recentAnomalies?.slice(0, 5).map((a: SecurityThreat) => (
                  <Table.Tr key={a.id} style={{ cursor: 'pointer' }} onClick={() => handleRowClick(a)}>
                    <Table.Td>
                      <Group gap="sm" wrap="nowrap">
                        <ThemeIcon 
                          variant="light" 
                          color={getSeverityColor(a.severity)} 
                          size="md" 
                          radius="md"
                        >
                          {getThreatIcon(a.type || '')}
                        </ThemeIcon>
                        <Stack gap={0}>
                          <Group gap={4}>
                            <Text size="sm" fw={700}>{(a.type || 'Unknown').replace(/_/g, ' ').toUpperCase()}</Text>
                            {a.recommendation?.includes("Smart Insight:") && (
                              <Tooltip label="Deep intelligence analysis available">
                                <Badge size="xs" color="blue" variant="outline" p={4} style={{ borderStyle: 'dashed' }}>
                                  <IconBrain size={10} />
                                </Badge>
                              </Tooltip>
                            )}
                          </Group>
                          <Text size="xs" c="dimmed" maw={300} truncate="end">{a.details}</Text>
                        </Stack>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        <Badge size="xs" variant="outline">{a.countryCode || 'XX'}</Badge>
                        <Text size="sm" fw={500} ff="monospace" onClick={(e) => handleTraceClick(e, a.sourceIp)} style={{ cursor: 'pointer', textDecoration: 'underline' }}>{a.sourceIp}</Text>
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
                        <Text size="xs" c="dimmed">{safeFormatDate(a.timestamp, 'HH:mm:ss')}</Text>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))
              )}
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
