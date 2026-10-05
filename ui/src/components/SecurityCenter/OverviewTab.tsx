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
  IconEye,
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
import type { SecurityPosture } from '../../hooks/useSecurityPosture';
import { useReputations } from '../../hooks/useReputations';
import {
  DETECTING_ONLY,
  POSTURE_FORMULA,
  postureColor,
  postureLines,
  reputationSummary,
  wafDetectsSomewhere,
  wafStatus,
} from './postureView';
import type { MetricsSnapshot, SecurityThreat, DonutChartDataItem } from '../../types/metrics';
import type { Anomaly } from '../../types/gateon';

import { getSeverityColor } from '../../utils/security';

const AnimatedTitle = ({ value, suffix = "" }: { value: number; suffix?: string }) => {
  const animatedValue = useAnimateValue(value);
  return <Title order={3}>{animatedValue}{suffix}</Title>;
};

interface OverviewTabProps {
  metrics: MetricsSnapshot | null | undefined;
  threatTypeData: DonutChartDataItem[];
  totalThreats: number;
}

/**
 * The posture percentage, from the server's posture report: a weighted sum of
 * the protections in effect, computed from configuration only (ADR 0048). It
 * used to be computed here from client reputation, so it read 100% with nothing
 * configured and rose as an attacker's reputation fell.
 */
export function SecurityPostureCard({ posture, isLoading, error }: {
  posture: SecurityPosture | undefined;
  isLoading: boolean;
  error: unknown;
}) {
  const score = posture?.score;
  const color = score ? postureColor(score.percent) : 'gray';
  return (
    <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
      <Group justify="space-between">
        <Stack gap={0}>
          <Text size="xs" c="dimmed" fw={700} tt="uppercase">Security Posture</Text>
          {isLoading ? (
            <Skeleton height={28} width={60} mt={4} />
          ) : score ? (
            <Tooltip
              multiline
              w={360}
              label={
                <Stack gap={4}>
                  <Text size="xs">{POSTURE_FORMULA}</Text>
                  {postureLines(score).map((line) => (
                    <Text key={line} size="xs">{line}</Text>
                  ))}
                </Stack>
              }
            >
              <Title order={3} style={{ cursor: 'help' }}>{`${score.percent}%`}</Title>
            </Tooltip>
          ) : (
            <Text size="sm" c="red">{error ? 'Unavailable' : 'Not reported'}</Text>
          )}
        </Stack>
        <RingProgress
          size={60}
          thickness={6}
          roundCaps
          sections={[{ value: score?.percent ?? 0, color }]}
          label={
            <Center>
              <IconShieldCheck size={18} color={`var(--mantine-color-${color}-6)`} />
            </Center>
          }
        />
      </Group>
      <Text size="xs" c="dimmed" mt="sm">
        Protections in effect, weighted. Hover the figure for each control. Traffic does not move it.
      </Text>
    </Card>
  );
}

const REPUTATION_LIMIT = 50;

/** Clients whose reputation the WAF and anomaly findings have lowered. */
function ReputationCard() {
  const { data, isLoading, error } = useReputations(REPUTATION_LIMIT);
  const view = data ? reputationSummary(data.reputations ?? [], REPUTATION_LIMIT) : null;
  return (
    <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
      <Group justify="space-between">
        <Stack gap={0}>
          <Text size="xs" c="dimmed" fw={700} tt="uppercase">Client Reputation</Text>
          {isLoading ? (
            <Skeleton height={28} width={80} mt={4} />
          ) : view ? (
            <Title order={3}>{view.value}</Title>
          ) : (
            <Text size="sm" c="red">{error ? 'Unavailable' : 'Not reported'}</Text>
          )}
        </Stack>
        <ThemeIcon color="blue" variant="light" size="lg" radius="md">
          <IconFingerprint size={20} />
        </ThemeIcon>
      </Group>
      <Text size="xs" c="dimmed" mt="sm">
        {view?.detail ?? 'Clients whose reputation WAF and anomaly findings have lowered.'}
      </Text>
    </Card>
  );
}

export function OverviewTab({ 
  metrics,
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

  const { data: posture, isLoading: postureLoading, error: postureError } = useSecurityPosture();
  const wafView = posture?.waf ? wafStatus(posture.waf) : null;
  const wafOff = wafView?.label === 'Disabled';
  const wafDetecting = wafDetectsSomewhere(posture?.waf);

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
    if ((f?.mitigationBlocked || 0) > 0) stages.push({ label: "Blocked Source (mitigation)", value: f!.mitigationBlocked, color: "red" });
    if ((f?.advancedSecurityBlocked || 0) > 0) stages.push({ label: "Advanced Sec", value: f!.advancedSecurityBlocked, color: "dark" });
    if ((f?.geoipBlocked || 0) > 0) stages.push({ label: "GeoIP Block", value: f!.geoipBlocked, color: "indigo" });
    if ((f?.authFailures || 0) > 0) stages.push({ label: "Auth Failures", value: f!.authFailures, color: "cyan" });
    if ((f?.turnstileFailures || 0) > 0) stages.push({ label: "Turnstile Fail", value: f!.turnstileFailures, color: "violet" });
    if ((f?.hmacFailures || 0) > 0) stages.push({ label: "HMAC Fail", value: f!.hmacFailures, color: "gray" });
    if ((f?.otherRefused || 0) > 0) stages.push({ label: "Other Refusals (IP/host filter, limits, no route)", value: f!.otherRefused, color: "gray" });
    if ((f?.answered || 0) > 0) stages.push({ label: "Answered by Gateway (redirects, challenges)", value: f!.answered, color: "violet" });
    stages.push({ label: "Allowed (reached a backend)", value: f?.allowed || 0, color: "teal" });
    return { stages, ingress };
  }, [metrics?.mitigationFunnel]);

  /**
   * What an audit-only WAF declined to refuse.
   *
   * Audit-only produces a 200 and a threat-list entry, so from the dashboard it
   * is indistinguishable from a WAF that found nothing. That left an operator
   * two choices -- enforce blind, or leave detection on forever -- and most
   * picked the second. These counts are the missing third option: the cost of
   * enforcing, measured on this deployment's own traffic before it is paid.
   *
   * Capped at the ten noisiest rules. The list is fed by gateway traffic, and a
   * view that renders one row per rule seen is a view that stops rendering.
   */
  const wouldBlock = React.useMemo(() => {
    const rows = metrics?.middleware?.wafWouldBlock ?? [];
    const total = rows.reduce((sum, r) => sum + (r.value || 0), 0);
    const top = [...rows].sort((a, b) => (b.value || 0) - (a.value || 0)).slice(0, 10);
    return { total, top, ruleCount: rows.length };
  }, [metrics?.middleware?.wafWouldBlock]);

  return (
    <Stack gap="lg">
      {wouldBlock.total > 0 && (
        <Alert
          color="blue"
          variant="light"
          icon={<IconEye size={18} />}
          title="Detection only: these requests would be blocked if you enforced"
        >
          <Stack gap="sm">
            <Text size="sm">
              A WAF on this gateway is running in audit-only mode. It has found{' '}
              <strong>{safeToLocaleString(wouldBlock.total)}</strong>{' '}
              {wouldBlock.total === 1 ? 'request' : 'requests'} across{' '}
              <strong>{wouldBlock.ruleCount}</strong>{' '}
              {wouldBlock.ruleCount === 1 ? 'rule' : 'rules'} that it would have
              refused. Nothing was blocked; this is what switching enforcement on
              would cost. Work through the rules below and confirm each one is
              catching an attack rather than your own traffic.
            </Text>
            <Table highlightOnHover withTableBorder={false} verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Rule</Table.Th>
                  <Table.Th style={{ textAlign: 'right' }}>Would block</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {wouldBlock.top.map((r) => (
                  <Table.Tr key={r.label}>
                    {/* Rendered as text. Everything on this page is derived from
                        traffic the gateway observed, which comes from hostile
                        clients -- a dashboard that interprets it is the exploit. */}
                    <Table.Td>
                      <Text size="xs" ff="monospace">{r.label}</Text>
                    </Table.Td>
                    <Table.Td style={{ textAlign: 'right' }}>
                      <Badge size="xs" variant="light" color="blue">
                        {safeToLocaleString(r.value)}
                      </Badge>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            {wouldBlock.ruleCount > wouldBlock.top.length && (
              <Text size="xs" c="dimmed">
                Showing the {wouldBlock.top.length} noisiest of {wouldBlock.ruleCount} rules.
              </Text>
            )}
          </Stack>
        </Alert>
      )}
      {wafDetecting && wouldBlock.total === 0 && wafView && (
        <Alert
          color="orange"
          variant="light"
          icon={<IconEye size={18} />}
          title={`Web Application Firewall: ${DETECTING_ONLY}`}
        >
          <Text size="sm">
            {wafView.detail} An audit-only WAF records the attacks it matches and forwards them to
            the backend; nothing is blocked there.
          </Text>
        </Alert>
      )}
      {wafOff && (
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
      {/* No "Global Threat Score" card: it was the day's unscaled sum of
          threat scores, shown as a risk level it had no scale for (T41). */}
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <SecurityPostureCard posture={posture} isLoading={postureLoading} error={postureError} />

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
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Mitigated Today</Text>
              <AnimatedTitle value={metrics?.security?.mitigatedToday ?? 0} />
            </Stack>
            <ThemeIcon color="teal" variant="light" size="lg" radius="md">
              <IconShieldCheck size={20} />
            </ThemeIcon>
          </Group>
          <Text size="xs" c="dimmed" mt="sm">
            Threats blocked or challenged since midnight, gateway time.
          </Text>
        </Card>

        <ReputationCard />
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
