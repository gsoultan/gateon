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
  Button 
} from '@mantine/core';
import { DonutChart } from '@mantine/charts';
import { 
  IconShieldCheck, 
  IconShieldOff, 
  IconActivity, 
  IconHistory, 
  IconFingerprint, 
  IconArrowUpRight, 
  IconRefresh, 
  IconClock,
  IconCpu,
  IconBrain,
  IconRobot,
  IconUsers,
  IconBug,
  IconShieldLock,
  IconBolt,
} from '@tabler/icons-react';
import { Alert, Anchor } from '@mantine/core';
import { Link } from '@tanstack/react-router';
import { format } from 'date-fns';
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

  const getThreatIcon = (type: string) => {
    const t = type.toLowerCase();
    if (t.includes('waf') || t.includes('sqli') || t.includes('xss')) return <IconShieldLock size={16} />;
    if (t.includes('bot') || t.includes('scanner')) return <IconRobot size={16} />;
    if (t.includes('brute') || t.includes('impossible_travel')) return <IconUsers size={16} />;
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
      source: anomaly.source_ip,
      recommendation: anomaly.recommendation || "Investigate source IP and associated traffic patterns.",
      country_code: anomaly.country_code,
      ja3: anomaly.ja3,
      ja4: anomaly.ja4,
      score: anomaly.score,
      route_id: anomaly.route_id,
      request_uri: anomaly.request_uri,
      mitigated: anomaly.mitigated,
      category: anomaly.category,
      action_taken: anomaly.action_taken,
      request_headers: anomaly.request_headers,
      request_body: anomaly.request_body,
      response_headers: anomaly.response_headers,
      response_body: anomaly.response_body,
      user_agent: anomaly.user_agent,
      http_method: anomaly.http_method,
      confidence: anomaly.confidence,
      entropy: anomaly.entropy,
      cluster_size: anomaly.cluster_size,
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
    const f = metrics?.mitigation_funnel;
    const ingress = f?.http_ingress || 0;
    const stages: { label: string; value: number; color: string }[] = [
      { label: "HTTP Ingress", value: ingress, color: "blue" },
      { label: "WAF Block", value: f?.waf_blocked || 0, color: "orange" },
      { label: "Rate Limit", value: f?.rate_limited || 0, color: "yellow" },
    ];
    if ((f?.bot_blocked || 0) > 0) stages.push({ label: "Bot Mitigation", value: f!.bot_blocked, color: "pink" });
    if ((f?.file_security_blocked || 0) > 0) stages.push({ label: "File Security", value: f!.file_security_blocked, color: "red" });
    if ((f?.deception_blocked || 0) > 0) stages.push({ label: "Deception/Trap", value: f!.deception_blocked, color: "grape" });
    if ((f?.advanced_security_blocked || 0) > 0) stages.push({ label: "Advanced Sec", value: f!.advanced_security_blocked, color: "dark" });
    if ((f?.geoip_blocked || 0) > 0) stages.push({ label: "GeoIP Block", value: f!.geoip_blocked, color: "indigo" });
    if ((f?.auth_failures || 0) > 0) stages.push({ label: "Auth Failures", value: f!.auth_failures, color: "cyan" });
    if ((f?.turnstile_failures || 0) > 0) stages.push({ label: "Turnstile Fail", value: f!.turnstile_failures, color: "violet" });
    if ((f?.hmac_failures || 0) > 0) stages.push({ label: "HMAC Fail", value: f!.hmac_failures, color: "gray" });
    stages.push({ label: "Allowed (Passed)", value: f?.allowed || 0, color: "teal" });
    return { stages, ingress };
  }, [metrics?.mitigation_funnel]);

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
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Kernel Protection</Text>
              <Title order={3}>{posture?.ebpf?.attached ? 'Active' : 'Inactive'}</Title>
            </Stack>
            <ThemeIcon color={posture?.ebpf?.attached ? 'teal' : 'gray'} variant="light" size="lg" radius="md">
              <IconCpu size={20} />
            </ThemeIcon>
          </Group>
          <Group gap={4} mt="sm" wrap="nowrap">
            <Text size="xs" c="dimmed" truncate="end">
              {posture?.ebpf?.attached ? `Offloading to ${posture.ebpf.interface}` : 'eBPF offloading disabled'}
            </Text>
            {posture?.ebpf?.shunned_ips && posture.ebpf.shunned_ips > 0 ? (
              <Badge size="xs" variant="filled" color="red">
                {posture.ebpf.shunned_ips} Shunned
              </Badge>
            ) : null}
          </Group>
        </Card>

        <Card withBorder radius="md" p="md" className="hover:shadow-lg transition-all duration-300">
          <Group justify="space-between">
            <Stack gap={0}>
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">Mitigated Today</Text>
              <AnimatedTitle value={metrics?.security?.mitigated_today ?? 0} />
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
            <Badge size="xs" color="blue" variant="dot">JA4 & Fingerprinting Active</Badge>
            <Text size="xs" c="dimmed">Adaptive Acceleration Enabled</Text>
          </Group>
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
                      <Text size="sm" c="dimmed">{step.value.toLocaleString()}</Text>
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
            {((metrics?.mitigation_funnel?.server_errors || 0) > 0 ||
              (metrics?.mitigation_funnel?.xdp_packets_dropped || 0) > 0) && (
              <Group gap="lg" mt="md" pt="sm" style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}>
                <Group gap={6}>
                  <Text size="xs" c="dimmed">Server Errors (5xx of allowed):</Text>
                  <Text size="xs" fw={600} c="pink">
                    {(metrics?.mitigation_funnel?.server_errors || 0).toLocaleString()}
                  </Text>
                </Group>
                <Group gap={6}>
                  <Text size="xs" c="dimmed">XDP/eBPF packets dropped:</Text>
                  <Text size="xs" fw={600} c="red">
                    {(metrics?.mitigation_funnel?.xdp_packets_dropped || 0).toLocaleString()}
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
              {metrics?.security?.recent_anomalies?.slice(0, 5).map((a: SecurityThreat) => (
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
