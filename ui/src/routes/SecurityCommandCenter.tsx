import React from 'react';
import { Container, Grid, Card, Text, Title, Group, Stack, Progress, Badge, ThemeIcon, SimpleGrid, Button, ActionIcon, Tooltip, Switch, Divider, Table, TextInput, Box } from '@mantine/core';
import { IconShieldCheck, IconShieldExclamation, IconAlertTriangle, IconActivity, IconBell, IconHistory, IconFingerprint, IconWorld, IconLock, IconRefresh, IconSearch, IconAdjustments, IconTarget, IconExternalLink, IconUserCheck, IconGhost, IconShieldOff } from '@tabler/icons-react';
import { useSecurityThreats, useGateonStatus, apiFetch, useMetricsSnapshot } from '../hooks/useGateon';
import { ReputationMonitor } from '../components/ReputationMonitor';
import { Notifications } from '@mantine/notifications';
import { Link } from '@tanstack/react-router';
import type { GlobalConfig } from '../types/gateon';

export default function SecurityCommandCenter() {
  const { data: threatsData, isLoading: threatsLoading } = useSecurityThreats(100);
  const { data: status } = useGateonStatus();
  const { data: metrics } = useMetricsSnapshot();
  const [globalConfig, setGlobalConfig] = React.useState<GlobalConfig | null>(null);

  React.useEffect(() => {
    apiFetch("/v1/global")
      .then(r => r.ok ? r.json() : null)
      .then(cfg => setGlobalConfig(cfg))
      .catch(() => {});
  }, []);
  
  const securityScore = React.useMemo(() => {
    if (!threatsData?.threats) return 100;
    const activeThreats = threatsData.threats.filter(t => !t.mitigated);
    const score = 100 - (activeThreats.length * 5);
    return Math.max(score, 0);
  }, [threatsData]);

  const scoreColor = securityScore > 80 ? 'teal' : securityScore > 50 ? 'orange' : 'red';

  return (
    <Container size="xl">
      <Stack gap="xl">
        <Group justify="space-between">
          <Stack gap={0}>
            <Title order={2} fw={800} style={{ letterSpacing: -1 }}>Security Command Center</Title>
            <Text c="dimmed" size="sm">Centralized orchestration for autonomous threat detection and response.</Text>
          </Stack>
          <Group>
            <Button variant="light" leftSection={<IconAdjustments size={16} />} component={Link} to="/settings">Global Settings</Button>
            <Button leftSection={<IconShieldCheck size={16} />}>Run Security Scan</Button>
          </Group>
        </Group>

        <Grid gutter="md">
          <Grid.Col span={{ base: 12, md: 4 }}>
            <Card withBorder radius="md" p="xl" style={{ height: '100%' }}>
              <Stack align="center" gap="md">
                <Text fw={700} size="sm" c="dimmed" tt="uppercase">System Security Score</Text>
                <Box style={{ position: 'relative' }}>
                  <Progress
                    value={securityScore}
                    size="xl"
                    radius="xl"
                    color={scoreColor}
                    h={120}
                    w={120}
                    style={{ borderRadius: '50%' }}
                  />
                  <Box style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }}>
                    <Title order={1} fw={900}>{securityScore}%</Title>
                  </Box>
                </Box>
                <Text size="sm" ta="center" c="dimmed">
                  {securityScore === 100 ? 'System is fully secured. All potential threats mitigated.' : 'Security posture slightly degraded. Check active threats.'}
                </Text>
              </Stack>
            </Card>
          </Grid.Col>

          <Grid.Col span={{ base: 12, md: 8 }}>
            <SimpleGrid cols={{ base: 1, sm: 2 }} verticalSpacing="md">
              <Card withBorder p="md" radius="md">
                <Group>
                  <ThemeIcon color="red" variant="light" size="lg">
                    <IconShieldExclamation size={20} />
                  </ThemeIcon>
                  <Stack gap={0}>
                    <Text size="xs" c="dimmed" fw={700}>MITIGATED THREATS</Text>
                    <Text fw={700}>{metrics?.middleware.mitigated_threats?.reduce((acc, val) => acc + val.value, 0) || 0} Blocked Attacks</Text>
                  </Stack>
                </Group>
              </Card>
              <Card withBorder p="md" radius="md">
                <Group>
                  <ThemeIcon color="orange" variant="light" size="lg">
                    <IconAlertTriangle size={20} />
                  </ThemeIcon>
                  <Stack gap={0}>
                    <Text size="xs" c="dimmed" fw={700}>ACTIVE THREATS</Text>
                    <Text fw={700}>{metrics?.active_suspicious_sessions || 0} Suspicious Sessions</Text>
                  </Stack>
                </Group>
              </Card>
              <Card withBorder p="md" radius="md">
                <Group>
                  <ThemeIcon color="blue" variant="light" size="lg">
                    <IconUserCheck size={20} />
                  </ThemeIcon>
                  <Stack gap={0}>
                    <Text size="xs" c="dimmed" fw={700}>UNVERIFIED CLIENTS</Text>
                    <Text fw={700}>{metrics?.active_unverified_clients || 0} In Challenge State</Text>
                  </Stack>
                </Group>
              </Card>
              <Card withBorder p="md" radius="md">
                <Group>
                  <ThemeIcon color="violet" variant="light" size="lg">
                    <IconShieldOff size={20} />
                  </ThemeIcon>
                  <Stack gap={0}>
                    <Text size="xs" c="dimmed" fw={700}>EBPF DROPS</Text>
                    <Text fw={700}>{metrics?.middleware.ebpf_dropped_packets?.reduce((acc, val) => acc + val.value, 0) || 0} L4/L7 Drops</Text>
                  </Stack>
                </Group>
              </Card>
            </SimpleGrid>
          </Grid.Col>
        </Grid>

        <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="xl">
          <ReputationMonitor />
          
          <Card withBorder radius="md">
            <Group justify="space-between" mb="md">
              <Group gap="sm">
                <ThemeIcon color="orange" variant="light">
                  <IconBell size={18} />
                </ThemeIcon>
                <Title order={4}>Alert Playbooks</Title>
              </Group>
              <Button size="xs" variant="subtle" component={Link} to="/settings" rightSection={<IconExternalLink size={12} />}>
                Manage
              </Button>
            </Group>
            
            <Stack gap="xs">
              {globalConfig?.alerting?.playbooks?.map((pb) => (
                <Card key={pb.id} withBorder p="xs" radius="sm">
                  <Group justify="space-between">
                    <Stack gap={2}>
                      <Text size="sm" fw={600}>{pb.name}</Text>
                      <Text size="xs" c="dimmed">
                        Trigger: {pb.event_type} | Score ≥ {pb.threshold} | Action: {pb.action}
                      </Text>
                    </Stack>
                    <Badge size="sm" variant="light" color={pb.action === 'block' ? 'red' : 'blue'}>
                      {pb.action.toUpperCase()}
                    </Badge>
                  </Group>
                </Card>
              ))}
              {(!globalConfig?.alerting?.playbooks || globalConfig.alerting.playbooks.length === 0) && (
                <Text size="sm" c="dimmed" ta="center" py="xl">
                  No active playbooks. Configure them in Settings.
                </Text>
              )}
              <Button variant="light" mt="sm" component={Link} to="/settings">Configure Playbooks</Button>
            </Stack>
          </Card>
        </SimpleGrid>

        <Card withBorder radius="md">
          <Group justify="space-between" mb="lg">
            <Group gap="sm">
              <ThemeIcon color="red" variant="light">
                <IconTarget size={18} />
              </ThemeIcon>
              <Title order={4}>Active Mitigations (Kernel-Level)</Title>
            </Group>
            <TextInput placeholder="Filter mitigated IPs..." leftSection={<IconSearch size={14} />} size="xs" />
          </Group>

          <Table.ScrollContainer minWidth={800}>
            <Table verticalSpacing="sm">
              <Table.Thead bg="var(--mantine-color-default-hover)">
                <Table.Tr>
                  <Table.Th>Source IP</Table.Th>
                  <Table.Th>Type</Table.Th>
                  <Table.Th>Mechanism</Table.Th>
                  <Table.Th>Action Taken</Table.Th>
                  <Table.Th>Expiration</Table.Th>
                  <Table.Th>Control</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {threatsData?.threats?.filter(t => t.mitigated).slice(0, 5).map((t, i) => (
                  <Table.Tr key={i}>
                    <Table.Td><Text size="sm" fw={700} ff="monospace">{t.source}</Text></Table.Td>
                    <Table.Td><Badge size="xs" color="red">{t.type}</Badge></Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        <IconActivity size={12} />
                        <Text size="xs">eBPF / XDP</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td><Text size="xs">Packet Drop (Shun)</Text></Table.Td>
                    <Table.Td><Text size="xs">Permanent</Text></Table.Td>
                    <Table.Td>
                      <Button size="compact-xs" variant="outline" color="blue">Release</Button>
                    </Table.Td>
                  </Table.Tr>
                ))}
                {(!threatsData?.threats || threatsData.threats.filter(t => t.mitigated).length === 0) && (
                  <Table.Tr>
                    <Table.Td colSpan={6}><Text ta="center" py="md" c="dimmed">No active kernel-level mitigations.</Text></Table.Td>
                  </Table.Tr>
                )}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>
      </Stack>
    </Container>
  );
}

