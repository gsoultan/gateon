import React from 'react';
import { 
  Grid, 
  Card, 
  Title, 
  Text, 
  Stack, 
  SimpleGrid, 
  Box, 
  Table, 
  Avatar, 
  Badge, 
  ThemeIcon, 
  Group,
  Skeleton,
} from '@mantine/core';
import { AreaChart, BarChart, DonutChart } from '@mantine/charts';
import { IconMapPin, IconActivity, IconTarget, IconCpu } from '@tabler/icons-react';
import type { MetricsSnapshot, LabeledCount, DonutChartDataItem, HeavyHitter, IPStat } from '../../types/metrics';
import { safeToFixed, safeToLocaleString } from '../../utils/format';

interface CountryData {
  country: string;
  threats: number;
}

interface TrendData {
  date: string;
  threats: number;
  fullDate: string;
}

interface AnalyticsTabProps {
  metrics: MetricsSnapshot | null;
  trendData: TrendData[];
  countryData: CountryData[];
  threatTypeData: DonutChartDataItem[];
  totalThreats: number;
}

export function AnalyticsTab({ metrics, trendData, countryData, threatTypeData, totalThreats }: AnalyticsTabProps) {
  return (
    <Stack gap="lg">
      <Card withBorder radius="md">
        <Group justify="space-between" mb="md">
          <Stack gap={0}>
            <Title order={4}>Attack Trends (Last 24 Hours)</Title>
            <Text size="xs" c="dimmed">Time-series analysis of intercepted threats</Text>
          </Stack>
          <ThemeIcon variant="light" color="blue">
            <IconActivity size={18} />
          </ThemeIcon>
        </Group>
        <Box h={300} w="100%" style={{ minWidth: 0 }}>
          <AreaChart
            h={300}
            data={trendData}
            dataKey="date"
            series={[{ name: 'threats', color: 'red.7', label: 'Threats Detected' }]}
            curveType="monotone"
            withDots
            dotProps={{ r: 3, strokeWidth: 1 }}
            activeDotProps={{ r: 5, strokeWidth: 2 }}
            strokeWidth={2}
            withGradient
            gridAxis="xy"
            withXAxis
            withYAxis
            withTooltip
            tooltipAnimationDuration={200}
            type="default"
            connectNulls
          />
        </Box>
      </Card>

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md">
            <Title order={4} mb="md">Geographic Threat Distribution</Title>
            <Box h={300} w="100%" style={{ minWidth: 0 }}>
              <BarChart
                h={300}
                data={countryData}
                dataKey="country"
                series={[{ name: 'threats', color: 'blue.7', label: 'Attacks' }]}
                orientation="vertical"
                gridAxis="none"
                yAxisProps={{ width: 80 }}
                withTooltip
                barProps={{ radius: [0, 4, 4, 0] }}
              />
            </Box>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md">
            <Title order={4} mb="md">Threat Classification Analysis</Title>
            <SimpleGrid cols={2}>
              <Box h={250} w="100%" style={{ minWidth: 0 }}>
                <DonutChart
                  h={200}
                  thickness={25}
                  data={threatTypeData}
                  withTooltip
                  chartLabel={`${totalThreats} Total`}
                  strokeWidth={2}
                  paddingAngle={4}
                />
              </Box>
              <Stack gap="xs" justify="center">
                {threatTypeData.map((item) => {
                  const colorParts = item.color.split('.');
                  const baseColor = colorParts[0];
                  const shade = colorParts[1] || '7';
                  return (
                    <Group key={item.name} justify="space-between">
                      <Group gap="xs">
                        <Box w={10} h={10} style={{ borderRadius: '50%', backgroundColor: `var(--mantine-color-${baseColor}-${shade})` }} />
                        <Text size="xs" fw={500}>{item.name}</Text>
                      </Group>
                      <Text size="xs" fw={700}>{item.value}</Text>
                    </Group>
                  );
                })}
              </Stack>
            </SimpleGrid>
          </Card>
        </Grid.Col>
      </Grid>

      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Card withBorder radius="md">
          <Title order={4} mb="md">Top Attack Sources</Title>
          <Table.ScrollContainer minWidth={300}>
            <Table>
              <Table.Tbody>
                {!metrics ? (
                  Array(3).fill(0).map((_, i) => (
                    <Table.Tr key={i}>
                      <Table.Td><Skeleton height={24} circle mb={4} /><Skeleton height={12} width="60%" /></Table.Td>
                      <Table.Td ta="right"><Skeleton height={20} width={40} radius="xl" /></Table.Td>
                    </Table.Tr>
                  ))
                ) : metrics.security?.topThreatSources?.length === 0 ? (
                  <Table.Tr>
                    <Table.Td colSpan={2} ta="center" py="xl">
                      <Text size="sm" c="dimmed">No attack sources detected.</Text>
                    </Table.Td>
                  </Table.Tr>
                ) : (
                  metrics.security?.topThreatSources?.map((s: LabeledCount) => (
                    <Table.Tr key={s.label}>
                      <Table.Td>
                        <Group gap="sm">
                          <Avatar size="sm" radius="xl" color="red"><IconMapPin size={14} /></Avatar>
                          <Stack gap={0}>
                            <Text size="sm" fw={700}>{s.label}</Text>
                            <Text size="xs" c="dimmed">ASN: {s.subtext || 'Unknown'}</Text>
                          </Stack>
                        </Group>
                      </Table.Td>
                      <Table.Td ta="right">
                        <Badge color="red" variant="light">{s.value}</Badge>
                      </Table.Td>
                    </Table.Tr>
                  ))
                )}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>

        <Card withBorder radius="md">
          <Title order={4} mb="md">Kernel-Level Network Telemetry</Title>
          <Text size="xs" c="dimmed" mb="sm">Top IPs tracked via eBPF/XDP offloading</Text>
          <Table.ScrollContainer minWidth={300}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Source IP</Table.Th>
                  <Table.Th ta="right">Packet Count</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {!metrics ? (
                  Array(3).fill(0).map((_, i) => (
                    <Table.Tr key={i}>
                      <Table.Td><Skeleton height={24} circle mb={4} /><Skeleton height={12} width="50%" /></Table.Td>
                      <Table.Td ta="right"><Skeleton height={20} width={60} /></Table.Td>
                    </Table.Tr>
                  ))
                ) : (!metrics.security?.ebpfTopIPs || metrics.security.ebpfTopIPs.length === 0) ? (
                  <Table.Tr>
                    <Table.Td colSpan={2} ta="center" py="xl">
                      <Text size="sm" c="dimmed">No kernel telemetry available (eBPF might be disabled).</Text>
                    </Table.Td>
                  </Table.Tr>
                ) : (
                  metrics.security?.ebpfTopIPs?.map((s: IPStat) => (
                    <Table.Tr key={s.ip}>
                      <Table.Td>
                        <Group gap="sm">
                          <ThemeIcon size="sm" radius="xl" color="teal" variant="light"><IconCpu size={14} /></ThemeIcon>
                          <Text size="sm" fw={700} ff="monospace">{s.ip}</Text>
                        </Group>
                      </Table.Td>
                      <Table.Td ta="right">
                        <Text size="sm" fw={500}>{safeToLocaleString(s.count)}</Text>
                      </Table.Td>
                    </Table.Tr>
                  ))
                )}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>

        <Card withBorder radius="md">
          <Title order={4} mb="md">Heaviest Hitters (Subnets)</Title>
          <Stack gap="sm">
            {!metrics ? (
              Array(2).fill(0).map((_, i) => (
                <Box key={i} p="xs" style={{ border: '1px solid var(--mantine-color-default-border)', borderRadius: 'var(--mantine-radius-sm)' }}>
                  <Group justify="space-between">
                    <Group gap="xs" style={{ flex: 1 }}>
                      <Skeleton height={24} circle />
                      <div style={{ flex: 1 }}>
                        <Skeleton height={12} width="40%" mb={6} />
                        <Skeleton height={10} width="60%" />
                      </div>
                    </Group>
                    <Skeleton height={20} width={60} radius="xl" />
                  </Group>
                </Box>
              ))
            ) : metrics.security?.heavyHitters?.length === 0 ? (
              <Text size="sm" c="dimmed" ta="center" py="xl">No malicious subnets detected.</Text>
            ) : (
              metrics.security?.heavyHitters?.map((h: HeavyHitter) => (
                <Box key={h.network} p="xs" style={{ border: '1px solid var(--mantine-color-red-light)', borderRadius: 'var(--mantine-radius-sm)' }} bg="var(--mantine-color-red-light)">
                  <Group justify="space-between">
                    <Group gap="xs">
                      <ThemeIcon color="red" variant="subtle" size="sm">
                        <IconTarget size={14} />
                      </ThemeIcon>
                      <Stack gap={0}>
                        <Text size="sm" fw={700} ff="monospace">{h.network}</Text>
                        <Text size="xs" c="dimmed">{h.count} threats ({safeToFixed(h.percentage, 1)}%)</Text>
                      </Stack>
                    </Group>
                    <Badge color="red" variant="filled">CRITICAL</Badge>
                  </Group>
                </Box>
              ))
            )}
          </Stack>
        </Card>
      </SimpleGrid>
    </Stack>
  );
}
