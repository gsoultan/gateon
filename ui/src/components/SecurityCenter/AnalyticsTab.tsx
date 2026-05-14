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
  Paper 
} from '@mantine/core';
import { AreaChart, BarChart, DonutChart } from '@mantine/charts';
import { IconMapPin, IconActivity, IconTarget } from '@tabler/icons-react';
import type { MetricsSnapshot, TrafficSample, LabeledCount, DonutChartDataItem } from '../../types/metrics';

interface CountryData {
  country: string;
  threats: number;
}

interface AnalyticsTabProps {
  metrics: MetricsSnapshot | null;
  trendData: TrafficSample[];
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
            minWidth={0}
            data={trendData}
            dataKey="ts"
            series={[{ name: 'threats', color: 'red.6', label: 'Threats Detected' }]}
            curveType="monotone"
            withDots={false}
            withGradient
            gridAxis="xy"
            withXAxis
            withYAxis
            withTooltip
            tooltipAnimationDuration={200}
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
                minWidth={0}
                data={countryData}
                dataKey="country"
                series={[{ name: 'threats', color: 'blue.6', label: 'Attacks' }]}
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
                  minWidth={0}
                  thickness={25}
                  data={threatTypeData}
                  withTooltip
                  chartLabel={`${totalThreats} Total`}
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
                {metrics?.security?.top_threat_sources?.map((s: LabeledCount) => (
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
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>

        <Card withBorder radius="md">
          <Title order={4} mb="md">Heaviest Hitters (Subnets)</Title>
          <Stack gap="sm">
            {metrics?.security?.heavy_hitters?.map((h: string) => (
              <Box key={h} p="xs" style={{ border: '1px solid var(--mantine-color-red-light)', borderRadius: 'var(--mantine-radius-sm)' }} bg="var(--mantine-color-red-light)">
                <Group justify="space-between">
                  <Group gap="xs">
                    <ThemeIcon color="red" variant="subtle" size="sm">
                      <IconTarget size={14} />
                    </ThemeIcon>
                    <Text size="sm" fw={700} ff="monospace">{h}</Text>
                  </Group>
                  <Badge color="red" variant="filled">CRITICAL</Badge>
                </Group>
              </Box>
            ))}
            {(!metrics?.security?.heavy_hitters || metrics.security.heavy_hitters.length === 0) && (
              <Text size="sm" c="dimmed" ta="center" py="xl">No malicious subnets detected.</Text>
            )}
          </Stack>
        </Card>
      </SimpleGrid>
    </Stack>
  );
}
