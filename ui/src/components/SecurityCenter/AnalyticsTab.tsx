import React, { useMemo } from 'react';
import { Grid, Card, Title, Text, Stack, SimpleGrid, Box, Table, Avatar, Badge, ThemeIcon } from '@mantine/core';
import { AreaChart, BarChart, DonutChart } from '@mantine/charts';
import { IconMapPin, IconActivity, IconTarget, IconChartBar } from '@tabler/icons-react';
import { format } from 'date-fns';

interface AnalyticsTabProps {
  metrics: any;
  trendData: any[];
  countryData: any[];
  threatTypeData: any[];
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
        <Box h={300}>
          <AreaChart
            h={300}
            data={trendData}
            dataKey="date"
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
            <Box h={300}>
              <BarChart
                h={300}
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
              <Box h={250}>
                <DonutChart
                  size={200}
                  thickness={25}
                  data={threatTypeData}
                  withTooltip
                  chartLabel={`${totalThreats} Total`}
                />
              </Box>
              <Stack gap="xs" justify="center">
                {threatTypeData.map((item) => (
                  <Group key={item.name} justify="space-between">
                    <Group gap="xs">
                      <Box w={10} h={10} style={{ borderRadius: '50%', backgroundColor: `var(--mantine-color-${item.color.split('.')[0]}-7)` }} />
                      <Text size="xs" fw={500}>{item.name}</Text>
                    </Group>
                    <Text size="xs" fw={700}>{item.value}</Text>
                  </Group>
                ))}
              </Stack>
            </SimpleGrid>
          </Card>
        </Grid.Col>
      </Grid>

      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Card withBorder radius="md">
          <Title order={4} mb="md">Top Attack Sources</Title>
          <Table.ScrollContainer minWidth={300}>
            <Table variant="vertical">
              <Table.Tbody>
                {metrics?.security?.top_threat_sources?.map((s: any) => (
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
              <Paper key={h} withBorder p="xs" radius="sm" bg="var(--mantine-color-red-light)">
                <Group justify="space-between">
                  <Group gap="xs">
                    <ThemeIcon color="red" variant="subtle" size="sm">
                      <IconTarget size={14} />
                    </ThemeIcon>
                    <Text size="sm" fw={700} ff="monospace">{h}</Text>
                  </Group>
                  <Badge color="red" variant="filled">CRITICAL</Badge>
                </Group>
              </Paper>
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

const Group = ({ children, justify, mb, mt, gap, wrap, align, grow, style }: any) => (
  <Box style={{ display: 'flex', justifyContent: justify, marginBottom: mb, marginTop: mt, gap, flexWrap: wrap, alignItems: align, flexGrow: grow ? 1 : 0, ...style }}>
    {children}
  </Box>
);
