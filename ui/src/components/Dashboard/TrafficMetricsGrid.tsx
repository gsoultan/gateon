import { SimpleGrid, Paper, Group, Text, ThemeIcon, Stack, Box } from "@mantine/core";
import { IconArrowUpRight, IconArrowDownRight } from "@tabler/icons-react";
import type { TablerIconsProps } from "@tabler/icons-react";

interface MetricItem {
  label: string;
  value: string;
  icon: React.FC<TablerIconsProps>;
  color: string;
  description: string;
  diff?: number;
}

interface TrafficMetricsGridProps {
  metrics: MetricItem[];
}

export function TrafficMetricsGrid({ metrics }: TrafficMetricsGridProps) {
  return (
    <SimpleGrid cols={{ base: 1, sm: 2, md: 3, lg: 5 }} spacing="md">
      {metrics.map((metric) => (
        <Paper key={metric.label} withBorder p="md" radius="md">
          <Group justify="space-between">
            <ThemeIcon color={metric.color} variant="light" size="lg" radius="md">
              <metric.icon size="1.2rem" stroke={1.5} />
            </ThemeIcon>
            {metric.diff !== undefined && (
              <Group gap={2}>
                <Text color={metric.diff > 0 ? "teal" : "red"} size="sm" fw={700}>
                  {metric.diff > 0 ? "+" : ""}
                  {metric.diff}%
                </Text>
                {metric.diff > 0 ? (
                  <IconArrowUpRight size="1rem" stroke={1.5} color="var(--mantine-color-teal-filled)" />
                ) : (
                  <IconArrowDownRight size="1rem" stroke={1.5} color="var(--mantine-color-red-filled)" />
                )}
              </Group>
            )}
          </Group>

          <Stack gap={0} mt="md">
            <Text size="xs" c="dimmed" fw={700} style={{ textTransform: "uppercase" }}>
              {metric.label}
            </Text>
            <Text fw={700} size="xl">
              {metric.value}
            </Text>
          </Stack>

          <Text size="xs" c="dimmed" mt={7}>
            {metric.description}
          </Text>
        </Paper>
      ))}
    </SimpleGrid>
  );
}
