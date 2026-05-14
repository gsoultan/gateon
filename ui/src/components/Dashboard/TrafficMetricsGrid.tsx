import React, { memo } from "react";
import { SimpleGrid, Paper, Group, Text, ThemeIcon, Stack, Box, Badge } from "@mantine/core";
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

export const TrafficMetricsGrid = memo(function TrafficMetricsGrid({
  metrics,
}: TrafficMetricsGridProps) {
  return (
    <SimpleGrid cols={{ base: 1, sm: 2, md: 3, lg: 5 }} spacing="md">
      {metrics.map((metric) => (
        <Paper
          key={metric.label}
          withBorder
          p="md"
          radius="md"
          shadow="xs"
          style={{
            transition: "all 0.2s ease",
            borderTop: `3px solid var(--mantine-color-${metric.color}-6)`,
          }}
          className="hover:shadow-md hover:-translate-y-0.5"
        >
          <Group justify="space-between" mb="xs">
            <ThemeIcon
              color={metric.color}
              variant="light"
              size="lg"
              radius="md"
            >
              <metric.icon size="1.2rem" stroke={1.5} />
            </ThemeIcon>
            {metric.diff !== undefined && (
              <Badge
                color={metric.diff > 0 ? "teal" : "red"}
                variant="light"
                size="sm"
                leftSection={
                  metric.diff > 0 ? (
                    <IconArrowUpRight size="0.8rem" />
                  ) : (
                    <IconArrowDownRight size="0.8rem" />
                  )
                }
              >
                {Math.abs(metric.diff)}%
              </Badge>
            )}
          </Group>

          <Stack gap={0} mt="md">
            <Text
              size="xs"
              c="dimmed"
              fw={700}
              style={{ textTransform: "uppercase", letterSpacing: 0.5 }}
            >
              {metric.label}
            </Text>
            <Text fw={800} size="xl" style={{ letterSpacing: -0.5 }}>
              {metric.value}
            </Text>
          </Stack>

          <Text size="xs" c="dimmed" mt={4}>
            {metric.description}
          </Text>
        </Paper>
      ))}
    </SimpleGrid>
  );
});
