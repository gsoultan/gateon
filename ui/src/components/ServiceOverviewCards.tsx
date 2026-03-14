import { Card, SimpleGrid, Text, Title, Paper } from "@mantine/core";
import {
  IconCheck,
  IconAlertTriangle,
  IconRoute,
  IconPlugConnected,
} from "@tabler/icons-react";
import { useAggStats } from "../hooks/useGateon";

export function ServiceOverviewCards() {
  const { data: agg, isLoading } = useAggStats();

  const healthy = agg?.healthy_targets ?? 0;
  const atRisk =
    (agg?.open_circuits ?? 0) + (agg?.half_open_circuits ?? 0);
  const total = agg?.total_targets ?? 0;
  const healthyRoutesRatio =
    total > 0 ? Math.round((healthy / total) * 100) : 100;

  const cards: Array<{
    label: string;
    value: number | string;
    total?: number;
    color: "green" | "red" | "teal" | "yellow" | "blue";
    icon: typeof IconCheck;
    description: string;
  }> = [
    {
      label: "Healthy Targets",
      value: healthy,
      total,
      color: "green",
      icon: IconCheck,
      description: "Targets with CLOSED circuit",
    },
    {
      label: "At-Risk Targets",
      value: atRisk,
      color: "red",
      icon: IconAlertTriangle,
      description: "OPEN or HALF-OPEN circuits",
    },
    {
      label: "Health Ratio",
      value: `${healthyRoutesRatio}%`,
      color: healthyRoutesRatio >= 80 ? "teal" : healthyRoutesRatio >= 50 ? "yellow" : "red",
      icon: IconRoute,
      description: "Healthy / total targets",
    },
    {
      label: "Active Connections",
      value: agg?.active_connections ?? 0,
      color: "blue" as const,
      icon: IconPlugConnected,
      description: "In-flight requests",
    },
  ];

  if (isLoading) return null;

  return (
    <Card shadow="xs" padding="lg" radius="lg" withBorder>
      <Title order={5} fw={700} mb="md" c="dimmed" style={{ letterSpacing: 1 }}>
        SERVICE OVERVIEW
      </Title>
      <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
        {cards.map((c) => (
          <Paper
            key={c.label}
            p="md"
            radius="md"
            withBorder
            style={{
              borderLeftWidth: 3,
              borderLeftColor: `var(--mantine-color-${c.color}-6)`,
            }}
          >
            <c.icon
              size={20}
              color={`var(--mantine-color-${c.color}-6)`}
              style={{ marginBottom: 4 }}
            />
            <Text size="xs" c="dimmed" fw={700} style={{ textTransform: "uppercase" }}>
              {c.label}
            </Text>
            <Text size="xl" fw={800} c={`${c.color}.6`}>
            {c.value}
            {c.total != null && c.total > 0 && (
                <Text component="span" size="sm" fw={500} c="dimmed" ml={4}>
                  / {c.total}
                </Text>
              )}
            </Text>
            {c.description && (
              <Text size="xs" c="dimmed" mt={2}>
                {c.description}
              </Text>
            )}
          </Paper>
        ))}
      </SimpleGrid>
    </Card>
  );
}
