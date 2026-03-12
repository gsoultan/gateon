import { Suspense, lazy } from "react";
import { Stack, Title, Text, Group } from "@mantine/core";

const PathStatsTable = lazy(() =>
  import("../components/PathStatsTable").then((m) => ({
    default: m.PathStatsTable,
  })),
);

const FALLBACK = <Text>Loading path metrics...</Text>;

export default function PathMetricsPage() {
  return (
    <Stack gap="lg">
      <Group justify="space-between" align="center">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            Path Metrics
          </Title>
          <Text c="dimmed" size="sm" fw={500}>
            Detailed response time and request count statistics per host and
            path.
          </Text>
        </div>
      </Group>

      <Suspense fallback={FALLBACK}>
        <PathStatsTable />
      </Suspense>
    </Stack>
  );
}
