import { Paper, Text, Group, Box, Badge } from "@mantine/core";
import { BarChart } from "@mantine/charts";

interface DistributionDatum {
  group: string;
  requests: number;
}

interface DistributionCardProps {
  title: string;
  subtitle: string;
  data: DistributionDatum[];
  valueFormatter?: (value: number) => string;
  color?: string;
}

export function DistributionCard({
  title,
  subtitle,
  data,
  valueFormatter = (v) => `${Math.round(v)} req`,
  color = "blue.6",
}: DistributionCardProps) {
  return (
    <Paper p="md" radius="md" withBorder>
      <Group justify="space-between" mb="xs">
        <div>
          <Text size="sm" fw={700}>
            {title}
          </Text>
          <Text size="xs" c="dimmed">
            {subtitle}
          </Text>
        </div>
        {data.length > 0 && (
          <Badge variant="outline" size="xs">
            {data.length} items
          </Badge>
        )}
      </Group>

      {data.length > 0 ? (
        <Box mt="md">
          <BarChart
            h={180}
            minWidth={0}
            data={data}
            dataKey="group"
            withLegend={false}
            gridAxis="y"
            tickLine="none"
            series={[{ name: "requests", color }]}
            valueFormatter={valueFormatter}
          />
        </Box>
      ) : (
        <Box h={180} style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Text size="sm" c="dimmed">
            No data available.
          </Text>
        </Box>
      )}
    </Paper>
  );
}
