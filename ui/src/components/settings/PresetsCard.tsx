import { Card, Title, Text, Stack, Button, Group, Paper } from "@mantine/core";
import { IconRocket } from "@tabler/icons-react";

interface PresetsCardProps {
  disabled: boolean;
  onApply: (preset: "development" | "production" | "high-throughput") => void;
}

export function PresetsCard({ disabled, onApply }: PresetsCardProps) {
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="md">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="teal.6">
            <IconRocket size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              Quick Presets
            </Title>
            <Text c="dimmed" size="xs">
              One-click apply common configuration scenarios.
            </Text>
          </div>
        </Group>
        <Group gap="sm">
          <Button
            variant="light"
            color="gray"
            size="sm"
            radius="md"
            disabled={disabled}
            onClick={() => onApply("development")}
          >
            Development
          </Button>
          <Button
            variant="light"
            color="blue"
            size="sm"
            radius="md"
            disabled={disabled}
            onClick={() => onApply("production")}
          >
            Production
          </Button>
          <Button
            variant="light"
            color="teal"
            size="sm"
            radius="md"
            disabled={disabled}
            onClick={() => onApply("high-throughput")}
          >
            High-Throughput (100k+ req/s)
          </Button>
        </Group>
        <Text size="xs" c="dimmed">
          Presets update Gateway Configuration below. Remember to save after applying.
        </Text>
      </Stack>
    </Card>
  );
}
