import { Card, Title, Text, Stack, TextInput, NumberInput, Button, Group, Divider, Paper } from "@mantine/core";
import { IconAdjustments } from "@tabler/icons-react";

interface GeneralSettingsCardProps {
  apiUrlDraft: string;
  setApiUrlDraft: (v: string) => void;
  refreshIntervalDraft: number;
  setRefreshIntervalDraft: (v: number) => void;
  generalSavedOk: boolean;
  onSave: () => void;
}

export function GeneralSettingsCard({
  apiUrlDraft,
  setApiUrlDraft,
  refreshIntervalDraft,
  setRefreshIntervalDraft,
  generalSavedOk,
  onSave,
}: GeneralSettingsCardProps) {
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="lg">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="blue.6">
            <IconAdjustments size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              General Settings
            </Title>
            <Text c="dimmed" size="xs">
              Configure UI behavior and connection to the gateway.
            </Text>
          </div>
        </Group>
        <Divider />
        <Stack gap="md">
          <TextInput
            label="Gateway API URL"
            description="The base URL of the Gateon Management API"
            placeholder="http://localhost:8080"
            value={apiUrlDraft}
            onChange={(e) => setApiUrlDraft(e.currentTarget.value)}
            radius="md"
          />
          <NumberInput
            label="Metrics Refresh Interval (seconds)"
            description="How often to poll the gateway for real-time metrics"
            min={1}
            max={60}
            value={refreshIntervalDraft}
            onChange={(val) =>
              setRefreshIntervalDraft(typeof val === "number" ? val : 10)
            }
            radius="md"
          />
        </Stack>
        <Group justify="flex-end" mt="md" gap="sm">
          {generalSavedOk && (
            <Text size="sm" c="green" fw={500}>
              Saved
            </Text>
          )}
          <Button onClick={onSave} radius="md" px="xl">
            Save Settings
          </Button>
        </Group>
      </Stack>
    </Card>
  );
}
