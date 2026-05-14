import { useState } from "react";
import {
  Modal,
  Button,
  Text,
  Stack,
  Textarea,
  Group,
  Paper,
  ScrollArea,
  Loader,
} from "@mantine/core";
import { IconRobot, IconSparkles } from "@tabler/icons-react";
import { apiFetch } from "../hooks/useGateon";

interface LogAIAnalystProps {
  logs: string[];
  opened: boolean;
  onClose: () => void;
}

export function LogAIAnalyst({ logs, opened, onClose }: LogAIAnalystProps) {
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const analyzeLogs = async () => {
    setLoading(true);
    setAnalysis(null);
    try {
      const res = await apiFetch("/AnalyzeLogs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logs: logs.slice(0, 50) }),
      });
      
      if (!res.ok) {
        throw new Error(await res.text());
      }
      
      const data = await res.json();
      setAnalysis(data.analysis);
    } catch (err) {
      setAnalysis("Failed to analyze logs. Please try again later.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={
        <Group gap="xs">
          <IconRobot size={20} color="var(--mantine-color-blue-filled)" />
          <Text fw={700}>AI Log Assistant</Text>
        </Group>
      }
      size="lg"
      radius="md"
    >
      <Stack gap="md">
        <Text size="sm">
          The AI will analyze the last 50 logs to identify patterns, errors, or
          anomalies.
        </Text>

        <Paper withBorder p="xs" bg="light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))">
          <Text size="xs" fw={700} mb={4}>Context (Recent Logs):</Text>
          <ScrollArea h={100}>
            <Text size="xs" style={{ whiteSpace: "pre-wrap" }}>
              {logs.slice(0, 50).join("\n")}
            </Text>
          </ScrollArea>
        </Paper>

        {!analysis && !loading && (
          <Button
            leftSection={<IconSparkles size={16} />}
            onClick={analyzeLogs}
            fullWidth
          >
            Analyze Now
          </Button>
        )}

        {loading && (
          <Group justify="center" p="xl">
            <Stack align="center" gap="xs">
              <Loader size="sm" />
              <Text size="xs" c="dimmed">AI is thinking...</Text>
            </Stack>
          </Group>
        )}

        {analysis && (
          <Paper withBorder p="md" radius="md" bg="light-dark(var(--mantine-color-blue-0), var(--mantine-color-dark-8))">
            <Stack gap="xs">
              <Text fw={600} size="sm">Analysis & Recommendations:</Text>
              <Text size="sm">{analysis}</Text>
              <Button variant="subtle" size="xs" onClick={() => setAnalysis(null)}>
                Clear & Re-analyze
              </Button>
            </Stack>
          </Paper>
        )}
      </Stack>
    </Modal>
  );
}
