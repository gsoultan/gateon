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
      // Stub for AI analysis. In a real implementation, this would call an LLM API.
      // We pass the last 10 logs for context.
      const logContext = logs.slice(0, 10).join("\n");
      
      // Simulate API delay
      await new Promise((resolve) => setTimeout(resolve, 2000));
      
      const hasErrors = logContext.includes("error") || logContext.includes("404") || logContext.includes("500");
      
      if (hasErrors) {
        setAnalysis(
          "I've detected some errors in your logs. It seems several requests returned a 404 or 500 status code. " +
          "Recommendation: Check if the backend services are healthy and if the route rules match the expected paths. " +
          "Also, verify if the 'upstream' targets are reachable from the Gateon instance."
        );
      } else {
        setAnalysis(
          "Traffic seems healthy. Latency is within normal bounds. No significant errors detected in the recent logs."
        );
      }
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
          The AI will analyze the last 10 logs to identify patterns, errors, or
          anomalies.
        </Text>

        <Paper withBorder p="xs" bg="gray.0">
          <Text size="xs" fw={700} mb={4}>Context (Recent Logs):</Text>
          <ScrollArea h={100}>
            <Text size="xs" style={{ whiteSpace: "pre-wrap" }}>
              {logs.slice(0, 10).join("\n")}
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
          <Paper withBorder p="md" radius="md" bg="blue.0">
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
