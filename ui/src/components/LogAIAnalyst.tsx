// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import {
  Alert,
  Modal,
  Button,
  Text,
  Stack,
  Group,
  Paper,
  ScrollArea,
  Loader,
} from "@mantine/core";
import { IconAlertCircle, IconRobot, IconSparkles } from "@tabler/icons-react";
import { apiFetch } from "../hooks/useGateon";

/** How many of the most recent lines are analyzed. */
const ANALYZED_LINES = 50;

interface LogAIAnalystProps {
  /** The lines the operator is looking at, newest first, filters applied. */
  logs: string[];
  opened: boolean;
  onClose: () => void;
}

interface LogAnalysis {
  analysis: string;
  /** The gateway's own tally of the same lines. */
  local?: string;
  /** "local", or "provider:model" when a configured AI provider answered. */
  engine?: string;
  /** Why a configured provider did not answer. */
  notice?: string;
}

export function LogAIAnalyst({ logs, opened, onClose }: LogAIAnalystProps) {
  const [result, setResult] = useState<LogAnalysis | null>(null);
  const [failed, setFailed] = useState(false);
  const [loading, setLoading] = useState(false);
  const lines = logs.slice(0, ANALYZED_LINES);

  const reset = () => {
    setResult(null);
    setFailed(false);
  };

  // A verdict belongs to the lines it was given: closing the dialog drops it,
  // so reopening it on newer lines does not show the old one beside them.
  const close = () => {
    reset();
    onClose();
  };

  const analyzeLogs = async () => {
    setLoading(true);
    reset();
    try {
      const res = await apiFetch("/v1/AnalyzeLogs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logs: lines }),
      });
      if (!res.ok) {
        setFailed(true);
        return;
      }
      setResult(await res.json());
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  };

  const provider = result?.engine && result.engine !== "local" ? result.engine : null;

  return (
    <Modal
      opened={opened}
      onClose={close}
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
          Analyzes the {lines.length} most recent log lines in view (filters applied) for errors, refused requests
          and probes.
        </Text>

        <Paper withBorder p="xs" bg="light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))">
          <Text size="xs" fw={700} mb={4}>Context (Recent Logs):</Text>
          <ScrollArea h={100}>
            <Text size="xs" style={{ whiteSpace: "pre-wrap" }}>
              {lines.join("\n")}
            </Text>
          </ScrollArea>
        </Paper>

        {!result && !loading && (
          <Button
            leftSection={<IconSparkles size={16} />}
            onClick={analyzeLogs}
            disabled={lines.length === 0}
            fullWidth
          >
            Analyze Now
          </Button>
        )}

        {failed && (
          <Alert icon={<IconAlertCircle size={16} />} color="red" title="Analysis failed">
            The logs could not be analyzed. Try again in a moment.
          </Alert>
        )}

        {loading && (
          <Group justify="center" p="xl">
            <Stack align="center" gap="xs">
              <Loader size="sm" />
              <Text size="xs" c="dimmed">Analyzing...</Text>
            </Stack>
          </Group>
        )}

        {result?.notice && (
          <Alert icon={<IconAlertCircle size={16} />} color="yellow" title="AI provider unavailable">
            {result.notice}
          </Alert>
        )}

        {result && (
          <Paper withBorder p="md" radius="md" bg="light-dark(var(--mantine-color-blue-0), var(--mantine-color-dark-8))">
            <Stack gap="xs">
              <Text fw={600} size="sm">
                {provider ? `Analysis by ${provider}` : "Analysis & Recommendations (Local Mode)"}
              </Text>
              <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{result.analysis}</Text>
              {provider && result.local && (
                <Text size="xs" c="dimmed">
                  Local tally: {result.local}
                </Text>
              )}
              <Button variant="subtle" size="xs" onClick={reset}>
                Clear & Re-analyze
              </Button>
            </Stack>
          </Paper>
        )}
      </Stack>
    </Modal>
  );
}
