// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import {
  Alert,
  Button,
  Card,
  Divider,
  Group,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  TextInput,
  ThemeIcon,
  Title,
} from "@mantine/core";
import { IconAlertCircle, IconCheck, IconPlugConnected, IconSparkles } from "@tabler/icons-react";
import type { AIConfig, GlobalConfig } from "../../types/gateon";
import { apiFetch } from "../../hooks/useGateon";
import { useAdminOnlySetting } from "../../hooks/usePermissions";
import { StoredSecretInput } from "./StoredSecretInput";
import { AdminOnlyNote } from "./adminOnly/AdminOnlyNote";

const PROVIDERS = [
  { value: "anthropic", label: "Anthropic (Claude)" },
  { value: "openai", label: "OpenAI (ChatGPT)" },
  { value: "openai_compatible", label: "OpenAI-compatible server" },
];

/** What each provider uses when a field is left empty; mirrors internal/ai/llm. */
const DEFAULTS: Record<string, { model: string; baseUrl: string }> = {
  anthropic: { model: "claude-opus-5-5", baseUrl: "https://api.anthropic.com" },
  openai: { model: "gpt-5", baseUrl: "https://api.openai.com/v1" },
  openai_compatible: { model: "", baseUrl: "" },
};

type TestResult = { ok: boolean; message: string };

interface AISettingsCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

/**
 * The language model the AI Advisory and Log Assistant may ask to narrate
 * the local analysis (ADR 0070). Administrator-only: it decides where
 * findings, and with log sharing the gateway's log lines, are sent.
 */
export function AISettingsCard({ config, onChange, disabled: formDisabled }: AISettingsCardProps) {
  const { disabled, locked } = useAdminOnlySetting(!!formDisabled);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<TestResult | null>(null);
  const ai: AIConfig = config.ai || {};
  const provider = ai.provider || "anthropic";
  const defaults = DEFAULTS[provider] ?? DEFAULTS.anthropic;
  const compatible = provider === "openai_compatible";

  const update = (value: Partial<AIConfig>) => {
    setResult(null);
    onChange({ ...config, ai: { ...ai, ...value } });
  };

  // The test calls the provider with the saved settings, never the ones on
  // screen: the key is not in the browser to send.
  const runTest = async () => {
    setTesting(true);
    setResult(null);
    try {
      const res = await apiFetch("/v1/ai-advisory/test", { method: "POST" });
      if (!res.ok) {
        setResult({
          ok: false,
          message: res.status === 403 ? "You do not have permission to test the provider." : "The test could not be run.",
        });
        return;
      }
      const data: { ok: boolean; message: string } = await res.json();
      setResult({ ok: !!data.ok, message: data.message || "" });
    } catch {
      setResult({ ok: false, message: "The test could not be run." });
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="lg">
        <Group justify="space-between" wrap="nowrap" align="flex-start">
          <Group wrap="nowrap" align="flex-start">
            <ThemeIcon size="xl" radius="md" variant="light" color="violet">
              <IconSparkles size={24} />
            </ThemeIcon>
            <Stack gap={2}>
              <Title order={3}>AI Provider</Title>
              <Text size="sm" c="dimmed">
                Let Claude, ChatGPT or a self-hosted model narrate the AI Advisory and Log Assistant. The local
                analysis always runs, and is shown whenever the provider cannot answer.
              </Text>
            </Stack>
          </Group>
          <Switch
            checked={!!ai.enabled}
            onChange={(e) => update({ enabled: e.currentTarget.checked, provider })}
            aria-label="Use an AI provider"
            disabled={disabled}
            size="lg"
          />
        </Group>
        <AdminOnlyNote locked={locked} />

        {ai.enabled && (
          <>
            <Divider />
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg" verticalSpacing="md">
              <Select
                label="Provider"
                data={PROVIDERS}
                value={provider}
                allowDeselect={false}
                onChange={(value) => value && update({ provider: value })}
                disabled={disabled}
              />
              <TextInput
                label="Model"
                placeholder={defaults.model || "e.g. llama3.1"}
                description={compatible ? "Required: the model id your server serves." : "Leave empty for the default."}
                value={ai.model || ""}
                onChange={(e) => update({ model: e.currentTarget.value })}
                required={compatible}
                disabled={disabled}
              />
              <TextInput
                label="Base URL"
                placeholder={defaults.baseUrl || "http://127.0.0.1:11434/v1"}
                description="https://, or http:// to a loopback or private address."
                value={ai.baseUrl || ""}
                onChange={(e) => update({ baseUrl: e.currentTarget.value })}
                required={compatible}
                disabled={disabled}
              />
              <StoredSecretInput
                label="API key"
                value={ai.apiKey}
                onChange={(apiKey) => update({ apiKey })}
                clearable={compatible}
                required={!compatible}
                placeholder="Paste a key, or $env:ANTHROPIC_API_KEY"
                description="Stored on the gateway and never shown again."
                disabled={disabled}
              />
              <NumberInput
                label="Timeout"
                description="Per call. Empty uses 30 seconds; at most 120."
                min={0}
                max={120}
                suffix=" s"
                value={ai.timeoutSeconds || ""}
                onChange={(v) => update({ timeoutSeconds: Number(v) || 0 })}
                disabled={disabled}
              />
              <NumberInput
                label="Output token limit"
                description="Per call. Empty uses 4096; at most 16000."
                min={0}
                max={16000}
                step={256}
                value={ai.maxOutputTokens || ""}
                onChange={(v) => update({ maxOutputTokens: Number(v) || 0 })}
                disabled={disabled}
              />
            </SimpleGrid>

            <Group justify="space-between" wrap="nowrap" align="flex-start">
              <Stack gap={2}>
                <Text fw={500}>Share log lines with the provider</Text>
                <Text size="xs" c="dimmed">
                  Off: the Log Assistant sends only the local tally. On: it also sends the lines you analyze, with
                  credentials masked. Log lines contain client addresses and request paths.
                </Text>
              </Stack>
              <Switch
                checked={!!ai.shareLogLines}
                onChange={(e) => update({ shareLogLines: e.currentTarget.checked })}
                aria-label="Share log lines with the provider"
                disabled={disabled}
              />
            </Group>

            <Group justify="space-between" wrap="nowrap">
              <Text size="xs" c="dimmed">
                Save first: the test uses the saved settings.
              </Text>
              <Button
                variant="light"
                leftSection={<IconPlugConnected size={16} />}
                onClick={runTest}
                loading={testing}
                disabled={disabled}
              >
                Test connection
              </Button>
            </Group>
            {result && (
              <Alert
                color={result.ok ? "green" : "red"}
                icon={result.ok ? <IconCheck size={16} /> : <IconAlertCircle size={16} />}
                title={result.ok ? "Connected" : "Not connected"}
              >
                {result.message}
              </Alert>
            )}
          </>
        )}
      </Stack>
    </Card>
  );
}
