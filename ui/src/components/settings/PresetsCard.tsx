// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import { Button, Card, Code, Group, Modal, Paper, Stack, Table, Text, Title } from "@mantine/core";
import { IconRocket } from "@tabler/icons-react";
import type { GlobalConfig } from "../../types/gateon";
import { presetChanges, type PresetChange } from "./presetDiff";
import { withPreset, type SettingsPreset } from "./tabs/settingsState";

interface PresetsCardProps {
  config: GlobalConfig;
  disabled: boolean;
  onApply: (preset: SettingsPreset) => void;
}

const PRESETS: ReadonlyArray<{ id: SettingsPreset; label: string; summary: string }> = [
  { id: "development", label: "Development", summary: "Debug logging as text, TLS, Redis and OpenTelemetry off." },
  { id: "production", label: "Production", summary: "Info logging as JSON, TLS, Redis and OpenTelemetry on, 30 days of path metrics." },
  { id: "high-throughput", label: "High throughput", summary: "Warn logging, a 20,000-connection idle pool for 100k+ requests a second." },
];

/**
 * Three starting points for the gateway section. A preset is shown as the
 * list of fields it would change before it is applied, and applying it only
 * edits the form: nothing reaches the gateway until the page is saved.
 */
export function PresetsCard({ config, disabled, onApply }: PresetsCardProps) {
  const [preview, setPreview] = useState<{ preset: SettingsPreset; label: string; changes: PresetChange[] } | null>(null);

  const open = (preset: SettingsPreset, label: string) => setPreview({ preset, label, changes: presetChanges(config, withPreset(config, preset)) });

  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="md">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="teal.6">
            <IconRocket size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              Presets
            </Title>
            <Text c="dimmed" size="xs">
              A starting point for the settings below. Each one shows what it changes before it changes anything.
            </Text>
          </div>
        </Group>
        <Group gap="sm">
          {PRESETS.map((p) => (
            <Button key={p.id} variant="light" size="sm" radius="md" disabled={disabled} onClick={() => open(p.id, p.label)}>
              {p.label}
            </Button>
          ))}
        </Group>
      </Stack>

      <Modal opened={preview !== null} onClose={() => setPreview(null)} title={preview ? `Apply the ${preview.label} preset` : ""} size="lg">
        {preview && (
          <Stack gap="md">
            <Text size="sm" c="dimmed">
              {PRESETS.find((p) => p.id === preview.preset)?.summary}
            </Text>
            {preview.changes.length === 0 ? (
              <Text size="sm">The settings already match this preset. Nothing would change.</Text>
            ) : (
              <Table withTableBorder striped>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Setting</Table.Th>
                    <Table.Th>Now</Table.Th>
                    <Table.Th>After</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {preview.changes.map((c) => (
                    <Table.Tr key={c.path}>
                      <Table.Td>
                        <Code>{c.path}</Code>
                      </Table.Td>
                      <Table.Td>{c.from}</Table.Td>
                      <Table.Td>{c.to}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
            <Text size="xs" c="dimmed">
              Applying edits the form. The gateway keeps its settings until you save.
            </Text>
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setPreview(null)}>
                Cancel
              </Button>
              <Button
                disabled={preview.changes.length === 0}
                onClick={() => {
                  onApply(preview.preset);
                  setPreview(null);
                }}
              >
                Apply {preview.label}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Card>
  );
}
