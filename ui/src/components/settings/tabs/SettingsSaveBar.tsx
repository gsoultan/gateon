// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Button, Group, Paper, Text } from "@mantine/core";
import { IconCheck } from "@tabler/icons-react";

interface SettingsSaveBarProps {
  hasChanges: boolean;
  saving: boolean;
  /** False until the gateway's settings have loaded. */
  canSave: boolean;
  error: string | null;
  savedOk: boolean;
  onSave: () => void;
  onDiscard: () => void;
}

/**
 * The bar at the foot of Settings. It is there only when there is something
 * to save, or a save to report: it used to say "You have modified the global
 * configuration" the moment the page opened, edited or not, and sat over the
 * last fields of every tab.
 */
export function SettingsSaveBar({ hasChanges, saving, canSave, error, savedOk, onSave, onDiscard }: SettingsSaveBarProps) {
  if (!hasChanges && !error && !savedOk) return null;
  return (
    <Paper
      withBorder
      p="md"
      radius="lg"
      shadow="lg"
      role="region"
      aria-label="Unsaved changes"
      style={{ position: "sticky", bottom: 20, zIndex: 10 }}
    >
      <Group justify="space-between" gap="md" wrap="wrap">
        <div>
          {hasChanges ? (
            <>
              <Text fw={600}>Unsaved changes</Text>
              <Text size="sm" c="dimmed">
                The gateway keeps its current settings until you save.
              </Text>
            </>
          ) : (
            <Text fw={600} c={error ? undefined : "teal"}>
              {error ? "Not saved" : "All changes saved"}
            </Text>
          )}
          {error && (
            <Text c="red" size="sm" mt={4}>
              {error}
            </Text>
          )}
        </div>
        {hasChanges && (
          <Group gap="sm">
            <Button variant="default" onClick={onDiscard} disabled={saving}>
              Discard
            </Button>
            <Button onClick={onSave} loading={saving} disabled={!canSave} leftSection={<IconCheck size={16} />}>
              Save changes
            </Button>
          </Group>
        )}
      </Group>
    </Paper>
  );
}
