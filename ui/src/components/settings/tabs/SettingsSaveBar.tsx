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
 * The bar at the foot of Settings. It used to say "You have modified the
 * global configuration" the moment the page opened, edited or not, floating
 * over the last fields of every tab. Now it floats, with Discard, only while
 * there are edits; otherwise it is a quiet row at the end of the page.
 *
 * The save button is always present once the page can save, so an operator
 * can re-apply the stored configuration unchanged, and it is the signal the
 * end-to-end tests wait on for "the settings have loaded".
 */
export function SettingsSaveBar({ hasChanges, saving, canSave, error, savedOk, onSave, onDiscard }: SettingsSaveBarProps) {
  return (
    <Paper
      withBorder
      p="md"
      radius="lg"
      shadow={hasChanges ? "lg" : undefined}
      role="region"
      aria-label={hasChanges ? "Unsaved changes" : "Save configuration"}
      style={hasChanges ? { position: "sticky", bottom: 20, zIndex: 10 } : undefined}
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
            <Text fw={500} c={error ? undefined : savedOk ? "teal" : "dimmed"}>
              {error ? "Not saved" : savedOk ? "Configuration successfully updated!" : "No unsaved changes"}
            </Text>
          )}
          {error && (
            <Text c="red" size="sm" mt={4}>
              {error}
            </Text>
          )}
        </div>
        <Group gap="sm">
          {hasChanges && (
            <Button variant="default" onClick={onDiscard} disabled={saving}>
              Discard
            </Button>
          )}
          <Button
            variant={hasChanges ? "filled" : "default"}
            onClick={onSave}
            loading={saving}
            disabled={!canSave}
            leftSection={<IconCheck size={16} />}
          >
            Save Global Configuration
          </Button>
        </Group>
      </Group>
    </Paper>
  );
}
