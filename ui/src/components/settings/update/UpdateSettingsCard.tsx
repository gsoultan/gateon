// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Group, Stack, Switch, Text, TextInput, ThemeIcon, Title } from "@mantine/core";
import { IconCalendarRepeat } from "@tabler/icons-react";
import type { GlobalConfig, UpdateConfig } from "../../../types/gateon";
import { useAdminOnlySetting } from "../../../hooks/usePermissions";
import { useUpdateStatus } from "../../../hooks/useUpdateStatus";
import { AdminOnlyNote } from "../adminOnly/AdminOnlyNote";

/** Where the gateway asks when the field is empty; mirrors internal/selfupdate. */
export const DEFAULT_RELEASE_SOURCE = "https://github.com/gsoultan/gateon/releases";

interface UpdateSettingsCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

/**
 * Whether the gateway asks for newer releases, and which server it asks
 * (ADR 0085). Administrator-only: it names a host the gateway connects to on
 * its own, and what that host serves is the version this dashboard offers.
 */
export function UpdateSettingsCard({ config, onChange, disabled: formDisabled }: UpdateSettingsCardProps) {
  const { disabled, locked } = useAdminOnlySetting(!!formDisabled);
  const { data: status } = useUpdateStatus();
  const update: UpdateConfig = config.update || {};
  const pinnedOff = !!status?.disabledByEnv;
  const set = (value: Partial<UpdateConfig>) => onChange({ ...config, update: { ...update, ...value } });

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="lg">
        <Group wrap="nowrap" align="flex-start">
          <ThemeIcon size="xl" radius="md" variant="light" color="teal">
            <IconCalendarRepeat size={24} />
          </ThemeIcon>
          <Stack gap={2}>
            <Title order={3}>Update check</Title>
            <Text size="sm" c="dimmed">
              Checking only tells you a newer version is out. Nothing is downloaded or installed.
            </Text>
          </Stack>
        </Group>
        <AdminOnlyNote locked={locked} />

        <Group justify="space-between" wrap="nowrap" align="flex-start">
          <Stack gap={2}>
            <Text fw={500}>Check for new versions every day</Text>
            <Text size="xs" c="dimmed">
              {pinnedOff
                ? "GATEON_UPDATE_CHECK turns the check off on this host. Remove it and restart the gateway to use this switch."
                : "The gateway reads two small files from the release source. It sends its version and nothing else."}
            </Text>
          </Stack>
          <Switch
            checked={!update.checkDisabled && !pinnedOff}
            onChange={(e) => set({ checkDisabled: !e.currentTarget.checked })}
            aria-label="Check for new versions every day"
            disabled={disabled || pinnedOff}
            size="lg"
          />
        </Group>

        <TextInput
          label="Release source"
          placeholder={DEFAULT_RELEASE_SOURCE}
          description="Leave empty for GitHub. Point it at an https:// mirror for hosts that cannot reach GitHub; a release from any source must carry the same signature."
          value={update.sourceUrl || ""}
          onChange={(e) => set({ sourceUrl: e.currentTarget.value })}
          disabled={disabled}
        />
      </Stack>
    </Card>
  );
}
