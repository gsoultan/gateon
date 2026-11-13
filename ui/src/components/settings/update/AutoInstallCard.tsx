// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Group, Select, Stack, Switch, Text, TextInput, ThemeIcon, Title } from "@mantine/core";
import { IconClockPlay } from "@tabler/icons-react";
import type { GlobalConfig, UpdateConfig } from "../../../types/gateon";
import { useAdminOnlySetting } from "../../../hooks/usePermissions";
import { useUpdateStatus } from "../../../hooks/useUpdateStatus";
import { UpdateScope, UpgradeBlocker } from "../../../services/gen/gateon/v1/status_pb";
import { AdminOnlyNote } from "../adminOnly/AdminOnlyNote";
import { SCOPE_OPTIONS, windowError } from "./upgradeView";

interface AutoInstallCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

/** What the switch's description says, for each reason it may not be the operator's to flip. */
function switchNote(byEnv: boolean, on: boolean, cannotInstall: boolean): string {
  if (byEnv) {
    return `GATEON_UPDATE_AUTO_INSTALL turns this ${on ? "on" : "off"} on this host. Remove it and restart the gateway to use this switch.`;
  }
  if (cannotInstall) return "This gateway cannot install a release itself (see Install above), so this setting has no effect here.";
  return "Off by default. When on, a verified newer release is installed inside the window below, and rolled back if it does not become ready. A release that was rolled back is not tried again automatically.";
}

/**
 * Whether the gateway installs releases without being asked, how far it may
 * go, and when (ADR 0087). Administrator-only: it decides when the gateway
 * restarts itself.
 */
export function AutoInstallCard({ config, onChange, disabled: formDisabled }: AutoInstallCardProps) {
  const { disabled, locked } = useAdminOnlySetting(!!formDisabled);
  const { data: status } = useUpdateStatus();
  const update: UpdateConfig = config.update || {};
  const upgrade = status?.upgrade;
  const byEnv = !!upgrade?.autoInstallByEnv;
  const on = byEnv ? !!upgrade?.autoInstall : !!update.autoInstall;
  const cannotInstall = !!upgrade && upgrade.blocker !== UpgradeBlocker.UNSPECIFIED;
  const set = (value: Partial<UpdateConfig>) => onChange({ ...config, update: { ...update, ...value } });
  const start = update.autoInstallWindowStart || "";
  const end = update.autoInstallWindowEnd || "";
  const badWindow = windowError(start, end);
  const inForce = upgrade ? `${upgrade.windowStart} to ${upgrade.windowEnd}` : "02:00 to 04:00";

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="lg">
        <Group wrap="nowrap" align="flex-start">
          <ThemeIcon size="xl" radius="md" variant="light" color="orange">
            <IconClockPlay size={24} />
          </ThemeIcon>
          <Stack gap={2}>
            <Title order={3}>Automatic install</Title>
            <Text size="sm" c="dimmed">
              Let the gateway upgrade itself during a maintenance window. An upgrade restarts the gateway.
            </Text>
          </Stack>
        </Group>
        <AdminOnlyNote locked={locked} />

        <Group justify="space-between" wrap="nowrap" align="flex-start">
          <Stack gap={2}>
            <Text fw={500}>Install new versions automatically</Text>
            <Text size="xs" c="dimmed">
              {switchNote(byEnv, on, cannotInstall)}
            </Text>
          </Stack>
          <Switch
            checked={on}
            onChange={(e) => set({ autoInstall: e.currentTarget.checked })}
            aria-label="Install new versions automatically"
            disabled={disabled || byEnv}
            size="lg"
          />
        </Group>

        <Select
          label="Which releases"
          description="A patch release fixes bugs and changes nothing you configured. Wider scopes can need action first: read the release notes."
          data={SCOPE_OPTIONS}
          value={String(update.autoInstallScope || UpdateScope.PATCH)}
          onChange={(value) => set({ autoInstallScope: Number(value ?? UpdateScope.PATCH) })}
          allowDeselect={false}
          disabled={disabled}
        />

        <Group grow align="flex-start">
          <TextInput
            label="Window starts"
            placeholder="02:00"
            description="Local time on the gateway's host, HH:MM."
            value={start}
            onChange={(e) => set({ autoInstallWindowStart: e.currentTarget.value.trim() })}
            error={badWindow}
            disabled={disabled}
          />
          <TextInput
            label="Window ends"
            placeholder="04:00"
            description="An end before the start runs through midnight."
            value={end}
            onChange={(e) => set({ autoInstallWindowEnd: e.currentTarget.value.trim() })}
            error={!!badWindow}
            disabled={disabled}
          />
        </Group>
        <Text size="xs" c="dimmed">
          Window in force now: {inForce}. Leave both fields empty to use the host's default.
        </Text>
      </Stack>
    </Card>
  );
}
