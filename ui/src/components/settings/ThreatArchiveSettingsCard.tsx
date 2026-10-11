// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Code, Group, NumberInput, Stack, Switch, Text, ThemeIcon, Title } from "@mantine/core";
import { IconShieldLock } from "@tabler/icons-react";
import type { GlobalConfig, LogConfig } from "../../types/gateon";

interface ThreatArchiveSettingsCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

const orZero = (v: string | number) => (typeof v === "number" && v > 0 ? Math.floor(v) : 0);

// ThreatArchiveSettingsCard decides what happens to security threats past
// their retention: deleted, or moved to archive files first. Off by default,
// because it spends disk every existing install has budgeted for something
// else.
export function ThreatArchiveSettingsCard({ config, onChange, disabled }: ThreatArchiveSettingsCardProps) {
  const log = config.log || {};
  const update = (value: Partial<LogConfig>) => onChange({ ...config, log: { ...log, ...value } });

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="lg">
        <Group justify="space-between" wrap="nowrap">
          <Group wrap="nowrap">
            <ThemeIcon size="xl" radius="md" variant="light" color="red">
              <IconShieldLock size={24} />
            </ThemeIcon>
            <Stack gap={0}>
              <Title order={3}>Security threat archive</Title>
              <Text size="sm" c="dimmed">
                Move threats older than their retention period into compressed files instead of deleting them, and
                browse them under Security Hub, Archive.
              </Text>
            </Stack>
          </Group>
          <Switch
            aria-label="Archive security threats"
            checked={!!log.securityThreatArchiveEnabled}
            onChange={(e) => update({ securityThreatArchiveEnabled: e.currentTarget.checked })}
            disabled={disabled}
            size="lg"
          />
        </Group>

        <NumberInput
          label="Archive size limit (MB)"
          placeholder="Profile default"
          description="Empty uses the resource profile's: 256 MB, 1 GB or 10 GB. Past it the oldest files are removed."
          min={1}
          allowDecimal={false}
          value={log.securityThreatArchiveMaxSizeMb || ""}
          onChange={(v) => update({ securityThreatArchiveMaxSizeMb: orZero(v) })}
          disabled={disabled}
          radius="md"
        />

        <Text size="xs" c="dimmed">
          Files are written to <Code>security/archives</Code> under the gateway's data directory, or{" "}
          <Code>GATEON_THREAT_ARCHIVE_DIR</Code>. <Code>GATEON_THREAT_ARCHIVE_ENABLED</Code> and{" "}
          <Code>GATEON_THREAT_ARCHIVE_MAX_MB</Code> override these settings. Reading the archive never queries the
          database.
        </Text>
      </Stack>
    </Card>
  );
}
