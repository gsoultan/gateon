// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Code, Group, Stack, Switch, Text, ThemeIcon, Title } from "@mantine/core";
import { IconArchive } from "@tabler/icons-react";
import { useAdminOnlySetting } from "../../hooks/usePermissions";
import type { GlobalConfig } from "../../types/gateon";
import { AdminOnlyNote } from "./adminOnly/AdminOnlyNote";

interface ArchiveOnRetentionCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

// withArchiveOnRetention is config with the switch set, everything else kept:
// log.archiveOnRetention is the JSON name PUT /v1/global reads.
export const withArchiveOnRetention = (config: GlobalConfig, on: boolean): GlobalConfig => ({
  ...config,
  log: { ...(config.log || {}), archiveOnRetention: on },
});

// ArchiveOnRetentionCard is the one switch that archives every log retention
// removes: traces, security threats and audit entries. It only ever adds an
// archive, so with it off each card below decides for its own log. Off by
// default on every profile, because it spends disk on three archives at once.
// Administrator-only: switching it off lets retention delete audit entries it
// used to keep, and the gateway refuses that change from an operator.
export function ArchiveOnRetentionCard({ config, onChange, disabled: formDisabled }: ArchiveOnRetentionCardProps) {
  const { disabled, locked } = useAdminOnlySetting(!!formDisabled);
  const log = config.log || {};

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="lg">
        <Group justify="space-between" wrap="nowrap">
          <Group wrap="nowrap">
            <ThemeIcon size="xl" radius="md" variant="light" color="teal">
              <IconArchive size={24} />
            </ThemeIcon>
            <Stack gap={0}>
              <Title order={3}>Archive everything on retention</Title>
              <Text size="sm" c="dimmed">
                Archive traces, security threats and audit entries before retention removes them, whatever each
                archive's own switch says. Each archive keeps its own size limit.
              </Text>
            </Stack>
          </Group>
          <Switch
            aria-label="Archive everything on retention"
            checked={!!log.archiveOnRetention}
            onChange={(e) => onChange(withArchiveOnRetention(config, e.currentTarget.checked))}
            disabled={disabled}
            size="lg"
          />
        </Group>
        <AdminOnlyNote locked={locked} />
        <Text size="xs" c="dimmed">
          Off by default on every resource profile. <Code>GATEON_ARCHIVE_ON_RETENTION</Code> overrides this setting,
          and each archive's own <Code>GATEON_*_ARCHIVE_ENABLED</Code> variable overrides both.
        </Text>
      </Stack>
    </Card>
  );
}
