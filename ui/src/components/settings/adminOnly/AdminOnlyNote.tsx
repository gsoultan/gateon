// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Group, Text } from "@mantine/core";
import { IconLock } from "@tabler/icons-react";
import { ADMIN_ONLY_REASON } from "../../../hooks/usePermissions";

interface AdminOnlyNoteProps {
  /** Shown only to a caller who can edit other settings but not these. */
  locked: boolean;
}

/**
 * Says why a setting an operator can see is read-only for them. The gateway
 * refuses an operator's change to it (ADR 0040), so the dashboard does not
 * offer one that would fail on save.
 */
export function AdminOnlyNote({ locked }: AdminOnlyNoteProps) {
  if (!locked) return null;
  return (
    <Group gap={6} wrap="nowrap" data-testid="admin-only-note">
      <IconLock size={14} aria-hidden />
      <Text size="xs" c="dimmed">
        {ADMIN_ONLY_REASON}
      </Text>
    </Group>
  );
}
