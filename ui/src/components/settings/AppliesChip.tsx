// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ReactNode } from "react";
import { Badge, Box, Group, Tooltip } from "@mantine/core";

/** When a saved setting takes effect. */
export type Applies = "now" | "connections" | "restart" | "dashboard";

const APPLIES: Record<Applies, { label: string; color: string; reason: string }> = {
  now: { label: "Applies now", color: "green", reason: "In force as soon as it is saved." },
  connections: { label: "New connections", color: "blue", reason: "Saved now; connections already open keep their settings." },
  restart: { label: "After restart", color: "orange", reason: "Saved now; the gateway reads it when it next starts." },
  dashboard: { label: "This browser", color: "gray", reason: "A preference of this dashboard, not of the gateway." },
};

export function AppliesChip({ applies }: { applies: Applies }) {
  const a = APPLIES[applies];
  return (
    <Tooltip label={a.reason}>
      <Badge variant="light" color={a.color} size="sm" radius="sm" tt="none" fw={500}>
        {a.label}
      </Badge>
    </Tooltip>
  );
}

interface SettingsEntryProps {
  /** The anchor a link or a search result scrolls to. */
  id: string;
  applies: Applies;
  children: ReactNode;
}

/**
 * One card of Settings with, above it, the one fact every card used to state
 * in its own words or not at all: when a change here takes effect.
 */
export function SettingsEntry({ id, applies, children }: SettingsEntryProps) {
  return (
    <Box id={id} style={{ scrollMarginTop: 80 }}>
      <Group justify="flex-end" mb={6}>
        <AppliesChip applies={applies} />
      </Group>
      {children}
    </Box>
  );
}
