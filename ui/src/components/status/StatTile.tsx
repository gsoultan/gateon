// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ReactNode } from "react";
import { Paper, Stack, Text } from "@mantine/core";

interface StatTileProps {
  label: string;
  /** Already formatted; a number nobody has yet is "–", never 0. */
  value: ReactNode;
  hint?: ReactNode;
}

/** One number with its name, the same size and weight everywhere it appears. */
export function StatTile({ label, value, hint }: StatTileProps) {
  return (
    <Paper withBorder p="md" radius="md">
      <Stack gap={2}>
        <Text size="xs" c="dimmed" fw={600} tt="uppercase" style={{ letterSpacing: "0.04em" }}>
          {label}
        </Text>
        <Text size="xl" fw={700} style={{ fontVariantNumeric: "tabular-nums", lineHeight: 1.2 }}>
          {value}
        </Text>
        {hint && (
          <Text size="xs" c="dimmed">
            {hint}
          </Text>
        )}
      </Stack>
    </Paper>
  );
}
