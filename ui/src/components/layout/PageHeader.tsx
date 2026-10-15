// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ReactNode } from "react";
import { Group, Stack, Text, Title } from "@mantine/core";

interface PageHeaderProps {
  title: ReactNode;
  description?: ReactNode;
  /** Buttons for the page's main actions, right-aligned; they wrap under the title on a narrow screen. */
  actions?: ReactNode;
}

/**
 * The top of every page: its name, one line on what it is for, and its main
 * actions. Pages used to set their own title weight, letter spacing and
 * button size, so no two headers lined up.
 */
export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <Group justify="space-between" align="flex-end" gap="md" wrap="wrap">
      <Stack gap={4} style={{ minWidth: 0, flex: "1 1 320px" }}>
        <Title order={2} style={{ letterSpacing: "-0.02em" }}>
          {title}
        </Title>
        {description && (
          <Text c="dimmed" size="sm" maw={720}>
            {description}
          </Text>
        )}
      </Stack>
      {actions && (
        <Group gap="sm" wrap="wrap">
          {actions}
        </Group>
      )}
    </Group>
  );
}
