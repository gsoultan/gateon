// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ReactNode } from "react";
import { Group, SimpleGrid, Stack, Text } from "@mantine/core";

interface FormSectionProps {
  title: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  children: ReactNode;
}

/**
 * One titled group of related fields. A long form reads as a few named steps
 * rather than one column of twenty inputs, and every form spaces its groups
 * the same way.
 */
export function FormSection({ title, description, icon, children }: FormSectionProps) {
  return (
    <Stack gap="md" component="section">
      <Stack gap={2}>
        <Group gap={8} wrap="nowrap">
          {icon}
          <Text fw={600} size="md">
            {title}
          </Text>
        </Group>
        {description && (
          <Text size="sm" c="dimmed">
            {description}
          </Text>
        )}
      </Stack>
      {children}
    </Stack>
  );
}

/** Two fields side by side on a wide screen, stacked on a narrow one. */
export function FieldGrid({ children, cols = 2 }: { children: ReactNode; cols?: 2 | 3 }) {
  return (
    <SimpleGrid cols={{ base: 1, sm: cols }} spacing="md" verticalSpacing="md">
      {children}
    </SimpleGrid>
  );
}
