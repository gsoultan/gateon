// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState, type ReactNode } from "react";
import { Collapse, Group, SimpleGrid, Stack, Text, UnstyledButton } from "@mantine/core";
import { IconChevronDown, IconChevronRight } from "@tabler/icons-react";

interface FormSectionProps {
  title: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  children: ReactNode;
  /**
   * Folded by default, with a one-line summary beside the title. For the
   * parts of a form most saves never touch, so the common case is short.
   */
  collapsible?: boolean;
  defaultOpen?: boolean;
  /** What the folded section holds, read without opening it. */
  summary?: ReactNode;
}

/**
 * One titled group of related fields. A long form reads as a few named steps
 * rather than one column of twenty inputs, and every form spaces its groups
 * the same way.
 */
export function FormSection({ title, description, icon, children, collapsible = false, defaultOpen = true, summary }: FormSectionProps) {
  const [open, setOpen] = useState(!collapsible || defaultOpen);
  const heading = (
    <Group gap={8} wrap="nowrap">
      {collapsible && (open ? <IconChevronDown size={16} /> : <IconChevronRight size={16} />)}
      {icon}
      <Text fw={600} size="md">
        {title}
      </Text>
      {collapsible && !open && summary && (
        <Text size="sm" c="dimmed" truncate>
          {summary}
        </Text>
      )}
    </Group>
  );
  return (
    <Stack gap="md" component="section">
      <Stack gap={2}>
        {collapsible ? (
          <UnstyledButton onClick={() => setOpen((o) => !o)} aria-expanded={open} style={{ display: "block" }}>
            {heading}
          </UnstyledButton>
        ) : (
          heading
        )}
        {description && (open || !collapsible) && (
          <Text size="sm" c="dimmed">
            {description}
          </Text>
        )}
      </Stack>
      {collapsible ? <Collapse expanded={open}>{children}</Collapse> : children}
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
