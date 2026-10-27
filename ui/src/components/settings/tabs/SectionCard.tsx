// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { ReactNode } from "react";
import { Card, Stack, Text, Title } from "@mantine/core";

interface SectionCardProps {
  title: string;
  description: string;
  children: ReactNode;
}

/**
 * A card around a form section that used to be one part of the Gateway card.
 * Redis, OpenTelemetry and logging each moved to the section of Settings
 * they belong to, and each needs the title the shared card used to give it.
 */
export function SectionCard({ title, description, children }: SectionCardProps) {
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="lg">
        <div>
          <Title order={4} fw={700}>
            {title}
          </Title>
          <Text c="dimmed" size="xs">
            {description}
          </Text>
        </div>
        {children}
      </Stack>
    </Card>
  );
}
