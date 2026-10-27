// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Button, Card, Group, Skeleton, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { Link } from "@tanstack/react-router";
import { linkSearch } from "../layout/createLink";
import { IconCircleCheck } from "@tabler/icons-react";
import { StatusChip } from "../status";
import { ATTENTION_CAP } from "./attention";
import { useAttention } from "./useAttention";

/**
 * What to do next, worst first, one action per row. The list is capped; the
 * pages the rows link to hold the rest. An empty list is a result, and says
 * so, rather than an empty box.
 */
export function AttentionList() {
  const { items, isLoading } = useAttention();
  return (
    <Card withBorder radius="md" padding="lg" id="attention">
      <Stack gap="md">
        <Group justify="space-between">
          <Title order={4}>Needs attention</Title>
          {items.length > 0 && (
            <Text size="sm" c="dimmed">
              {items.length >= ATTENTION_CAP ? `First ${ATTENTION_CAP}` : `${items.length} ${items.length === 1 ? "item" : "items"}`}
            </Text>
          )}
        </Group>
        {isLoading && items.length === 0 ? (
          <Stack gap="xs">
            <Skeleton height={44} radius="sm" />
            <Skeleton height={44} radius="sm" />
          </Stack>
        ) : items.length === 0 ? (
          <Group gap="sm" py="sm">
            <ThemeIcon color="green" variant="light" radius="xl" size="lg">
              <IconCircleCheck size={20} />
            </ThemeIcon>
            <div>
              <Text size="sm" fw={600}>
                Nothing needs attention
              </Text>
              <Text size="xs" c="dimmed">
                Every backend answers, no certificate is close to expiry, and the WAF is enforcing.
              </Text>
            </div>
          </Group>
        ) : (
          <Stack gap={0} role="list">
            {items.map((item) => (
              <Group
                key={item.id}
                role="listitem"
                justify="space-between"
                wrap="nowrap"
                py="sm"
                style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}
              >
                <Group gap="sm" wrap="nowrap" style={{ minWidth: 0 }}>
                  <StatusChip state={item.state} />
                  <div style={{ minWidth: 0 }}>
                    <Text size="sm" fw={600} lineClamp={1}>
                      {item.title}
                    </Text>
                    <Text size="xs" c="dimmed" lineClamp={2}>
                      {item.detail}
                    </Text>
                  </div>
                </Group>
                <Button component={Link} to={item.action.to} search={linkSearch(item.action.search)} variant="light" size="xs" style={{ flexShrink: 0 }}>
                  {item.action.label}
                </Button>
              </Group>
            ))}
          </Stack>
        )}
      </Stack>
    </Card>
  );
}
