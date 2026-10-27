// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMemo, useState } from "react";
import { Badge, Box, Group, Paper, ScrollArea, SimpleGrid, Stack, Tabs, Text, TextInput, UnstyledButton } from "@mantine/core";
import { IconSearch } from "@tabler/icons-react";
import { MIDDLEWARE_TYPES, POLICY_FAMILIES, POLICY_FAMILY_DESCRIPTIONS, type PolicyFamily } from "./middlewareTypes";

interface PolicyCatalogProps {
  value?: string;
  onPick: (type: string) => void;
}

/**
 * The 47 policy types on six shelves, with a search box. It replaces a
 * grouped Select whose list ran off the screen: a shelf can be read, and a
 * type is picked by what it does rather than by knowing its name.
 */
export function PolicyCatalog({ value, onPick }: PolicyCatalogProps) {
  const [query, setQuery] = useState("");
  const [family, setFamily] = useState<PolicyFamily>(MIDDLEWARE_TYPES.find((t) => t.value === value)?.group ?? "Limits");
  const q = query.trim().toLowerCase();
  const matches = useMemo(
    () => (q ? MIDDLEWARE_TYPES.filter((t) => `${t.label} ${t.value} ${t.description} ${t.group}`.toLowerCase().includes(q)) : null),
    [q],
  );
  const shown = matches ?? MIDDLEWARE_TYPES.filter((t) => t.group === family);

  return (
    <Stack gap="sm">
      <TextInput
        placeholder="Search policies"
        aria-label="Search policy types"
        leftSection={<IconSearch size={16} />}
        value={query}
        onChange={(e) => setQuery(e.currentTarget.value)}
      />
      {!matches && (
        <Tabs value={family} onChange={(v) => v && setFamily(v as PolicyFamily)} variant="pills" radius="md">
          <Tabs.List className="scrollable-tabs-list">
            {POLICY_FAMILIES.map((f) => (
              <Tabs.Tab key={f} value={f}>
                {f}
              </Tabs.Tab>
            ))}
          </Tabs.List>
        </Tabs>
      )}
      <Text size="xs" c="dimmed">
        {matches ? `${matches.length} ${matches.length === 1 ? "policy matches" : "policies match"}` : POLICY_FAMILY_DESCRIPTIONS[family]}
      </Text>
      <ScrollArea.Autosize mah={360} type="auto">
        {shown.length === 0 ? (
          <Text size="sm" c="dimmed" py="md">
            No policy matches “{query}”.
          </Text>
        ) : (
          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xs">
            {shown.map((t) => {
              const selected = t.value === value;
              return (
                <UnstyledButton key={t.value} onClick={() => onPick(t.value)} aria-pressed={selected} style={{ display: "block" }}>
                  <Paper
                    withBorder
                    p="sm"
                    radius="md"
                    style={{
                      borderColor: selected ? "var(--mantine-primary-color-filled)" : undefined,
                      background: selected ? "var(--mantine-primary-color-light)" : undefined,
                    }}
                  >
                    <Group justify="space-between" wrap="nowrap" gap="xs">
                      <Text size="sm" fw={600}>
                        {t.label}
                      </Text>
                      {matches && (
                        <Badge size="xs" variant="light" color="gray">
                          {t.group}
                        </Badge>
                      )}
                    </Group>
                    <Box mt={2}>
                      <Text size="xs" c="dimmed">
                        {t.description}
                      </Text>
                    </Box>
                  </Paper>
                </UnstyledButton>
              );
            })}
          </SimpleGrid>
        )}
      </ScrollArea.Autosize>
    </Stack>
  );
}
