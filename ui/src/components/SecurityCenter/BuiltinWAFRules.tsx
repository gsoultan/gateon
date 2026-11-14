// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from 'react';
import { Alert, Badge, Button, Card, Group, Pagination, Select, Stack, Table, Text, TextInput } from '@mantine/core';
import { IconAlertCircle, IconSearch, IconShieldCheck } from '@tabler/icons-react';
import { useBuiltinWafRules } from '../../hooks/useBuiltinWafRules';
import type { BuiltinWafRule } from '../../types/gateon';

const PAGE_SIZE = 10;
const COLUMNS = 6;

/** Where a rule's detection is written. gwaf rules carry gwaf's own ID. */
export function detectionSource(rule: BuiltinWafRule): string {
  return rule.source === 'gwaf' && rule.sourceRuleId ? `gwaf ${rule.sourceRuleId}` : 'gateon';
}

/** What a match does, in the words the rest of the dashboard uses. */
export function onMatch(rule: BuiltinWafRule): { label: string; color: string } {
  return rule.action === 'log' ? { label: 'Records only', color: 'gray' } : { label: 'Blocks', color: 'red' };
}

function RuleRow({ rule }: { rule: BuiltinWafRule }) {
  const match = onMatch(rule);
  return (
    <Table.Tr>
      <Table.Td>
        <Stack gap={0}>
          <Text size="sm" fw={500}>{rule.name}</Text>
          <Text size="xs" c="dimmed">
            ID: {rule.id}{rule.tags?.length ? ` · ${rule.tags.join(', ')}` : ''}
          </Text>
        </Stack>
      </Table.Td>
      <Table.Td><Badge variant="light">{rule.category}</Badge></Table.Td>
      <Table.Td><Text size="sm">{detectionSource(rule)}</Text></Table.Td>
      <Table.Td>
        <Badge color={rule.paranoiaLevel > 2 ? 'red' : rule.paranoiaLevel > 1 ? 'orange' : 'blue'}>
          PL {rule.paranoiaLevel}
        </Badge>
      </Table.Td>
      <Table.Td><Text size="sm" tt="capitalize">{rule.confidence}</Text></Table.Td>
      <Table.Td><Badge color={match.color} variant="light">{match.label}</Badge></Table.Td>
    </Table.Tr>
  );
}

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <Table.Tr>
      <Table.Td colSpan={COLUMNS}>{children}</Table.Td>
    </Table.Tr>
  );
}

/**
 * The rules compiled into the gateway, read-only.
 *
 * The Rules page used to list only the rules an operator had written, so a
 * fresh install said "No rules found" while a hundred were refusing requests.
 * There is deliberately no edit or delete here: these are not rows, and a
 * control that looked like it changed one would be a control that did nothing.
 */
export function BuiltinWAFRules() {
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('all');
  const { data, isPending, isError, refetch } = useBuiltinWafRules({ page, pageSize: PAGE_SIZE, search, category });

  const rules = data?.rules ?? [];
  const totalPages = Math.ceil((data?.total ?? 0) / PAGE_SIZE);
  const filtered = search !== '' || category !== 'all';

  let body: React.ReactNode;
  if (isError) {
    body = (
      <Notice>
        <Alert icon={<IconAlertCircle size={16} />} color="red" title="The built-in rules could not be loaded" m="md">
          <Stack gap="xs" align="flex-start">
            <Text size="sm">They are still running. Only this list is unavailable.</Text>
            <Button size="xs" variant="light" color="red" onClick={() => refetch()}>Try again</Button>
          </Stack>
        </Alert>
      </Notice>
    );
  } else if (isPending) {
    body = <Notice><Text ta="center" py="xl">Loading built-in rules...</Text></Notice>;
  } else if (rules.length === 0) {
    body = (
      <Notice>
        <Stack align="center" py="xl" gap="xs">
          <IconShieldCheck size={48} color="var(--mantine-color-dimmed)" stroke={1} />
          <Text c="dimmed">
            {filtered ? 'No built-in rule matches this search and category.' : 'This gateway reports no built-in rules.'}
          </Text>
        </Stack>
      </Notice>
    );
  } else {
    body = rules.map((rule) => <RuleRow key={rule.id} rule={rule} />);
  }

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <Text size="sm" c="dimmed" maw={640}>
          These ship with the gateway and cannot be edited or deleted. A rule runs on a route when the
          route&apos;s WAF paranoia level is at or above the rule&apos;s and its category is switched on there.
          Detection marked gwaf comes from the gwaf library; the number is gwaf&apos;s own rule ID.
        </Text>
        <Group>
          <TextInput
            aria-label="Search built-in rules"
            placeholder="Search name, ID or tag..."
            leftSection={<IconSearch size={16} />}
            value={search}
            onChange={(e) => { setSearch(e.currentTarget.value); setPage(0); }}
            w={250}
          />
          <Select
            aria-label="Filter built-in rules by category"
            data={[{ value: 'all', label: 'All categories' }, ...(data?.categories ?? []).map((c) => ({ value: c, label: c }))]}
            value={category}
            onChange={(value) => { setCategory(value || 'all'); setPage(0); }}
            allowDeselect={false}
            w={180}
          />
        </Group>
      </Group>

      <Card withBorder padding="0">
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Rule</Table.Th>
              <Table.Th>Category</Table.Th>
              <Table.Th>Detection</Table.Th>
              <Table.Th>Paranoia</Table.Th>
              <Table.Th>Confidence</Table.Th>
              <Table.Th>On match</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>{body}</Table.Tbody>
        </Table>
      </Card>

      {totalPages > 1 && (
        <Group justify="center">
          <Pagination total={totalPages} value={page + 1} onChange={(next) => setPage(next - 1)} />
        </Group>
      )}
    </Stack>
  );
}
