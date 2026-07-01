import React, { useState } from 'react';
import {
  Table,
  Group,
  Text,
  Badge,
  ActionIcon,
  Button,
  Modal,
  TextInput,
  Textarea,
  Switch,
  NumberInput,
  Select,
  Stack,
  Card,
  Code,
  Tooltip,
  Title,
} from '@mantine/core';
import { IconEdit, IconTrash, IconPlus, IconShieldCheck, IconInfoCircle } from '@tabler/icons-react';
import { useWafRules } from '../../hooks/useWafRules';
import type {WafRule} from '../../types/gateon';
import { notifications } from '@mantine/notifications';

export function WAFRulesTab() {
  const { rules, isLoading, createRule, updateRule, deleteRule } = useWafRules();
  const [opened, setOpened] = useState(false);
  const [editingRule, setEditingRule] = useState<Partial<WafRule> | null>(null);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRule) return;

    try {
      if (editingRule.id) {
        await updateRule({ rule: editingRule as WafRule });
        notifications.show({ title: 'Success', message: 'WAF Rule updated successfully', color: 'green' });
      } else {
        await createRule({ rule: editingRule });
        notifications.show({ title: 'Success', message: 'WAF Rule created successfully', color: 'green' });
      }
      setOpened(false);
      setEditingRule(null);
    } catch (err: any) {
      notifications.show({ title: 'Error', message: err.message || 'Failed to save rule', color: 'red' });
    }
  };

  const handleDelete = async (id: string) => {
    if (window.confirm('Are you sure you want to delete this rule?')) {
      try {
        await deleteRule(id);
        notifications.show({ title: 'Success', message: 'WAF Rule deleted successfully', color: 'green' });
      } catch (err: any) {
        notifications.show({ title: 'Error', message: err.message || 'Failed to delete rule', color: 'red' });
      }
    }
  };

  const rows = rules.map((rule) => (
    <Table.Tr key={rule.id}>
      <Table.Td>
        <Stack gap={0}>
          <Text size="sm" fw={500}>
            {rule.name}
          </Text>
          <Text size="xs" c="dimmed">
            ID: {rule.id}
          </Text>
        </Stack>
      </Table.Td>
      <Table.Td>
        <Badge variant="light">{rule.category}</Badge>
      </Table.Td>
      <Table.Td>
        <Tooltip label={rule.directive} multiline w={400}>
          <Code block style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '300px' }}>
            {rule.directive}
          </Code>
        </Tooltip>
      </Table.Td>
      <Table.Td>
        <Badge color={rule.paranoia_level > 2 ? 'red' : rule.paranoia_level > 1 ? 'orange' : 'blue'}>
          PL {rule.paranoia_level}
        </Badge>
      </Table.Td>
      <Table.Td>
        <Badge color={rule.enabled ? 'green' : 'gray'}>
          {rule.enabled ? 'Enabled' : 'Disabled'}
        </Badge>
      </Table.Td>
      <Table.Td>
        <Group gap={4} justify="right">
          <ActionIcon
            variant="subtle"
            color="blue"
            onClick={() => {
              setEditingRule(rule);
              setOpened(true);
            }}
          >
            <IconEdit size={16} />
          </ActionIcon>
          <ActionIcon variant="subtle" color="red" onClick={() => handleDelete(rule.id)}>
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
      </Table.Td>
    </Table.Tr>
  ));

  return (
    <Stack>
      <Group justify="space-between">
        <Stack gap={0}>
          <Title order={4}>WAF Security Rules</Title>
          <Text size="sm" c="dimmed">Manage custom and adaptive Coraza SecLang rules in the database.</Text>
        </Stack>
        <Button
          leftSection={<IconPlus size={16} />}
          onClick={() => {
            setEditingRule({
              name: '',
              directive: '',
              enabled: true,
              paranoia_level: 1,
              category: 'custom',
            });
            setOpened(true);
          }}
        >
          Add Rule
        </Button>
      </Group>

      <Card withBorder padding="0">
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Category</Table.Th>
              <Table.Th>Directive</Table.Th>
              <Table.Th>Paranoia</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {isLoading ? (
              <Table.Tr>
                <Table.Td colSpan={6}>
                  <Text ta="center" py="xl">Loading rules...</Text>
                </Table.Td>
              </Table.Tr>
            ) : rows.length > 0 ? (
              rows
            ) : (
              <Table.Tr>
                <Table.Td colSpan={6}>
                  <Stack align="center" py="xl" gap="xs">
                    <IconShieldCheck size={48} color="var(--mantine-color-dimmed)" stroke={1} />
                    <Text c="dimmed">No rules found in database.</Text>
                  </Stack>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Card>

      <Modal
        opened={opened}
        onClose={() => setOpened(false)}
        title={editingRule?.id ? 'Edit WAF Rule' : 'Add New WAF Rule'}
        size="lg"
      >
        <form onSubmit={handleSave}>
          <Stack>
            <TextInput
              label="Rule Name"
              placeholder="e.g. Block Suspicious Path"
              required
              value={editingRule?.name || ''}
              onChange={(e) => setEditingRule({ ...editingRule!, name: e.target.value })}
            />
            <Group grow>
              <Select
                label="Category"
                data={['Compliance', 'Initialization', 'Adaptive', 'Reputation', 'DoS', 'Injection', 'custom']}
                value={editingRule?.category || 'custom'}
                onChange={(val) => setEditingRule({ ...editingRule!, category: val || 'custom' })}
              />
              <NumberInput
                label="Paranoia Level"
                min={1}
                max={4}
                value={editingRule?.paranoia_level || 1}
                onChange={(val) => setEditingRule({ ...editingRule!, paranoia_level: Number(val) })}
              />
            </Group>
            <Textarea
              label="Coraza Directive (SecLang)"
              placeholder='SecRule REQUEST_URI "@contains /secret" "id:12345,phase:1,deny,status:403"'
              required
              minRows={4}
              value={editingRule?.directive || ''}
              onChange={(e) => setEditingRule({ ...editingRule!, directive: e.target.value })}
              description={
                <Group gap={4} mt={4}>
                  <IconInfoCircle size={14} />
                  <Text size="xs">Ensure the rule has a unique ID and correct SecLang syntax.</Text>
                </Group>
              }
            />
            <Switch
              label="Rule Enabled"
              checked={editingRule?.enabled ?? true}
              onChange={(e) => setEditingRule({ ...editingRule!, enabled: e.currentTarget.checked })}
            />
            <Group justify="right" mt="md">
              <Button variant="subtle" onClick={() => setOpened(false)}>Cancel</Button>
              <Button type="submit">Save Rule</Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}

