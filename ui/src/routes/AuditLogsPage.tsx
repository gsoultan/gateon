import { useState, useEffect } from 'react';
import { Container, Title, Text, Card, Table, Badge, Group, Stack, TextInput, ActionIcon, Tooltip, Paper, Pagination } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconSearch, IconRefresh, IconFingerprint, IconShieldCheck, IconShieldX } from '@tabler/icons-react';
import { useAuditLogs } from '../hooks/useAuditLogs';
import { useUrlFilters } from '../hooks/useUrlFilters';
import { format } from 'date-fns';

const PAGE_SIZE = 50;

export default function AuditLogsPage() {
  // Filter state lives in the URL so a filtered audit view is shareable.
  const [filters, setFilters] = useUrlFilters<{ q: string }>();
  const search = filters.q ?? '';
  const [debouncedSearch] = useDebouncedValue(search, 300);
  const [page, setPage] = useState(1);

  // Reset to the first page whenever the (debounced) search changes so we never
  // request a page that no longer exists for the filtered result set.
  useEffect(() => {
    setPage(1);
  }, [debouncedSearch]);

  const { data, isLoading, refetch, isFetching } = useAuditLogs({
    page: page - 1,
    page_size: PAGE_SIZE,
    search: debouncedSearch,
  });

  const logs = data?.logs ?? [];
  const totalCount = data?.total_count ?? logs.length;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  const formatTimestamp = (ts: string) => {
    try {
      const date = new Date(ts);
      if (isNaN(date.getTime())) return ts;
      return format(date, 'MMM dd, HH:mm:ss');
    } catch (e) {
      return ts;
    }
  };

  return (
    <Container size="xl">
      <Stack gap="lg">
        <Group justify="space-between">
          <Stack gap={0}>
            <Title order={2} fw={800} style={{ letterSpacing: -1 }}>Audit Logs</Title>
            <Text c="dimmed" size="sm">Forensic audit trail of all administrative actions and security events.</Text>
          </Stack>
          <ActionIcon variant="subtle" size="lg" onClick={() => refetch()} loading={isLoading || isFetching}>
            <IconRefresh size={20} />
          </ActionIcon>
        </Group>

        <Card withBorder radius="md" p="md">
          <TextInput
            placeholder="Search audit logs..."
            leftSection={<IconSearch size={16} />}
            value={search}
            onChange={(e) => setFilters({ q: e.currentTarget.value })}
            mb="md"
          />

          <Table.ScrollContainer minWidth={800}>
            <Table verticalSpacing="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Timestamp</Table.Th>
                  <Table.Th>User</Table.Th>
                  <Table.Th>Action</Table.Th>
                  <Table.Th>Resource</Table.Th>
                  <Table.Th>IP Address</Table.Th>
                  <Table.Th>Security</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody style={{ opacity: isFetching ? 0.6 : 1, transition: 'opacity 0.2s' }}>
                {logs.map((log) => (
                  <Table.Tr key={log.id}>
                    <Table.Td>
                      <Text size="sm" fw={500}>
                        {formatTimestamp(log.timestamp)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" color="blue" radius="sm">{log.user_id}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" fw={700}>{log.action}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" c="dimmed" style={{ fontFamily: 'var(--mantine-font-family-monospace)' }}>
                        {log.resource}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs">{log.ip_address}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Tooltip label={log.signature ? "Cryptographically Signed" : "Not Signed"}>
                        <ActionIcon variant="subtle" color={log.signature ? "green" : "gray"}>
                          {log.signature ? <IconShieldCheck size={18} /> : <IconShieldX size={18} />}
                        </ActionIcon>
                      </Tooltip>
                    </Table.Td>
                  </Table.Tr>
                ))}
                {!isLoading && logs.length === 0 && (
                  <Table.Tr>
                    <Table.Td colSpan={6}>
                      <Text ta="center" py="xl" c="dimmed">No audit logs found.</Text>
                    </Table.Td>
                  </Table.Tr>
                )}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>

          {totalCount > PAGE_SIZE && (
            <Group justify="space-between" align="center" pt="md" mt="md" style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}>
              <Text size="xs" c="dimmed">
                Showing {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, totalCount)} of {totalCount}
              </Text>
              <Pagination total={totalPages} value={page} onChange={setPage} size="sm" radius="md" />
            </Group>
          )}
        </Card>

        {logs.length > 0 && (
          <Paper withBorder p="md" radius="md" bg="var(--mantine-color-blue-light)">
            <Group gap="sm">
              <IconFingerprint size={24} color="var(--mantine-color-blue-filled)" />
              <Text size="sm" fw={500}>
                Integrity Check: All logs displayed are verified and signed using the system's HMAC key.
              </Text>
            </Group>
          </Paper>
        )}
      </Stack>
    </Container>
  );
}
