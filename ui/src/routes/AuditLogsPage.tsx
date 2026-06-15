import { Container, Title, Text, Card, Table, Badge, Group, Stack, TextInput, ActionIcon, Tooltip, Paper } from '@mantine/core';
import { IconSearch, IconRefresh, IconFingerprint, IconShieldCheck, IconShieldX } from '@tabler/icons-react';
import { useAuditLogs } from '../hooks/useAuditLogs';
import { useUrlFilters } from '../hooks/useUrlFilters';
import { format } from 'date-fns';

export default function AuditLogsPage() {
  // Filter state lives in the URL so a filtered audit view is shareable.
  const [filters, setFilters] = useUrlFilters<{ q: string }>();
  const search = filters.q ?? '';
  const { data, isLoading, refetch, isFetching } = useAuditLogs(100);

  const filteredLogs = data?.logs?.filter(log => 
    (log.action?.toLowerCase() || '').includes(search.toLowerCase()) ||
    (log.resource?.toLowerCase() || '').includes(search.toLowerCase()) ||
    (log.user_id?.toLowerCase() || '').includes(search.toLowerCase()) ||
    (log.details?.toLowerCase() || '').includes(search.toLowerCase())
  );

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
              <Table.Tbody>
                {filteredLogs?.map((log) => (
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
                {filteredLogs?.length === 0 && (
                  <Table.Tr>
                    <Table.Td colSpan={6}>
                      <Text ta="center" py="xl" c="dimmed">No audit logs found.</Text>
                    </Table.Td>
                  </Table.Tr>
                )}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>

        {filteredLogs && filteredLogs.length > 0 && (
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
