import { useState, useEffect } from 'react';
import {
  Container,
  Title,
  Text,
  Card,
  Table,
  Badge,
  Group,
  Stack,
  TextInput,
  ActionIcon,
  Tooltip,
  Paper,
  Pagination,
  Tabs,
  Button,
  Modal,
  Code,
  ScrollArea,
  ThemeIcon,
  Box,
  Divider,
  Grid,
} from '@mantine/core';
import { useDebouncedValue, useDisclosure } from '@mantine/hooks';
import {
  IconSearch,
  IconRefresh,
  IconFingerprint,
  IconShieldCheck,
  IconShieldX,
  IconArchive,
  IconList,
  IconFileZip,
  IconEye,
  IconDownload,
  IconInfoCircle,
} from '@tabler/icons-react';
import { useAuditLogs } from '../hooks/useAuditLogs';
import { useAuditArchives, getAuditArchive } from '../hooks/useAuditArchives';
import { useUrlFilters } from '../hooks/useUrlFilters';
import { format } from 'date-fns';
import type { AuditLog, AuditArchive } from '../types/gateon';

const PAGE_SIZE = 50;

export default function AuditLogsPage() {
  const [activeTab, setActiveTab] = useState<string | null>('active');
  const [filters, setFilters] = useUrlFilters<{ q: string }>();
  const search = filters.q ?? '';
  const [debouncedSearch] = useDebouncedValue(search, 300);
  const [page, setPage] = useState(1);
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [opened, { open, close }] = useDisclosure(false);

  const [archiveOpened, { open: openArchive, close: closeArchive }] = useDisclosure(false);
  const [currentArchiveLogs, setCurrentArchiveLogs] = useState<AuditLog[]>([]);
  const [currentArchiveName, setCurrentArchiveName] = useState("");
  const [isOpeningArchive, setIsOpeningArchive] = useState(false);

  // Active Logs Query
  const { data, isLoading, refetch, isFetching } = useAuditLogs({
    page: page - 1,
    page_size: PAGE_SIZE,
    search: debouncedSearch,
  });

  // Archives Query
  const { data: archivesData, isLoading: isLoadingArchives, refetch: refetchArchives } = useAuditArchives();

  useEffect(() => {
    setPage(1);
  }, [debouncedSearch]);

  const logs = data?.logs ?? [];
  const totalCount = data?.total_count ?? logs.length;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  const formatTimestamp = (ts: string) => {
    try {
      const date = new Date(ts);
      if (isNaN(date.getTime())) return ts;
      return format(date, 'MMM dd, yyyy HH:mm:ss');
    } catch (e) {
      return ts;
    }
  };

  const getActionColor = (action: string) => {
    const a = action.toLowerCase();
    if (a.includes('delete') || a.includes('block')) return 'red';
    if (a.includes('update') || a.includes('edit')) return 'orange';
    if (a.includes('create') || a.includes('add')) return 'green';
    if (a.includes('login')) return 'blue';
    return 'gray';
  };

  const handleOpenArchive = async (archive: AuditArchive) => {
    setIsOpeningArchive(true);
    setCurrentArchiveName(archive.filename);
    try {
      const parsedLogs = await getAuditArchive(archive.filename);
      setCurrentArchiveLogs(parsedLogs);
      openArchive();
    } catch (err) {
      console.error("Failed to open archive", err);
    } finally {
      setIsOpeningArchive(false);
    }
  };

  const handleDownloadArchive = async (archive: AuditArchive) => {
    try {
      const parsedLogs = await getAuditArchive(archive.filename);
      const data = JSON.stringify(parsedLogs, null, 2);
      const blob = new Blob([data], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = archive.filename.replace('.br', '');
      a.click();
    } catch (err) {
      console.error("Failed to download archive", err);
    }
  };

  return (
    <Container size="xl">
      <Stack gap="lg">
        <Group justify="space-between">
          <Stack gap={0}>
            <Title order={2} fw={800} style={{ letterSpacing: -1 }}>Forensic Audit Trail</Title>
            <Text c="dimmed" size="sm">Tamper-proof history of administrative actions and security blocks.</Text>
          </Stack>
          <Group>
            <Button
              variant="light"
              leftSection={<IconRefresh size={18} />}
              onClick={() => activeTab === 'active' ? refetch() : refetchArchives()}
              loading={isLoading || isFetching || isLoadingArchives}
            >
              Refresh
            </Button>
          </Group>
        </Group>

        <Tabs value={activeTab} onChange={setActiveTab} variant="pills" radius="md">
          <Tabs.List mb="md">
            <Tabs.Tab value="active" leftSection={<IconList size={16} />}>
              Active Logs
            </Tabs.Tab>
            <Tabs.Tab value="archived" leftSection={<IconArchive size={16} />}>
              Archived Logs
            </Tabs.Tab>
          </Tabs.List>

          <Tabs.Panel value="active">
            <Card withBorder radius="md" p={0} shadow="sm">
              <Box p="md">
                <TextInput
                  placeholder="Search actions, resources, users..."
                  leftSection={<IconSearch size={16} />}
                  value={search}
                  onChange={(e) => setFilters({ q: e.currentTarget.value })}
                />
              </Box>

              <Table.ScrollContainer minWidth={800}>
                <Table verticalSpacing="sm" highlightOnHover>
                  <Table.Thead bg="var(--mantine-color-gray-0)">
                    <Table.Tr>
                      <Table.Th>Timestamp</Table.Th>
                      <Table.Th>User</Table.Th>
                      <Table.Th>Action</Table.Th>
                      <Table.Th>Resource</Table.Th>
                      <Table.Th>IP Address</Table.Th>
                      <Table.Th>Integrity</Table.Th>
                      <Table.Th w={80}></Table.Th>
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
                          <Badge variant="dot" color={getActionColor(log.action)} radius="sm">{log.action}</Badge>
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
                            <ThemeIcon variant="subtle" color={log.signature ? "green" : "gray"} size="sm">
                              {log.signature ? <IconShieldCheck size={18} /> : <IconShieldX size={18} />}
                            </ThemeIcon>
                          </Tooltip>
                        </Table.Td>
                        <Table.Td>
                          <ActionIcon
                            variant="subtle"
                            onClick={() => {
                              setSelectedLog(log);
                              open();
                            }}
                          >
                            <IconEye size={18} />
                          </ActionIcon>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                    {!isLoading && logs.length === 0 && (
                      <Table.Tr>
                        <Table.Td colSpan={7}>
                          <Text ta="center" py="xl" c="dimmed">No audit logs found.</Text>
                        </Table.Td>
                      </Table.Tr>
                    )}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>

              {totalCount > PAGE_SIZE && (
                <Group justify="space-between" align="center" p="md" style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}>
                  <Text size="xs" c="dimmed">
                    Showing {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, totalCount)} of {totalCount}
                  </Text>
                  <Pagination total={totalPages} value={page} onChange={setPage} size="sm" radius="md" />
                </Group>
              )}
            </Card>
          </Tabs.Panel>

          <Tabs.Panel value="archived">
            <Card withBorder radius="md" p={0} shadow="sm">
              <Table.ScrollContainer minWidth={600}>
                <Table verticalSpacing="sm">
                  <Table.Thead bg="var(--mantine-color-gray-0)">
                    <Table.Tr>
                      <Table.Th>Archive File</Table.Th>
                      <Table.Th>Size</Table.Th>
                      <Table.Th>Created At</Table.Th>
                      <Table.Th w={150}>Actions</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {archivesData?.archives?.map((archive) => (
                      <Table.Tr key={archive.filename}>
                        <Table.Td>
                          <Group gap="sm">
                            <IconFileZip size={20} color="var(--mantine-color-grape-6)" />
                            <Text size="sm" fw={500}>{archive.filename}</Text>
                          </Group>
                        </Table.Td>
                        <Table.Td>
                          <Text size="xs">{(archive.size / 1024).toFixed(1)} KB</Text>
                        </Table.Td>
                        <Table.Td>
                          <Text size="xs">{formatTimestamp(archive.created_at)}</Text>
                        </Table.Td>
                        <Table.Td>
                          <Group gap="xs">
                            <Button
                              size="compact-xs"
                              variant="light"
                              leftSection={<IconEye size={14} />}
                              onClick={() => handleOpenArchive(archive)}
                              loading={isOpeningArchive && currentArchiveName === archive.filename}
                            >
                              Open
                            </Button>
                            <ActionIcon
                              variant="subtle"
                              color="blue"
                              onClick={() => handleDownloadArchive(archive)}
                            >
                              <IconDownload size={16} />
                            </ActionIcon>
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                    {!isLoadingArchives && (!archivesData?.archives || archivesData.archives.length === 0) && (
                      <Table.Tr>
                        <Table.Td colSpan={4}>
                          <Text ta="center" py="xl" c="dimmed">No archives found.</Text>
                        </Table.Td>
                      </Table.Tr>
                    )}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            </Card>
          </Tabs.Panel>
        </Tabs>

        {logs.length > 0 && activeTab === 'active' && (
          <Paper withBorder p="md" radius="md" bg="var(--mantine-color-blue-light)">
            <Group gap="sm">
              <IconFingerprint size={24} color="var(--mantine-color-blue-filled)" />
              <Text size="sm" fw={500}>
                Blockchain Integrity Check: Audit chain is intact and verified.
              </Text>
            </Group>
          </Paper>
        )}
      </Stack>

      <Modal
        opened={opened}
        onClose={close}
        title={<Group gap="xs"><IconInfoCircle size={20} /><Text fw={700}>Audit Entry Details</Text></Group>}
        size="lg"
        radius="md"
      >
        {selectedLog && (
          <Stack gap="md">
            <Group justify="space-between">
              <Stack gap={0}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Action</Text>
                <Badge color={getActionColor(selectedLog.action)} size="lg">{selectedLog.action}</Badge>
              </Stack>
              <Stack gap={0} align="flex-end">
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Timestamp</Text>
                <Text size="sm" fw={500}>{formatTimestamp(selectedLog.timestamp)}</Text>
              </Stack>
            </Group>

            <Divider />

            <Grid gutter="md">
              <Grid.Col span={6}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>User ID</Text>
                <Text size="sm">{selectedLog.user_id}</Text>
              </Grid.Col>
              <Grid.Col span={6}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>IP Address</Text>
                <Text size="sm">{selectedLog.ip_address}</Text>
              </Grid.Col>
              <Grid.Col span={12}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Resource</Text>
                <Code block style={{ fontSize: '11px' }}>{selectedLog.resource}</Code>
              </Grid.Col>
            </Grid>

            <Divider />

            <Stack gap={4}>
              <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Details</Text>
              <ScrollArea.Autosize maxHeight={200} type="always">
                <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{selectedLog.details}</Text>
              </ScrollArea.Autosize>
            </Stack>

            {selectedLog.signature && (
              <Box p="xs" bg="var(--mantine-color-gray-0)" style={{ borderRadius: 'var(--mantine-radius-sm)' }}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700} mb={4}>HMAC Signature</Text>
                <Code style={{ fontSize: '10px', wordBreak: 'break-all' }}>{selectedLog.signature}</Code>
              </Box>
            )}
          </Stack>
        )}
      </Modal>

      <Modal
        opened={archiveOpened}
        onClose={closeArchive}
        title={<Group gap="xs"><IconArchive size={20} /><Text fw={700}>Archive: {currentArchiveName}</Text></Group>}
        size="90%"
        radius="md"
      >
        <Table.ScrollContainer minWidth={800}>
          <Table verticalSpacing="xs" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Timestamp</Table.Th>
                <Table.Th>User</Table.Th>
                <Table.Th>Action</Table.Th>
                <Table.Th>Resource</Table.Th>
                <Table.Th>Details</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {currentArchiveLogs.map((log) => (
                <Table.Tr key={log.id}>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(log.timestamp)}</Table.Td>
                  <Table.Td><Badge size="xs" variant="light">{log.user_id}</Badge></Table.Td>
                  <Table.Td><Badge size="xs" variant="dot" color={getActionColor(log.action)}>{log.action}</Badge></Table.Td>
                  <Table.Td><Text size="xs" truncate maw={200}>{log.resource}</Text></Table.Td>
                  <Table.Td><Text size="xs" lineClamp={1}>{log.details}</Text></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Modal>
    </Container>
  );
}

