// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  Alert,
  Badge,
  Button,
  Card,
  Center,
  Code,
  Group,
  Menu,
  Progress,
  ScrollArea,
  SimpleGrid,
  Skeleton,
  Stack,
  Table,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconAlertTriangle, IconArchive, IconDownload, IconSearch } from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import { Fragment, useMemo } from "react";

import {
  traceArchiveDownloadUrl,
  useTraceArchives,
  type TraceArchiveSegment,
  type TraceArchiveStatus,
} from "../../hooks/useTraceArchives";
import { formatBytes } from "../../utils/format";
import { QueryError } from "../QueryError";

const when = (iso: string) => (iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—");
const clock = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const day = (iso: string) => new Date(iso).toLocaleDateString([], { weekday: "short", year: "numeric", month: "short", day: "numeric" });

// The directory an hour's file lives in under the archive root, which is named
// in UTC like the file: 2026/09/26.
const utcDir = (iso: string) => iso.slice(0, 10).replace(/-/g, "/");

interface TraceArchivePanelProps {
  /** Opens the History tab on one archived hour. */
  onViewHour: (periodStart: string) => void;
}

// TraceArchivePanel shows the trace archive: whether it is on, how much of its
// budget it uses, and each archived hour, to open in the History tab or to
// download as the file it is.
export default function TraceArchivePanel({ onViewHour }: TraceArchivePanelProps) {
  const archives = useTraceArchives();
  const pages = archives.data?.pages;
  const status = pages?.[0]?.status ?? null;
  const segments = useMemo(() => (pages ?? []).flatMap((p) => p.segments), [pages]);

  if (archives.isError) {
    return <QueryError error={archives.error} what="the trace archive" onRetry={() => archives.refetch()} />;
  }
  if (archives.isLoading) {
    return (
      <Stack gap="md">
        <Skeleton height={140} radius="md" />
        <Skeleton height={240} radius="md" />
      </Stack>
    );
  }
  return (
    <Stack gap="md">
      <ArchiveStatusCard status={status} newest={segments[0]} />
      <Card withBorder padding="md">
        <Stack gap="sm">
          <Group justify="space-between">
            <Title order={4}>Archived hours</Title>
            <Text size="xs" c="dimmed">Newest first · times in your local time zone</Text>
          </Group>
          {segments.length === 0 ? (
            <Center py="xl">
              <Stack align="center" gap={4}>
                <IconArchive size={36} stroke={1.5} color="var(--mantine-color-dimmed)" />
                <Text fw={500} c="dimmed">No hours archived yet</Text>
                <Text size="xs" c="dimmed" ta="center" maw={420}>
                  {status?.enabled
                    ? "An hour is archived a few minutes after it ends."
                    : "Turn the archive on in Settings to start keeping traces past the live store's retention."}
                </Text>
              </Stack>
            </Center>
          ) : (
            <SegmentTable segments={segments} onViewHour={onViewHour} />
          )}
          {archives.hasNextPage && (
            <Group justify="center">
              <Button variant="light" size="xs" onClick={() => archives.fetchNextPage()} loading={archives.isFetchingNextPage}>
                Load older hours
              </Button>
            </Group>
          )}
        </Stack>
      </Card>
    </Stack>
  );
}

function ArchiveStatusCard({ status, newest }: { status: TraceArchiveStatus | null; newest?: TraceArchiveSegment }) {
  if (!status) return null;
  const used = status.maxSizeBytes > 0 ? Math.min(100, (status.totalSizeBytes / status.maxSizeBytes) * 100) : 0;
  return (
    <Card withBorder padding="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Group gap="xs">
            <IconArchive size={20} />
            <Title order={4}>Trace archive</Title>
          </Group>
          <Badge color={status.enabled ? "teal" : "gray"} variant="light">
            {status.enabled ? "Archiving" : "Off"}
          </Badge>
        </Group>

        {!status.enabled && (
          <Alert color="blue" variant="light" radius="md">
            <Group justify="space-between" wrap="wrap" gap="xs">
              <Text size="sm">
                Archiving is off. When it is on, every hour of traces is kept in a compressed file after the live store
                lets it go.
              </Text>
              <Button component={Link} to="/settings" size="xs" variant="light">
                Open Settings
              </Button>
            </Group>
          </Alert>
        )}
        {status.enabled && !status.traceStoreActive && (
          <Alert color="yellow" variant="light" radius="md">
            The live trace store is off for this resource profile, so no new traces are recorded to archive.
          </Alert>
        )}
        {status.lastError && (
          <Alert color="red" variant="light" radius="md" icon={<IconAlertTriangle size={16} />} title="Archiving is failing">
            {status.lastError} Since {when(status.lastErrorAt)}.
          </Alert>
        )}

        <SimpleGrid cols={{ base: 2, md: 4 }}>
          <Stat label="Hours archived" value={status.segmentCount.toLocaleString()} />
          <Stat label="Kept for" value={`${status.retentionDays} days`} />
          <Stat
            label="Covers"
            value={status.oldestPeriod ? `${when(status.oldestPeriod)} – ${when(status.newestPeriod)}` : "—"}
          />
          <Stat label="Last archived" value={when(status.lastArchivedAt)} />
        </SimpleGrid>

        <Stack gap={4}>
          <Group justify="space-between">
            <Text size="xs" c="dimmed">Disk used</Text>
            <Text size="xs">
              {formatBytes(status.totalSizeBytes)} of {formatBytes(status.maxSizeBytes)}
            </Text>
          </Group>
          <Progress value={used} color={used > 90 ? "orange" : "blue"} aria-label="Archive disk used" />
          <Text size="xs" c="dimmed">When either limit is reached, the oldest hours go first.</Text>
        </Stack>

        <NamingNote example={newest} />
      </Stack>
    </Card>
  );
}

// NamingNote explains the file names with a real one where there is one.
function NamingNote({ example }: { example?: TraceArchiveSegment }) {
  const start = example?.periodStart ?? "2026-09-26T14:00:00Z";
  const name = example?.name ?? "traces-2026-09-26T14Z.ndjson.zst";
  const hour = Number(start.slice(11, 13));
  const span = `${String(hour).padStart(2, "0")}:00–${String((hour + 1) % 24).padStart(2, "0")}:00 UTC`;
  return (
    <Text size="xs" c="dimmed">
      One file per hour, named for the UTC hour it holds, in a directory per UTC day:{" "}
      <Code>{`${utcDir(start)}/${name}`}</Code> holds the traces whose requests started {span} on{" "}
      {start.slice(0, 10)}. Read one with <Code>zstd -dc FILE | jq .</Code>
    </Text>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <Stack gap={2}>
      <Text size="xs" c="dimmed">{label}</Text>
      <Text size="sm" fw={600}>{value}</Text>
    </Stack>
  );
}

function SegmentTable({ segments, onViewHour }: { segments: TraceArchiveSegment[]; onViewHour: (s: string) => void }) {
  return (
    <ScrollArea>
      <Table highlightOnHover verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Hour</Table.Th>
            <Table.Th>File</Table.Th>
            <Table.Th ta="right">Traces</Table.Th>
            <Table.Th ta="right">Size</Table.Th>
            <Table.Th>Archived</Table.Th>
            <Table.Th ta="right">Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {segments.map((s, i) => (
            <Fragment key={s.name}>
              {(i === 0 || day(segments[i - 1].periodStart) !== day(s.periodStart)) && (
                <Table.Tr>
                  <Table.Td colSpan={6} bg="var(--mantine-color-default-hover)">
                    <Text size="xs" fw={700}>{day(s.periodStart)}</Text>
                  </Table.Td>
                </Table.Tr>
              )}
              <SegmentRow segment={s} onViewHour={onViewHour} />
            </Fragment>
          ))}
        </Table.Tbody>
      </Table>
    </ScrollArea>
  );
}

function SegmentRow({ segment: s, onViewHour }: { segment: TraceArchiveSegment; onViewHour: (s: string) => void }) {
  return (
    <Table.Tr>
      <Table.Td>
        <Text size="sm" style={{ whiteSpace: "nowrap" }}>
          {clock(s.periodStart)} – {clock(s.periodEnd)}
        </Text>
      </Table.Td>
      <Table.Td>
        <Text size="xs" ff="monospace" c="dimmed">{s.name}</Text>
      </Table.Td>
      <Table.Td ta="right">
        <Text size="sm">{s.traceCount.toLocaleString()}</Text>
      </Table.Td>
      <Table.Td ta="right">
        <Text size="sm">{formatBytes(s.sizeBytes)}</Text>
      </Table.Td>
      <Table.Td>
        <Text size="xs" c="dimmed">{when(s.archivedAt)}</Text>
      </Table.Td>
      <Table.Td>
        <Group gap={4} justify="flex-end" wrap="nowrap">
          <Tooltip label="Search this hour's traces">
            <Button size="compact-xs" variant="light" leftSection={<IconSearch size={12} />} onClick={() => onViewHour(s.periodStart)}>
              View
            </Button>
          </Tooltip>
          <Menu position="bottom-end" withinPortal>
            <Menu.Target>
              <Button size="compact-xs" variant="subtle" leftSection={<IconDownload size={12} />} aria-label={`Download ${s.name}`}>
                Download
              </Button>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item component="a" href={traceArchiveDownloadUrl(s.name, false)} download={s.name}>
                Compressed (.ndjson.zst)
              </Menu.Item>
              <Menu.Item component="a" href={traceArchiveDownloadUrl(s.name, true)} download={s.name.replace(/\.zst$/, "")}>
                Plain NDJSON
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Group>
      </Table.Td>
    </Table.Tr>
  );
}
