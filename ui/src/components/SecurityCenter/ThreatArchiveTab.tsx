// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Group,
  Modal,
  Pagination,
  ScrollArea,
  SimpleGrid,
  Skeleton,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { IconArchive, IconArrowLeft, IconSearch } from "@tabler/icons-react";

import { useThreatArchive, useThreatArchives, type ThreatArchiveFile } from "../../hooks/useThreatArchives";
import type { Anomaly } from "../../services/gen/gateon/v1/diagnostics_pb";
import { formatBytes, safeFormatDate } from "../../utils/format";
import { getSeverityColor } from "../../utils/security";
import { QueryError } from "../QueryError";

const PAGE = 25;

// Everything shown here is traffic a hostile client wrote: paths, headers,
// bodies. It is rendered only as React text, never as HTML or markdown.

// ThreatArchiveTab lists the archive files, newest first, and opens one.
export function ThreatArchiveTab() {
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<ThreatArchiveFile | null>(null);
  const { data, isLoading, error, refetch } = useThreatArchives(PAGE, (page - 1) * PAGE);

  if (open) {
    return <ArchiveFileView file={open} onBack={() => setOpen(null)} />;
  }
  if (error) {
    return <QueryError error={error} what="the security threat archive" onRetry={() => void refetch()} />;
  }
  if (isLoading || !data) {
    return <Skeleton height={240} radius="md" />;
  }
  if (data.totalCount === 0) {
    return (
      <Alert icon={<IconArchive size={16} />} title="No archived threats yet" color="gray" radius="md">
        Threats older than the retention period are archived here instead of being deleted once{" "}
        <b>Security threat archive</b> is turned on under Settings, Gateway. Until then they are deleted.
      </Alert>
    );
  }
  return (
    <Card withBorder radius="md" p="lg">
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Each file holds the threats one retention pass moved out of the database, oldest first.
        </Text>
        <ScrollArea>
          <Table highlightOnHover verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Threats from</Table.Th>
                <Table.Th>To</Table.Th>
                <Table.Th>Size</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {data.items.map((f) => (
                <Table.Tr key={f.filename}>
                  <Table.Td>{safeFormatDate(f.firstAt, "MMM d, yyyy HH:mm")}</Table.Td>
                  <Table.Td>{safeFormatDate(f.lastAt, "MMM d, yyyy HH:mm")}</Table.Td>
                  <Table.Td>{formatBytes(f.size)}</Table.Td>
                  <Table.Td>
                    <Button size="xs" variant="light" onClick={() => setOpen(f)}>
                      Open
                    </Button>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </ScrollArea>
        <Pager total={data.totalCount} page={page} onChange={setPage} />
      </Stack>
    </Card>
  );
}

function Pager({ total, page, onChange }: { total: number; page: number; onChange: (p: number) => void }) {
  const pages = Math.ceil(total / PAGE);
  if (pages <= 1) return null;
  return (
    <Group justify="center">
      <Pagination total={pages} value={page} onChange={onChange} size="sm" />
    </Group>
  );
}

function ArchiveFileView({ file, onBack }: { file: ThreatArchiveFile; onBack: () => void }) {
  const [search, setSearch] = useState("");
  const [debounced] = useDebouncedValue(search, 300);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Anomaly | null>(null);
  const { data, isLoading, error, refetch } = useThreatArchive(file.filename, debounced, PAGE, (page - 1) * PAGE);

  return (
    <Card withBorder radius="md" p="lg">
      <Stack gap="md">
        <Group justify="space-between">
          <Button variant="subtle" leftSection={<IconArrowLeft size={16} />} onClick={onBack}>
            All archives
          </Button>
          <Text size="sm" c="dimmed">
            {safeFormatDate(file.firstAt, "MMM d, yyyy HH:mm")} to {safeFormatDate(file.lastAt, "MMM d, yyyy HH:mm")}
          </Text>
        </Group>
        <TextInput
          leftSection={<IconSearch size={16} />}
          placeholder="Search address, fingerprint, type, category, path or details"
          aria-label="Search this archive"
          value={search}
          onChange={(e) => {
            setSearch(e.currentTarget.value);
            setPage(1);
          }}
        />
        {error ? (
          <QueryError error={error} what="this archive file" onRetry={() => void refetch()} />
        ) : isLoading || !data ? (
          <Skeleton height={240} radius="md" />
        ) : data.totalCount === 0 ? (
          <Text c="dimmed" ta="center" py="xl">
            {debounced ? "No archived threats in this file match your search." : "This archive file is empty."}
          </Text>
        ) : (
          <>
            <ThreatRows threats={data.items} onSelect={setSelected} />
            <Pager total={data.totalCount} page={page} onChange={setPage} />
          </>
        )}
      </Stack>
      <ArchivedThreatModal threat={selected} onClose={() => setSelected(null)} />
    </Card>
  );
}

function ThreatRows({ threats, onSelect }: { threats: Anomaly[]; onSelect: (t: Anomaly) => void }) {
  return (
    <ScrollArea>
      <Table highlightOnHover verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Time</Table.Th>
            <Table.Th>Source</Table.Th>
            <Table.Th>Type</Table.Th>
            <Table.Th>Severity</Table.Th>
            <Table.Th>Path</Table.Th>
            <Table.Th>Action</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {threats.map((t) => (
            <Table.Tr key={t.id} style={{ cursor: "pointer" }} onClick={() => onSelect(t)}>
              <Table.Td>{safeFormatDate(t.timestamp, "MMM d, HH:mm:ss")}</Table.Td>
              <Table.Td>
                <Code>{t.source}</Code>
              </Table.Td>
              <Table.Td>{t.type}</Table.Td>
              <Table.Td>
                <Badge color={getSeverityColor(t.severity)} variant="light">
                  {t.severity}
                </Badge>
              </Table.Td>
              <Table.Td maw={320}>
                <Text size="sm" truncate="end">
                  {t.requestUri}
                </Text>
              </Table.Td>
              <Table.Td>{t.actionTaken || "detected"}</Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </ScrollArea>
  );
}

function Field({ label, value }: { label: string; value: string | number }) {
  return (
    <Stack gap={2}>
      <Text size="xs" c="dimmed">
        {label}
      </Text>
      <Text size="sm" style={{ wordBreak: "break-all" }}>
        {value === "" ? "—" : value}
      </Text>
    </Stack>
  );
}

function Block({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return (
    <Stack gap={4}>
      <Title order={6}>{label}</Title>
      <Code block style={{ maxHeight: 240, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
        {value}
      </Code>
    </Stack>
  );
}

// ArchivedThreatModal shows an archived threat as it was recorded. It offers
// no mitigation: the threat is history, and its row is gone.
function ArchivedThreatModal({ threat, onClose }: { threat: Anomaly | null; onClose: () => void }) {
  return (
    <Modal opened={!!threat} onClose={onClose} title="Archived threat" size="xl" radius="md">
      {threat && (
        <Stack gap="md">
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <Field label="Time" value={safeFormatDate(threat.timestamp, "MMM d, yyyy HH:mm:ss")} />
            <Field label="Source" value={threat.source} />
            <Field label="Country" value={threat.countryCode} />
            <Field label="Type" value={threat.type} />
            <Field label="Category" value={threat.category} />
            <Field label="Score" value={threat.score} />
            <Field label="Method" value={threat.httpMethod} />
            <Field label="Action" value={threat.actionTaken} />
            <Field label="Route" value={threat.routeId} />
            <Field label="JA4" value={threat.ja4} />
            <Field label="JA4H" value={threat.ja4h} />
            <Field label="User agent" value={threat.userAgent} />
          </SimpleGrid>
          <Field label="Path" value={threat.requestUri} />
          <Field label="Details" value={threat.description} />
          <Block label="Triggered rules" value={threat.triggeredRules} />
          <Block label="Request headers" value={threat.requestHeaders} />
          <Block label="Request body" value={threat.requestBody} />
          <Block label="Response headers" value={threat.responseHeaders} />
          <Block label="Response body" value={threat.responseBody} />
        </Stack>
      )}
    </Modal>
  );
}

export default ThreatArchiveTab;
