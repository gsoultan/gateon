// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Card,
  Center,
  Group,
  ScrollArea,
  SegmentedControl,
  Select,
  Skeleton,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
  VisuallyHidden,
} from "@mantine/core";
import { IconInfoCircle, IconSearch } from "@tabler/icons-react";
import { useMemo, useState, type FormEvent } from "react";

import {
  HISTORY_MAX_ROWS,
  loadedRows,
  useTraceHistory,
  type TraceHistoryQuery,
} from "../../hooks/useTraceHistory";
import type { Trace } from "../../hooks/useTraces";
import { useTableDensity } from "../../hooks/useTableDensity";
import { safeToFixed } from "../../utils/format";
import { QueryError } from "../QueryError";
import TraceDetailsModal from "./TraceDetailsModal";
import { getDurationColor, getStatusColor } from "./traceFormat";
import {
  PERIOD_PRESETS,
  fromLocalInput,
  periodProblem,
  presetPeriod,
  toLocalInput,
  type Period,
  type PeriodPreset,
} from "./tracePeriods";
import { severalNodes } from "./traceNodes";

// "any" stands for no filter: an option needs a value of its own to be
// selected, and the gateway takes an empty string for "no filter".
const ANY = "any";
const orAny = (v: string) => (v === ANY ? "" : v);

const STATUS_OPTIONS = [
  { value: ANY, label: "Any status" },
  { value: "2xx", label: "2xx success" },
  { value: "3xx", label: "3xx redirect" },
  { value: "4xx", label: "4xx client error" },
  { value: "5xx", label: "5xx server error" },
  { value: "errors", label: "Errors (4xx and 5xx)" },
];

const METHOD_OPTIONS = [ANY, "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => ({
  value: m,
  label: m === ANY ? "Any method" : m,
}));

const formatWhen = (iso: string) =>
  new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "medium" });

interface TraceHistoryPanelProps {
  /** A period to open with, e.g. the hour picked in the Archive tab. */
  initialPeriod?: Period | null;
  /** Called with each period searched, so the page can keep it in the URL. */
  onPeriodChange?: (period: Period) => void;
}

// TraceHistoryPanel finds the traces of a period: the last day, or any hour
// the trace archive still holds. The gateway reads the live store for what it
// still has and the archive for what came before; this panel sees one list.
export default function TraceHistoryPanel({ initialPeriod, onPeriodChange }: TraceHistoryPanelProps) {
  const density = useTableDensity();
  const [preset, setPreset] = useState<PeriodPreset>(initialPeriod ? "custom" : "24h");
  const [fromInput, setFromInput] = useState(initialPeriod ? toLocalInput(initialPeriod.from) : "");
  const [toInput, setToInput] = useState(initialPeriod ? toLocalInput(initialPeriod.to) : "");
  // The custom period's exact instants, while the inputs still show them
  // unedited. A local wall-clock time names two instants in the hour clocks go
  // back, so an archived hour picked there would, read back from the inputs,
  // become a different hour on the next search.
  const [exact, setExact] = useState<Period | null>(initialPeriod ?? null);
  const [status, setStatus] = useState(ANY);
  const [method, setMethod] = useState(ANY);
  const [text, setText] = useState("");
  const [oldestFirst, setOldestFirst] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [query, setQuery] = useState<TraceHistoryQuery | null>(() =>
    buildQuery(initialPeriod ?? presetPeriod("24h"), { status: "", method: "", text: "", oldestFirst: false }),
  );
  const [selected, setSelected] = useState<Trace | null>(null);

  const history = useTraceHistory(query);
  const pages = history.data?.pages;
  const rows = useMemo(() => (pages ?? []).flatMap((p) => p.traces), [pages]);
  const lastPage = pages?.[pages.length - 1];
  const capped = !!lastPage?.nextCursor && loadedRows(pages) >= HISTORY_MAX_ROWS;

  const search = (nextPreset: PeriodPreset = preset, nextOldestFirst = oldestFirst) => {
    const period =
      nextPreset !== "custom"
        ? presetPeriod(nextPreset)
        : (exact ?? { from: fromLocalInput(fromInput), to: fromLocalInput(toInput) });
    const why = periodProblem(period);
    setProblem(why);
    if (why || !period.from || !period.to) return;
    const settled = { from: period.from, to: period.to };
    setQuery(buildQuery(settled, { status: orAny(status), method: orAny(method), text: text.trim(), oldestFirst: nextOldestFirst }));
    onPeriodChange?.(settled);
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    search();
  };

  const pickPreset = (value: string) => {
    const next = value as PeriodPreset;
    setPreset(next);
    if (next === "custom") {
      // Start the custom inputs from whatever was showing, so they are not blank.
      if (query) {
        const showing = { from: new Date(query.from), to: new Date(query.to) };
        setFromInput(toLocalInput(showing.from));
        setToInput(toLocalInput(showing.to));
        setExact(showing);
      }
      return;
    }
    search(next);
  };

  return (
    <Card withBorder padding="md">
      <Stack gap="md">
        <form onSubmit={onSubmit}>
          <Stack gap="sm">
            <Group justify="space-between" align="flex-end" wrap="wrap">
              <SegmentedControl
                aria-label="Period"
                data={PERIOD_PRESETS}
                value={preset}
                onChange={pickPreset}
              />
              <SegmentedControl
                aria-label="Order"
                data={[
                  { value: "newest", label: "Newest first" },
                  { value: "oldest", label: "Oldest first" },
                ]}
                value={oldestFirst ? "oldest" : "newest"}
                onChange={(v) => {
                  setOldestFirst(v === "oldest");
                  search(preset, v === "oldest");
                }}
              />
            </Group>
            {preset === "custom" && (
              <Group grow align="flex-end">
                <TextInput
                  type="datetime-local"
                  label="From"
                  description="Your local time"
                  value={fromInput}
                  onChange={(e) => {
                    setFromInput(e.currentTarget.value);
                    setExact(null);
                  }}
                />
                <TextInput
                  type="datetime-local"
                  label="To"
                  description="Your local time"
                  value={toInput}
                  onChange={(e) => {
                    setToInput(e.currentTarget.value);
                    setExact(null);
                  }}
                />
              </Group>
            )}
            <Group align="flex-end" wrap="wrap">
              <Select
                label="Status"
                data={STATUS_OPTIONS}
                value={status}
                onChange={(v) => setStatus(v ?? ANY)}
                allowDeselect={false}
                w={{ base: "100%", sm: 200 }}
              />
              <Select
                label="Method"
                data={METHOD_OPTIONS}
                value={method}
                onChange={(v) => setMethod(v ?? ANY)}
                allowDeselect={false}
                w={{ base: "100%", sm: 150 }}
              />
              <TextInput
                label="Contains"
                placeholder="Path, trace ID, source IP or service"
                leftSection={<IconSearch size={16} />}
                value={text}
                maxLength={256}
                onChange={(e) => setText(e.currentTarget.value)}
                style={{ flex: 1, minWidth: 220 }}
              />
              <Button type="submit" leftSection={<IconSearch size={16} />} loading={history.isFetching && !history.isFetchingNextPage}>
                Search
              </Button>
            </Group>
          </Stack>
        </form>

        {problem && (
          <Alert color="orange" variant="light" radius="md">
            {problem}
          </Alert>
        )}

        {query && (
          <Text size="xs" c="dimmed">
            {formatWhen(query.from)} – {formatWhen(query.to)}, your local time
          </Text>
        )}

        <HistoryTable
          rows={rows}
          density={density}
          loading={history.isLoading}
          error={history.isError && !history.isFetchNextPageError ? history.error : null}
          onRetry={() => history.refetch()}
          onOpen={setSelected}
        />

        {history.isFetchNextPageError ? (
          // The rows loaded so far stay; only the page that failed is asked for again.
          <QueryError error={history.error} what="the next page" onRetry={() => history.fetchNextPage()} />
        ) : (
          <HistoryFooter
            rows={rows.length}
            capped={capped}
            partial={!!lastPage?.partial}
            scannedTo={lastPage?.scannedTo ?? ""}
            hasMore={!!history.hasNextPage}
            loadingMore={history.isFetchingNextPage}
            settled={!history.isLoading && !history.isError}
            onMore={() => history.fetchNextPage()}
          />
        )}
      </Stack>

      <TraceDetailsModal
        traceId={selected?.id ?? null}
        timestamp={selected?.timestamp ?? null}
        opened={selected !== null}
        onClose={() => setSelected(null)}
      />
    </Card>
  );
}

function buildQuery(
  period: Period,
  f: { status: string; method: string; text: string; oldestFirst: boolean },
): TraceHistoryQuery {
  return { from: period.from.toISOString(), to: period.to.toISOString(), ...f };
}

interface HistoryTableProps {
  rows: Trace[];
  density: ReturnType<typeof useTableDensity>;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  onOpen: (t: Trace) => void;
}

function HistoryTable({ rows, density, loading, error, onRetry, onOpen }: HistoryTableProps) {
  const showNode = useMemo(() => severalNodes(rows), [rows]);
  if (error) {
    return <QueryError error={error} what="the traces for this period" onRetry={onRetry} />;
  }
  const columns = showNode ? 9 : 8;
  return (
    <ScrollArea>
      <Table {...density} highlightOnHover striped>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Started</Table.Th>
            <Table.Th>Method</Table.Th>
            <Table.Th>Path</Table.Th>
            <Table.Th>Status</Table.Th>
            <Table.Th>Duration</Table.Th>
            <Table.Th>Source IP</Table.Th>
            <Table.Th>Service</Table.Th>
            {showNode && <Table.Th>Node</Table.Th>}
            <Table.Th>
              <VisuallyHidden>Details</VisuallyHidden>
            </Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {loading
            ? Array.from({ length: 5 }).map((_, i) => (
                <Table.Tr key={i}>
                  <Table.Td colSpan={columns}>
                    <Skeleton height={20} radius="xl" />
                  </Table.Td>
                </Table.Tr>
              ))
            : rows.map((t) => (
                <HistoryRow key={`${t.node ?? ""}:${t.timestamp}:${t.id}`} trace={t} showNode={showNode} onOpen={onOpen} />
              ))}
          {!loading && rows.length === 0 && (
            <Table.Tr>
              <Table.Td colSpan={columns}>
                <Center py="xl">
                  <Stack align="center" gap={4}>
                    <Text fw={500} c="dimmed">No traces in this period</Text>
                    <Text size="xs" c="dimmed" ta="center" maw={460}>
                      Traces older than the live store's retention are here only if the trace archive is on, and
                      only for as long as the archive keeps them.
                    </Text>
                  </Stack>
                </Center>
              </Table.Td>
            </Table.Tr>
          )}
        </Table.Tbody>
      </Table>
    </ScrollArea>
  );
}

interface HistoryRowProps {
  trace: Trace;
  showNode: boolean;
  onOpen: (t: Trace) => void;
}

function HistoryRow({ trace, showNode, onOpen }: HistoryRowProps) {
  return (
    <Table.Tr>
      <Table.Td>
        <Text size="xs" style={{ whiteSpace: "nowrap" }}>{formatWhen(trace.timestamp)}</Text>
      </Table.Td>
      <Table.Td>
        <Badge variant="outline" color="blue" size="xs">{trace.method || "-"}</Badge>
      </Table.Td>
      <Table.Td>
        <Tooltip label={trace.path} multiline maw={400} withArrow openDelay={300}>
          <Text size="xs" truncate="end" maw={260}>{trace.path}</Text>
        </Tooltip>
      </Table.Td>
      <Table.Td>
        <Badge variant="filled" color={getStatusColor(trace.status)}>{trace.status}</Badge>
      </Table.Td>
      <Table.Td>
        <Badge variant="light" color={getDurationColor(trace.durationMs)} radius="sm">
          {safeToFixed(trace.durationMs, trace.durationMs < 1 ? 3 : 2)} ms
        </Badge>
      </Table.Td>
      <Table.Td>
        <Text size="xs" ff="monospace">{trace.sourceIp || "-"}</Text>
      </Table.Td>
      <Table.Td>
        <Text size="xs" truncate="end" maw={160}>{trace.serviceName || "-"}</Text>
      </Table.Td>
      {showNode && (
        <Table.Td>
          <Text size="xs" ff="monospace" style={{ whiteSpace: "nowrap" }}>{trace.node || "-"}</Text>
        </Table.Td>
      )}
      <Table.Td>
        <ActionIcon variant="subtle" onClick={() => onOpen(trace)} aria-label={`Details of trace ${trace.id}`}>
          <IconInfoCircle size={16} />
        </ActionIcon>
      </Table.Td>
    </Table.Tr>
  );
}

interface HistoryFooterProps {
  rows: number;
  capped: boolean;
  partial: boolean;
  scannedTo: string;
  hasMore: boolean;
  loadingMore: boolean;
  settled: boolean;
  onMore: () => void;
}

// HistoryFooter says where the list stands: more to load, a search that ran
// out of budget before finding enough, the row cap, or the end of the period.
function HistoryFooter({ rows, capped, partial, scannedTo, hasMore, loadingMore, settled, onMore }: HistoryFooterProps) {
  if (!settled || (rows === 0 && !hasMore)) return null;
  return (
    <Group justify="space-between" align="center">
      <Text size="xs" c="dimmed">
        {rows.toLocaleString()} {rows === 1 ? "trace" : "traces"}
        {partial && scannedTo && ` · searched up to ${formatWhen(scannedTo)}`}
        {capped && ` · showing the first ${HISTORY_MAX_ROWS.toLocaleString()}; narrow the period or add a filter for the rest`}
        {!hasMore && !capped && " · end of the period"}
      </Text>
      {hasMore && (
        <Button size="xs" variant="light" onClick={onMore} loading={loadingMore}>
          {partial ? "Keep searching" : "Load more"}
        </Button>
      )}
    </Group>
  );
}
