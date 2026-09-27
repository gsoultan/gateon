// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  Badge,
  Center,
  Code,
  Divider,
  Grid,
  Group,
  Modal,
  Paper,
  ScrollArea,
  Skeleton,
  Stack,
  Text,
} from "@mantine/core";
import { IconInfoCircle } from "@tabler/icons-react";

import { Code as ConnectCode, ConnectError } from "@connectrpc/connect";
import { useTrace } from "../../hooks/useGateon";
import { safeToFixed } from "../../utils/format";
import { QueryError } from "../QueryError";
import { getStatusColor } from "./traceFormat";

interface TraceDetailsModalProps {
  /** The trace to show; the modal loads it in full when opened. */
  traceId: string | null;
  timestamp: string | null;
  opened: boolean;
  onClose: () => void;
}

// A trace the gateway no longer holds is an answer, not a failure: it is shown
// as such rather than as an error to retry.
const isNotFound = (err: unknown) => err instanceof ConnectError && err.code === ConnectCode.NotFound;

// TraceDetailsModal shows one trace in full. The gateway answers from its live
// store or, for a trace that has aged out of it, from the trace archive, so the
// Live and History tabs open traces the same way. Every value in it came from a
// client of the gateway and is rendered as text, never as markup.
export default function TraceDetailsModal({ traceId, timestamp, opened, onClose }: TraceDetailsModalProps) {
  const {
    data: fullTrace,
    isLoading: isFullTraceLoading,
    isError,
    error,
    refetch,
  } = useTrace(traceId || undefined, timestamp || undefined);

  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={700}>Trace Details</Text>} size="lg">
      {isError && !isNotFound(error) ? (
        <QueryError error={error} what="this trace" onRetry={() => refetch()} />
      ) : isFullTraceLoading ? (
        <Stack gap="md">
          <Skeleton height={50} radius="md" />
          <Grid columns={2}>
            <Grid.Col span={1}><Skeleton height={40} radius="md" /></Grid.Col>
            <Grid.Col span={1}><Skeleton height={40} radius="md" /></Grid.Col>
          </Grid>
          <Skeleton height={60} radius="md" />
          <Skeleton height={100} radius="md" />
          <Skeleton height={200} radius="md" />
        </Stack>
      ) : fullTrace ? (
        <Stack gap="md">
          <Paper withBorder p="sm" bg="light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))">
            <Group justify="space-between">
              <Text size="sm" fw={700} c="dimmed">TRACE ID</Text>
              <Code color="blue" variant="light">{fullTrace.id}</Code>
            </Group>
          </Paper>

          <Grid columns={2}>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">METHOD</Text>
                <Badge variant="filled" color="blue">{fullTrace.method || "N/A"}</Badge>
              </Stack>
            </Grid.Col>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">STATUS</Text>
                <Badge 
                  variant="filled" 
                  color={getStatusColor(fullTrace.status)}
                >
                  {fullTrace.status}
                </Badge>
              </Stack>
            </Grid.Col>
          </Grid>

          <Stack gap={4}>
            <Text size="xs" fw={700} c="dimmed">REQUEST URI</Text>
            <Paper withBorder p="xs" bg="light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))">
              <Text size="sm" style={{ wordBreak: 'break-all' }}>
                {fullTrace.requestUri || fullTrace.path}
              </Text>
            </Paper>
          </Stack>

          <Divider />

          <Grid columns={2}>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">SOURCE IP</Text>
                <Text size="sm" ff="monospace">{fullTrace.sourceIp || "-"}</Text>
              </Stack>
            </Grid.Col>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">DURATION</Text>
                <Text size="sm">{safeToFixed(fullTrace.durationMs, 3)} ms</Text>
              </Stack>
            </Grid.Col>
          </Grid>

          {fullTrace.reputation !== undefined && (
            <Stack gap={4}>
              <Text size="xs" fw={700} c="dimmed">TRUST SCORE</Text>
              <Badge
                variant="light"
                size="lg"
                color={fullTrace.reputation >= 80 ? "teal" : fullTrace.reputation >= 50 ? "yellow" : "red"}
              >
                {safeToFixed(fullTrace.reputation, 0)}%
              </Badge>
            </Stack>
          )}

          <Divider label="TIMING BREAKDOWN" labelPosition="center" />

          <Grid columns={4}>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">ENTRYPOINT</Text>
                <Text size="sm">{safeToFixed(fullTrace.entrypointDelayMs, 3)} ms</Text>
              </Stack>
            </Grid.Col>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">ROUTING</Text>
                <Text size="sm">{safeToFixed(fullTrace.routeDelayMs, 3)} ms</Text>
              </Stack>
            </Grid.Col>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">MIDDLEWARE</Text>
                <Text size="sm">{safeToFixed(fullTrace.middlewareDelayMs, 3)} ms</Text>
              </Stack>
            </Grid.Col>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">SERVICE</Text>
                <Text size="sm">{safeToFixed(fullTrace.serviceDelayMs, 3)} ms</Text>
              </Stack>
            </Grid.Col>
          </Grid>

          <Divider />

          <Stack gap={4}>
            <Text size="xs" fw={700} c="dimmed">USER AGENT</Text>
            <Text size="sm" c="dimmed" style={{ wordBreak: 'break-all' }}>
              {fullTrace.userAgent || "N/A"}
            </Text>
          </Stack>

          <Grid columns={2}>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">TLS JA4 FINGERPRINT</Text>
                <Text size="xs" ff="monospace" c="dimmed">{fullTrace.ja4 || "N/A"}</Text>
              </Stack>
            </Grid.Col>
            <Grid.Col span={1}>
              <Stack gap={4}>
                <Text size="xs" fw={700} c="dimmed">HTTP JA4H FINGERPRINT</Text>
                <Text size="xs" ff="monospace" c="dimmed">{fullTrace.ja4h || "N/A"}</Text>
              </Stack>
            </Grid.Col>
          </Grid>

          <Stack gap={4}>
            <Text size="xs" fw={700} c="dimmed">REFERER</Text>
            <Text size="sm" c="dimmed" style={{ wordBreak: 'break-all' }}>
              {fullTrace.referer || "N/A"}
            </Text>
          </Stack>

          <Stack gap={4}>
            <Text size="xs" fw={700} c="dimmed">TIMESTAMP</Text>
            <Text size="sm">{new Date(fullTrace.timestamp).toLocaleString()}</Text>
          </Stack>

          {fullTrace.recommendation && (
            <Paper withBorder p="sm" radius="md" style={{ borderLeft: '4px solid var(--mantine-color-blue-6)', backgroundColor: 'light-dark(var(--mantine-color-blue-0), rgba(34, 139, 230, 0.1))' }}>
              <Group gap="xs" mb={4}>
                <IconInfoCircle size={16} color="var(--mantine-color-blue-6)" />
                <Text size="sm" fw={700} c="blue.7">SMART RECOMMENDATION</Text>
              </Group>
              <Text size="sm" c="blue.9" fw={500}>{fullTrace.recommendation}</Text>
            </Paper>
          )}

          <Divider label="Metadata" labelPosition="center" />

          {fullTrace.requestHeaders && Object.keys(fullTrace.requestHeaders).length > 0 && (
            <Stack gap={4}>
              <Text size="xs" fw={700} c="dimmed">REQUEST HEADERS</Text>
              <Paper withBorder p="xs" bg="light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))">
                <Stack gap={2}>
                  {Object.entries(fullTrace.requestHeaders || {}).map(([key, value]) => (
                    <Group key={key} gap="xs" wrap="nowrap" align="flex-start">
                      <Text size="xs" fw={700} style={{ minWidth: 120 }}>{key}:</Text>
                      <Text size="xs" style={{ wordBreak: 'break-all' }}>{value}</Text>
                    </Group>
                  ))}
                </Stack>
              </Paper>
            </Stack>
          )}

          {fullTrace.requestBody && (
            <Stack gap={4}>
              <Text size="xs" fw={700} c="dimmed">REQUEST BODY</Text>
              <ScrollArea.Autosize mah={200}>
                <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {fullTrace.requestBody}
                </Code>
              </ScrollArea.Autosize>
            </Stack>
          )}

          {fullTrace.responseHeaders && Object.keys(fullTrace.responseHeaders).length > 0 && (
            <Stack gap={4}>
              <Text size="xs" fw={700} c="dimmed">RESPONSE HEADERS</Text>
              <Paper withBorder p="xs" bg="light-dark(var(--mantine-color-gray-0), var(--mantine-color-dark-6))">
                <Stack gap={2}>
                  {Object.entries(fullTrace.responseHeaders || {}).map(([key, value]) => (
                    <Group key={key} gap="xs" wrap="nowrap" align="flex-start">
                      <Text size="xs" fw={700} style={{ minWidth: 120 }}>{key}:</Text>
                      <Text size="xs" style={{ wordBreak: 'break-all' }}>{value}</Text>
                    </Group>
                  ))}
                </Stack>
              </Paper>
            </Stack>
          )}

          {fullTrace.responseBody && (
            <Stack gap={4}>
              <Text size="xs" fw={700} c="dimmed">RESPONSE BODY</Text>
              <ScrollArea.Autosize mah={200}>
                <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {fullTrace.responseBody}
                </Code>
              </ScrollArea.Autosize>
            </Stack>
          )}
        </Stack>
      ) : (
        <Center py="xl">
          <Stack align="center" gap={4}>
            <Text fw={500}>This trace is no longer stored</Text>
            <Text size="sm" c="dimmed" ta="center" maw={420}>
              It has aged out of the live trace store, and the trace archive does not hold it.
            </Text>
          </Stack>
        </Center>
      )}
    </Modal>
  );
}
