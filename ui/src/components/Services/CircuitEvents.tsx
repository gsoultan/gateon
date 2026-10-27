// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import { Button, Card, Group, Stack, Table, Text, Title } from "@mantine/core";
import { useCircuitBreakerEvents } from "../../hooks/useCircuitBreakerEvents";
import { StatusChip, circuitState } from "../status";

const SHORT = 8;

/**
 * When a target's circuit last opened, half-opened or closed, newest first.
 * This was the second half of the Circuit Breaker page; the first half is now
 * the Status column and the target rows of the Services table above.
 */
export function CircuitEvents() {
  const { data } = useCircuitBreakerEvents();
  const [all, setAll] = useState(false);
  const events = (data ?? []).slice().reverse();
  const shown = all ? events : events.slice(0, SHORT);
  return (
    <Card shadow="xs" padding="lg" radius="lg" withBorder>
      <Stack gap="md">
        <Group justify="space-between">
          <Title order={4}>Circuit events</Title>
          {events.length > SHORT && (
            <Button variant="subtle" size="xs" onClick={() => setAll((v) => !v)}>
              {all ? `Show latest ${SHORT}` : `Show all ${events.length}`}
            </Button>
          )}
        </Group>
        {events.length === 0 ? (
          <Text size="sm" c="dimmed">
            No circuit has changed state yet. A target that fails its health check or trips a route's circuit breaker appears here.
          </Text>
        ) : (
          <Table verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Time</Table.Th>
                <Table.Th>Target</Table.Th>
                <Table.Th>State</Table.Th>
                <Table.Th>Reason</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {shown.map((e, i) => {
                const c = circuitState(e.state.toLowerCase());
                return (
                  <Table.Tr key={`${e.timestamp}-${i}`}>
                    <Table.Td>
                      <Text size="xs" c="dimmed">
                        {new Date(e.timestamp).toLocaleString()}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" fw={500} ff="monospace">
                        {e.target}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <StatusChip state={c.state} label={c.label} size="xs" />
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" c="dimmed">
                        {e.reason}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        )}
      </Stack>
    </Card>
  );
}
