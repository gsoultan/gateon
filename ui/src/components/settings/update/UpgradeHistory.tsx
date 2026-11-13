// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Badge, Stack, Table, Text, Title } from "@mantine/core";
import { UpgradePhase, type UpgradeRecord } from "../../../services/gen/gateon/v1/status_pb";
import { safeToDateLocaleString } from "../../../utils/format";
import { outcomeLabel, startedBy } from "./upgradeView";

const COLORS: Partial<Record<UpgradePhase, string>> = {
  [UpgradePhase.SUCCEEDED]: "green",
  [UpgradePhase.ROLLED_BACK]: "yellow",
  [UpgradePhase.REFUSED]: "gray",
  [UpgradePhase.FAILED]: "red",
};

/**
 * The installs this host's upgrade helper has finished, newest first
 * (ADR 0087). The helper keeps twenty, so the table needs no paging. Every
 * string here is the gateway's own or a version it parsed; the name of who
 * asked is rendered as text.
 */
export function UpgradeHistory({ history }: { history: UpgradeRecord[] }) {
  return (
    <Stack gap="xs">
      <Title order={4}>Upgrade history</Title>
      {history.length === 0 ? (
        <Text size="sm" c="dimmed">
          No release has been installed from this gateway yet. Installs made with a package manager are not listed here.
        </Text>
      ) : (
        <Table.ScrollContainer minWidth={520}>
          <Table verticalSpacing="xs" aria-label="Upgrade history">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>When</Table.Th>
                <Table.Th>Version</Table.Th>
                <Table.Th>Outcome</Table.Th>
                <Table.Th>Started by</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {history.map((r) => (
                <Table.Tr key={`${r.startedAt}-${r.targetVersion}`}>
                  <Table.Td>{safeToDateLocaleString(Number(r.finishedAt || r.startedAt) * 1000, "Unknown")}</Table.Td>
                  <Table.Td>
                    v{r.previousVersion} to v{r.targetVersion}
                  </Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={COLORS[r.phase] ?? "blue"} tt="none">
                      {outcomeLabel(r.phase)}
                    </Badge>
                  </Table.Td>
                  <Table.Td>{startedBy(r)}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Stack>
  );
}
