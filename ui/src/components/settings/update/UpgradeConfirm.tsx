// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Button, Group, Modal, Stack, Table, Text } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";

interface UpgradeConfirmProps {
  opened: boolean;
  current: string;
  target: string;
  /** What went wrong starting the install, in words for a person. */
  error: string | null;
  pending: boolean;
  onConfirm: () => void;
  onClose: () => void;
}

/** What an upgrade does, row by row, before anyone agrees to it. */
const rows = (current: string, target: string): [string, string][] => [
  ["Installed now", `v${current}`],
  ["New version", `v${target}`],
  ["Signature", "Signed by a Gateon release key. The installer checks it again before it replaces anything."],
  ["Database", "If this release changes the database, a copy is taken first (SQLite). A PostgreSQL database is changed in place."],
  ["Interruption", "The gateway restarts. New connections are refused for a few seconds."],
  ["If it fails", `v${current} is put back automatically, unless a PostgreSQL database was already changed.`],
];

/**
 * The confirmation for an upgrade (ADR 0087). It names the exact version and
 * says what the restart costs: the action stops the gateway, so it is never
 * one click.
 */
export function UpgradeConfirm({ opened, current, target, error, pending, onConfirm, onClose }: UpgradeConfirmProps) {
  return (
    <Modal opened={opened} onClose={onClose} title={`Upgrade this gateway to v${target}?`} centered size="lg" closeOnClickOutside={!pending}>
      <Stack gap="md">
        <Table verticalSpacing="xs" withRowBorders>
          <Table.Tbody>
            {rows(current, target).map(([label, value]) => (
              <Table.Tr key={label}>
                <Table.Th scope="row" w={130} style={{ verticalAlign: "top" }}>
                  {label}
                </Table.Th>
                <Table.Td>
                  <Text size="sm">{value}</Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {error && (
          <Alert color="red" variant="light" icon={<IconAlertTriangle size={16} />} title="The upgrade was not started">
            {error}
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button onClick={onConfirm} loading={pending} data-autofocus>
            Upgrade to v{target} and restart
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
