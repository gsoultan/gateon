// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState, type ReactNode } from "react";
import { Code as ConnectCode, ConnectError } from "@connectrpc/connect";
import { Alert, Button, Group, Modal, Stack, Table, Text, Title } from "@mantine/core";
import { IconAlertTriangle, IconArrowBackUp } from "@tabler/icons-react";
import { useRollbackUpdate } from "../../../hooks/useUpdateStatus";
import { useAdminOnlySetting } from "../../../hooks/usePermissions";
import type { UpdateStatus } from "../../../services/gen/gateon/v1/status_pb";

/** Why a rollback did not start, in words for a person rather than a status code. */
function startError(err: unknown): string {
  if (err instanceof ConnectError) {
    if (err.code === ConnectCode.PermissionDenied) return "Only an administrator can roll this gateway back.";
    if (err.code === ConnectCode.Aborted) return "An upgrade or a rollback is already in progress on this gateway.";
    if (err.code === ConnectCode.FailedPrecondition) {
      return "That is no longer a version this gateway can go back to from here. Close this and look at the page again.";
    }
  }
  return "The gateway did not answer. Nothing was changed.";
}

/** What a rollback does, row by row, before anyone agrees to it. */
const rows = (current: string, previous: string): [string, string][] => [
  ["Running now", `v${current}`],
  ["Goes back to", `v${previous}, the version this gateway ran before its last upgrade. It is kept on this host, so nothing is downloaded.`],
  ["Database", `Left as it is. v${current} only added to what v${previous} reads, so nothing written since the upgrade is lost.`],
  ["Interruption", "The gateway restarts once, as it does for an upgrade."],
  ["If it fails", `v${current} is put back automatically and keeps running.`],
  ["Afterwards", `v${current} is not installed automatically again. You can install it again from this page.`],
];

interface RollbackConfirmProps {
  opened: boolean;
  current: string;
  previous: string;
  error: string | null;
  pending: boolean;
  onConfirm: () => void;
  onClose: () => void;
}

/** The confirmation for a rollback. It names both versions: the action restarts the gateway on an older one. */
function RollbackConfirm({ opened, current, previous, error, pending, onConfirm, onClose }: RollbackConfirmProps) {
  return (
    <Modal opened={opened} onClose={onClose} title={`Roll this gateway back to v${previous}?`} centered size="lg" closeOnClickOutside={!pending}>
      <Stack gap="md">
        <Table verticalSpacing="xs" withRowBorders>
          <Table.Tbody>
            {rows(current, previous).map(([label, value]) => (
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
          <Alert color="red" variant="light" icon={<IconAlertTriangle size={16} />} title="The rollback was not started">
            {error}
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose} disabled={pending} data-autofocus>
            Cancel
          </Button>
          <Button color="orange" onClick={onConfirm} loading={pending}>
            Roll back to v{previous} and restart
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

/**
 * Going back to the version the last upgrade replaced (ADR 0104). It renders
 * nothing when the host keeps no such version. When going back would need the
 * database copy put back as well, it shows onHost, the command for the host,
 * instead of a button: that discards data, and is not decided from a browser.
 */
export function RollbackOffer({ status, onHost }: { status: UpdateStatus; onHost: ReactNode }) {
  const { disabled: notAdmin } = useAdminOnlySetting(false);
  const rollback = useRollbackUpdate();
  const [confirming, setConfirming] = useState(false);
  const previous = status.upgrade?.rollbackVersion ?? "";
  if (!previous) return null;
  const close = () => {
    setConfirming(false);
    rollback.reset();
  };

  return (
    <Stack gap="xs" align="flex-start" data-testid="rollback-offer">
      <Title order={4}>Roll back</Title>
      {status.upgrade?.rollbackNeedsRestore ? (
        onHost
      ) : (
        <>
          <Button variant="default" leftSection={<IconArrowBackUp size={16} />} onClick={() => setConfirming(true)} disabled={notAdmin}>
            Roll back to v{previous}
          </Button>
          <Text size="xs" c="dimmed">
            {notAdmin
              ? "Only an administrator can roll this gateway back."
              : `v${previous} is the version this gateway ran before its last upgrade, kept on this host. You will be asked to confirm.`}
          </Text>
        </>
      )}
      <RollbackConfirm
        opened={confirming}
        current={status.currentVersion}
        previous={previous}
        error={rollback.isError ? startError(rollback.error) : null}
        pending={rollback.isPending}
        onClose={close}
        onConfirm={() => rollback.mutate(previous, { onSuccess: close })}
      />
    </Stack>
  );
}
