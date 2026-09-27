// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Button, Group, Modal, Stack, Text } from "@mantine/core";

/** The thing a destructive control is about to remove. */
export interface DeleteTarget {
  /** What it is, in lower case: "route", "service", "user". */
  kind: string;
  /** What the operator calls it: its name, or its id when it has none. */
  name: string;
  /** Its id, shown beside the name when the two differ. */
  id?: string;
}

interface ConfirmDeleteModalProps {
  /** The pending deletion, or null when there is none. */
  target: DeleteTarget | null;
  /** What deleting it does beyond removing it, as one sentence. */
  consequence?: string;
  /** True while the deletion is in flight. */
  loading?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

/** `"name" (id)`, or just `"name"` when the id adds nothing. */
export function describeTarget(target: DeleteTarget): string {
  const name = `"${target.name}"`;
  return target.id && target.id !== target.name ? `${name} (${target.id})` : name;
}

/**
 * The confirmation a destructive control asks for, naming its exact target.
 *
 * Several pages deleted on the first click -- a route from the desktop table,
 * a service, an entrypoint, a certificate, a client authority -- and the ones
 * that asked, asked "Are you sure you want to delete this user?", the same
 * question for every row, so a misclick on the wrong row read exactly like
 * the right one. The dialog is titled "Delete <kind>" and its question and
 * button name the thing itself.
 */
export function ConfirmDeleteModal({ target, consequence, loading, onCancel, onConfirm }: ConfirmDeleteModalProps) {
  const kind = target?.kind ?? "";
  return (
    <Modal opened={target !== null} onClose={onCancel} title={`Delete ${kind}`} centered radius="md">
      {target && (
        <Stack gap="md">
          <Text size="sm">
            Delete {kind} {describeTarget(target)}?{consequence ? ` ${consequence}` : ""}
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={onCancel}>
              Cancel
            </Button>
            <Button color="red" loading={loading} onClick={onConfirm}>
              Delete {kind}
            </Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}
