// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Anchor, Button, Card, Code, CopyButton, Group, Skeleton, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { IconAlertTriangle, IconArrowUpCircle, IconCheck, IconCopy, IconRefresh } from "@tabler/icons-react";
import { useCheckForUpdate, useUpdateStatus } from "../../../hooks/useUpdateStatus";
import { usePermissions } from "../../../hooks/usePermissions";
import { UpdateCheckState, type UpdateStatus } from "../../../services/gen/gateon/v1/status_pb";
import { checkedAgo, installKindLabel, staleNote, updateView, upgradeSteps } from "./updateView";

/** How to take the new version on this kind of install, with the release notes. */
function UpgradeSteps({ status }: { status: UpdateStatus }) {
  const steps = upgradeSteps(status.installKind, status.latestVersion);
  return (
    <Stack gap="sm">
      <Text size="sm">{steps.text}</Text>
      {steps.command && (
        <Group gap="xs" wrap="nowrap" align="stretch">
          <Code block style={{ flex: 1, minWidth: 0, overflowX: "auto", whiteSpace: "nowrap" }}>
            {steps.command}
          </Code>
          <CopyButton value={steps.command}>
            {({ copied, copy }) => (
              <Button variant="default" onClick={copy} leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />}>
                {copied ? "Copied" : "Copy"}
              </Button>
            )}
          </CopyButton>
        </Group>
      )}
      {status.releaseNotesUrl && (
        <Anchor href={status.releaseNotesUrl} target="_blank" rel="noopener noreferrer" size="sm" fw={600}>
          Release notes for v{status.latestVersion}
        </Anchor>
      )}
    </Stack>
  );
}

function StatusBody({ status }: { status: UpdateStatus }) {
  const view = updateView(status);
  const stale = staleNote(status);
  return (
    <Alert color={view.tone} variant="light" title={view.title} data-testid="update-status">
      <Stack gap="sm">
        <Text size="sm">{view.detail}</Text>
        {stale && (
          <Text size="xs" c="dimmed">
            {stale}
          </Text>
        )}
        {status.updateAvailable && <UpgradeSteps status={status} />}
      </Stack>
    </Alert>
  );
}

/**
 * The running version, whether a newer release exists, and how this install
 * takes it (ADR 0085). It reports and explains; it installs nothing.
 */
export function UpdateStatusCard() {
  const { data: status, isPending, isError, refetch } = useUpdateStatus();
  const check = useCheckForUpdate();
  const { canEditGlobal } = usePermissions();
  const off = status?.state === UpdateCheckState.DISABLED;
  const ago = status ? checkedAgo(status.checkedAt, Date.now()) : "";

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="lg">
        <Group justify="space-between" wrap="nowrap" align="flex-start">
          <Group wrap="nowrap" align="flex-start">
            <ThemeIcon size="xl" radius="md" variant="light" color="blue">
              <IconArrowUpCircle size={24} />
            </ThemeIcon>
            <Stack gap={2}>
              <Title order={3}>Software update</Title>
              {status && (
                <Text size="sm" c="dimmed">
                  Installed: {status.currentVersion || "unknown"} · {installKindLabel(status.installKind)}
                  {ago && ` · last checked ${ago}`}
                </Text>
              )}
            </Stack>
          </Group>
          {canEditGlobal && (
            <Button
              variant="default"
              leftSection={<IconRefresh size={16} />}
              onClick={() => check.mutate()}
              loading={check.isPending}
              disabled={!status || off}
            >
              Check now
            </Button>
          )}
        </Group>

        {isPending && <Skeleton height={96} radius="md" />}
        {isError && (
          <Alert color="red" variant="light" icon={<IconAlertTriangle size={16} />} title="The update status could not be loaded">
            <Stack gap="xs" align="flex-start">
              <Text size="sm">The gateway did not answer. Nothing here was changed.</Text>
              <Button size="xs" variant="light" color="red" onClick={() => void refetch()}>
                Retry
              </Button>
            </Stack>
          </Alert>
        )}
        {status && <StatusBody status={status} />}
        {check.isError && (
          <Alert color="red" variant="light" icon={<IconAlertTriangle size={16} />} title="The check could not be run">
            The gateway did not answer, or your role may not run it.
          </Alert>
        )}
      </Stack>
    </Card>
  );
}
