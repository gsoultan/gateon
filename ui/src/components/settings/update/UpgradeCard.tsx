// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import { Code as ConnectCode, ConnectError } from "@connectrpc/connect";
import { Alert, Button, Card, Code, CopyButton, Group, Loader, Skeleton, Stack, Stepper, Text, ThemeIcon, Title } from "@mantine/core";
import { IconAlertTriangle, IconCheck, IconCopy, IconDownload, IconRefresh } from "@tabler/icons-react";
import { useInstallUpdate, useUpdateStatus } from "../../../hooks/useUpdateStatus";
import { useAdminOnlySetting } from "../../../hooks/usePermissions";
import { UpdateSignature, UpgradeBlocker, type UpdateStatus, type UpgradeRecord } from "../../../services/gen/gateon/v1/status_pb";
import { UpgradeConfirm } from "./UpgradeConfirm";
import { UpgradeHistory } from "./UpgradeHistory";
import { activeStep, blockerNote, outcomeView, progressNote, UPGRADE_STEPS, upgradeInProgress } from "./upgradeView";

/** Why an install did not start, in words for a person rather than a status code. */
function startError(err: unknown): string {
  if (err instanceof ConnectError) {
    if (err.code === ConnectCode.PermissionDenied) return "Only an administrator can install an upgrade.";
    if (err.code === ConnectCode.Aborted) return "An upgrade is already in progress on this gateway.";
    if (err.code === ConnectCode.FailedPrecondition) {
      return "That is no longer the newest verified release, or this gateway cannot install one. Close this, use Check now, and try again.";
    }
  }
  return "The gateway did not answer. Nothing was changed.";
}

/** The steps of an install under way, and one sentence on what is happening now. */
function Progress({ record, unreachable }: { record: UpgradeRecord; unreachable: boolean }) {
  return (
    <Stack gap="md" data-testid="upgrade-progress" aria-live="polite">
      <Stepper active={activeStep(record.phase)} size="sm" allowNextStepsSelect={false}>
        {UPGRADE_STEPS.map((step) => (
          <Stepper.Step key={step.label} label={step.label} description={step.description} />
        ))}
      </Stepper>
      <Group gap="xs" wrap="nowrap">
        <Loader size="xs" />
        <Text size="sm">
          {unreachable ? "The gateway is restarting and is not answering yet. This page keeps trying." : progressNote(record)}
        </Text>
      </Group>
    </Stack>
  );
}

/** How the last install ended. */
function Outcome({ record, running }: { record: UpgradeRecord; running: string }) {
  const view = outcomeView(record);
  if (!view) return null;
  // The page was loaded from the version that has just been replaced.
  const reload = view.tone === "green" && running === record.targetVersion;
  return (
    <Alert color={view.tone} variant="light" title={view.title} data-testid="upgrade-outcome">
      <Stack gap="sm" align="flex-start">
        <Text size="sm">{view.detail}</Text>
        {reload && (
          <Button size="xs" variant="light" color="green" leftSection={<IconRefresh size={14} />} onClick={() => window.location.reload()}>
            Reload the dashboard
          </Button>
        )}
      </Stack>
    </Alert>
  );
}

/** What to run on the host when this gateway cannot install by itself. */
function Blocked({ blocker }: { blocker: UpgradeBlocker }) {
  const note = blockerNote(blocker);
  if (!note) return null;
  return (
    <Stack gap="sm">
      <Text size="sm">{note.text}</Text>
      {note.command && (
        <Group gap="xs" wrap="nowrap" align="stretch">
          <Code block style={{ flex: 1, minWidth: 0, overflowX: "auto", whiteSpace: "nowrap" }}>
            {note.command}
          </Code>
          <CopyButton value={note.command}>
            {({ copied, copy }) => (
              <Button variant="default" onClick={copy} leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />}>
                {copied ? "Copied" : "Copy"}
              </Button>
            )}
          </CopyButton>
        </Group>
      )}
    </Stack>
  );
}

/** The button, or the reason there is none. */
function Offer({ status, onUpgrade }: { status: UpdateStatus; onUpgrade: () => void }) {
  const { disabled: notAdmin } = useAdminOnlySetting(false);
  const blocker = status.upgrade?.blocker ?? UpgradeBlocker.ORCHESTRATED;
  if (blocker !== UpgradeBlocker.UNSPECIFIED) return <Blocked blocker={blocker} />;
  if (!status.updateAvailable) {
    return (
      <Text size="sm" c="dimmed">
        There is nothing to install: this gateway runs the newest release it knows of.
      </Text>
    );
  }
  if (status.signature !== UpdateSignature.VERIFIED) {
    return (
      <Text size="sm" c="dimmed">
        v{status.latestVersion} could not be verified, so it is not offered for install.
      </Text>
    );
  }
  return (
    <Stack gap="xs" align="flex-start">
      <Button leftSection={<IconDownload size={16} />} onClick={onUpgrade} disabled={notAdmin}>
        Upgrade to v{status.latestVersion}
      </Button>
      <Text size="xs" c="dimmed">
        {notAdmin
          ? "Only an administrator can install an upgrade."
          : "You will be asked to confirm. The gateway restarts on the new version; the current one is kept and put back if the new one does not become ready."}
      </Text>
    </Stack>
  );
}

/**
 * Installing a release from the dashboard (ADR 0087): the button, the
 * confirmation, the progress of an install under way, how the last one ended,
 * and the history. The gateway only downloads and verifies; a root-owned
 * helper on the host replaces the binary.
 */
export function UpgradeCard() {
  const { data: status, isPending, isError, refetch } = useUpdateStatus();
  const install = useInstallUpdate();
  const [confirming, setConfirming] = useState(false);
  const record = status?.upgrade?.current;
  const running = upgradeInProgress(record?.phase);
  const close = () => {
    setConfirming(false);
    install.reset();
  };

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="lg">
        <Group wrap="nowrap" align="flex-start">
          <ThemeIcon size="xl" radius="md" variant="light" color="grape">
            <IconDownload size={24} />
          </ThemeIcon>
          <Stack gap={2}>
            <Title order={3}>Install</Title>
            <Text size="sm" c="dimmed">
              Upgrade this gateway from here. The release is verified twice, and the version it replaces is kept.
            </Text>
          </Stack>
        </Group>

        {isPending && <Skeleton height={96} radius="md" />}
        {isError && !status && (
          <Alert color="red" variant="light" icon={<IconAlertTriangle size={16} />} title="The upgrade status could not be loaded">
            <Stack gap="xs" align="flex-start">
              <Text size="sm">The gateway did not answer. Nothing here was changed.</Text>
              <Button size="xs" variant="light" color="red" onClick={() => void refetch()}>
                Retry
              </Button>
            </Stack>
          </Alert>
        )}
        {status && (
          <>
            {running && record ? <Progress record={record} unreachable={isError} /> : <Offer status={status} onUpgrade={() => setConfirming(true)} />}
            {!running && record && <Outcome record={record} running={status.currentVersion} />}
            <UpgradeHistory history={status.upgrade?.history ?? []} />
            <UpgradeConfirm
              opened={confirming}
              current={status.currentVersion}
              target={status.latestVersion}
              error={install.isError ? startError(install.error) : null}
              pending={install.isPending}
              onClose={close}
              onConfirm={() => install.mutate(status.latestVersion, { onSuccess: close })}
            />
          </>
        )}
      </Stack>
    </Card>
  );
}
