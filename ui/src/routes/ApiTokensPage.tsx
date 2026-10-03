// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Center,
  Checkbox,
  Code,
  CopyButton,
  Group,
  Loader,
  Modal,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { IconAlertTriangle, IconKey, IconPlus, IconShieldLock, IconTrash } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "../store/useAuthStore";
import { QueryError } from "../components/QueryError";
import { ConfirmDeleteModal } from "../components/ConfirmDelete";
import { notifyError, notifySuccess } from "../utils/notify";
import { API_TOKENS_KEY, createApiToken, revokeApiToken, useApiTokens } from "../hooks/useApiTokens";
import {
  TOKEN_EXPIRY_OPTIONS,
  TOKEN_SCOPES,
  type TokenRow,
  formatTokenTime,
  isExpired,
  prometheusJob,
  tokenNameError,
  tokenRefusalMessage,
} from "../components/apiTokens";

/**
 * API tokens (ADR 0050): long-lived, scoped credentials an administrator
 * issues to a machine. /metrics used to accept only a user's eight-hour
 * session, so a scraper needed an account and a script signing it in again.
 */
export default function ApiTokensPage() {
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  if (!isAdmin) {
    return (
      <Center style={{ height: "50vh" }}>
        <Stack align="center" gap="xs">
          <IconShieldLock size={48} color="var(--mantine-color-red-6)" />
          <Title order={2}>Access Denied</Title>
          <Text c="dimmed">Only an administrator can manage API tokens.</Text>
        </Stack>
      </Center>
    );
  }
  return <TokensView />;
}

function TokensView() {
  const { data, isLoading, isError, error, refetch } = useApiTokens();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [issued, setIssued] = useState<{ name: string; secret: string } | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<TokenRow | null>(null);
  const [revoking, setRevoking] = useState(false);

  const confirmRevoke = async () => {
    const row = pendingRevoke;
    if (!row) return;
    setRevoking(true);
    try {
      await revokeApiToken(row.id);
      notifySuccess(`API token "${row.name}" revoked.`);
    } catch (err) {
      notifyError(err, { title: `Could not revoke "${row.name}"`, message: tokenRefusalMessage(err) });
    } finally {
      setRevoking(false);
      setPendingRevoke(null);
      void queryClient.invalidateQueries({ queryKey: API_TOKENS_KEY });
    }
  };

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-end">
        <Stack gap={0}>
          <Title order={2}>API tokens</Title>
          <Text c="dimmed" size="sm">
            Credentials for machines. A token with "Read metrics" lets a scraper read /metrics and nothing else;
            it is never a dashboard session.
          </Text>
        </Stack>
        <Button leftSection={<IconPlus size={16} />} onClick={() => setCreating(true)}>
          Create token
        </Button>
      </Group>

      <Card withBorder radius="md" p={0}>
        {isLoading && (
          <Center p="xl">
            <Loader size="sm" />
          </Center>
        )}
        {isError && (
          <Stack p="md">
            <QueryError error={error} what="API tokens" onRetry={() => void refetch()} />
          </Stack>
        )}
        {!isLoading && !isError && (data?.length ?? 0) === 0 && (
          <Stack align="center" gap="xs" p="xl">
            <IconKey size={32} color="var(--mantine-color-dimmed)" />
            <Text fw={600}>No API tokens</Text>
            <Text size="sm" c="dimmed" ta="center">
              Create one for each scraper, so revoking one does not cut off the others.
            </Text>
          </Stack>
        )}
        {!isLoading && !isError && (data?.length ?? 0) > 0 && (
          <TokenTable rows={data ?? []} onRevoke={setPendingRevoke} />
        )}
      </Card>

      <CreateTokenModal
        opened={creating}
        onClose={() => setCreating(false)}
        onIssued={(t) => {
          setCreating(false);
          setIssued(t);
          void queryClient.invalidateQueries({ queryKey: API_TOKENS_KEY });
        }}
      />
      <IssuedTokenModal issued={issued} onClose={() => setIssued(null)} />
      <ConfirmDeleteModal
        target={pendingRevoke ? { kind: "API token", name: pendingRevoke.name, id: pendingRevoke.hint } : null}
        consequence="Anything using it is refused from its next request."
        loading={revoking}
        onCancel={() => setPendingRevoke(null)}
        onConfirm={() => void confirmRevoke()}
      />
    </Stack>
  );
}

function TokenTable({ rows, onRevoke }: { rows: TokenRow[]; onRevoke: (row: TokenRow) => void }) {
  const now = new Date();
  return (
    <Table.ScrollContainer minWidth={760}>
      <Table verticalSpacing="sm" highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Name</Table.Th>
            <Table.Th>Token</Table.Th>
            <Table.Th>Scopes</Table.Th>
            <Table.Th>Created</Table.Th>
            <Table.Th>Last used</Table.Th>
            <Table.Th>Expires</Table.Th>
            <Table.Th />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.map((row) => (
            <Table.Tr key={row.id}>
              <Table.Td>
                <Text fw={600} size="sm">{row.name}</Text>
                <Text size="xs" c="dimmed">by {row.createdBy || "unknown"}</Text>
              </Table.Td>
              <Table.Td>
                <Code>{row.hint}</Code>
              </Table.Td>
              <Table.Td>
                <Group gap={4}>
                  {row.scopes.map((s) => (
                    <Badge key={s} variant="light" size="sm">{s}</Badge>
                  ))}
                </Group>
              </Table.Td>
              <Table.Td><Text size="sm">{formatTokenTime(row.createdAt, "")}</Text></Table.Td>
              <Table.Td><Text size="sm">{formatTokenTime(row.lastUsedAt, "Never")}</Text></Table.Td>
              <Table.Td>
                {isExpired(row, now) ? (
                  <Badge color="red" variant="light">Expired</Badge>
                ) : (
                  <Text size="sm">{formatTokenTime(row.expiresAt, "Never")}</Text>
                )}
              </Table.Td>
              <Table.Td>
                <Button
                  size="xs"
                  variant="subtle"
                  color="red"
                  leftSection={<IconTrash size={14} />}
                  aria-label={`Revoke API token ${row.name}`}
                  onClick={() => onRevoke(row)}
                >
                  Revoke
                </Button>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

interface CreateTokenModalProps {
  opened: boolean;
  onClose: () => void;
  onIssued: (issued: { name: string; secret: string }) => void;
}

function CreateTokenModal({ opened, onClose, onIssued }: CreateTokenModalProps) {
  const [saving, setSaving] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const form = useForm({
    initialValues: { name: "", scopes: ["metrics:read"] as string[], ttlDays: "0" },
    validate: {
      name: tokenNameError,
      scopes: (v: string[]) => (v.length === 0 ? "Choose at least one scope" : null),
    },
  });

  const close = () => {
    form.reset();
    setRefusal(null);
    onClose();
  };

  const submit = async (values: typeof form.values) => {
    setSaving(true);
    setRefusal(null);
    try {
      const issued = await createApiToken(values.name.trim(), values.scopes, Number(values.ttlDays));
      form.reset();
      onIssued(issued);
    } catch (err) {
      setRefusal(tokenRefusalMessage(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal opened={opened} onClose={close} title="Create API token" centered radius="md">
      <form onSubmit={form.onSubmit((v) => void submit(v))}>
        <Stack gap="sm">
          <TextInput
            label="Name"
            description="Who uses it, so you know what revoking it stops."
            placeholder="prometheus-eu-1"
            required
            {...form.getInputProps("name")}
          />
          <Checkbox.Group label="Scopes" required {...form.getInputProps("scopes")}>
            <Stack gap={4} mt={4}>
              {TOKEN_SCOPES.map((s) => (
                <Checkbox key={s.value} value={s.value} label={s.label} />
              ))}
            </Stack>
          </Checkbox.Group>
          <Select label="Expires" data={TOKEN_EXPIRY_OPTIONS} allowDeselect={false} {...form.getInputProps("ttlDays")} />
          {refusal && (
            <Alert color="red" variant="light" role="alert">
              {refusal}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>Cancel</Button>
            <Button type="submit" loading={saving}>Create token</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function IssuedTokenModal({ issued, onClose }: { issued: { name: string; secret: string } | null; onClose: () => void }) {
  return (
    <Modal
      opened={issued !== null}
      onClose={onClose}
      title={`API token "${issued?.name ?? ""}" created`}
      centered
      radius="md"
      size="lg"
      closeOnClickOutside={false}
    >
      {issued && (
        <Stack gap="sm">
          <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={16} />}>
            Copy the token now. It is not stored and will not be shown again; if it is lost, revoke it and create
            another.
          </Alert>
          <Group gap="xs" wrap="nowrap">
            <Code block style={{ flex: 1, wordBreak: "break-all" }}>{issued.secret}</Code>
            <CopyButton value={issued.secret}>
              {({ copied, copy }) => (
                <Button size="xs" variant={copied ? "light" : "filled"} onClick={copy}>
                  {copied ? "Copied" : "Copy"}
                </Button>
              )}
            </CopyButton>
          </Group>
          <Text size="sm">
            Put it in a file only Prometheus can read, and scrape with it as a bearer token:
          </Text>
          <Code block>{prometheusJob(window.location.host)}</Code>
          <Group justify="flex-end">
            <Button onClick={onClose}>I have copied it</Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}
