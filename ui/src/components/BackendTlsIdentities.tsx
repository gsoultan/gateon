// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { ActionIcon, Button, Group, Paper, Select, Stack, TagsInput, Text, TextInput } from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { TlsClientCertSelectionStrategy as Strategy } from "../types/gateon";
import { emptyClientIdentity } from "./serviceTlsDefaults";

const STRATEGIES = [
  { value: Strategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC.toString(), label: "Static (the client certificate above)" },
  { value: Strategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST.toString(), label: "By routed host" },
  { value: Strategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER.toString(), label: "By header set by the route" },
];

// BackendTlsIdentities edits the per-request client certificates: which one
// the gateway presents to the backend, chosen by the host the request was
// routed on or by a header the route's own middlewares set. A request with no
// match presents the static certificate, if there is one.
export function BackendTlsIdentities({ form }: { form: any }) {
  return (
    <form.Subscribe
      selector={(s: any) => s.values.tlsClientConfig?.certSelectionStrategy ?? Strategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC}
      children={(strategy: Strategy) => (
        <Stack gap="sm">
          <form.Field
            name="tlsClientConfig.certSelectionStrategy"
            children={(field: any) => (
              <Select
                label="Per-request certificate selection"
                description="Present a different client certificate depending on the request. Clients cannot choose it."
                data={STRATEGIES}
                value={(field.state.value ?? Strategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC).toString()}
                onChange={(v) => field.handleChange(Number(v ?? 0) as Strategy)}
                allowDeselect={false}
                size="xs"
              />
            )}
          />
          {strategy !== Strategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC && (
            <IdentityList form={form} byHost={strategy === Strategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST} />
          )}
        </Stack>
      )}
    />
  );
}

function IdentityList({ form, byHost }: { form: any; byHost: boolean }) {
  return (
    <form.Field
      name="tlsClientConfig.certIdentities"
      mode="array"
      children={(field: any) => {
        const items: unknown[] = field.state.value ?? [];
        return (
          <Stack gap="sm">
            {items.length === 0 && (
              <Text size="xs" c="dimmed">
                No per-request certificates yet. Every request presents the static certificate, if one is set.
              </Text>
            )}
            {items.map((_, i) => (
              <IdentityRow key={i} form={form} index={i} byHost={byHost} onRemove={() => field.removeValue(i)} />
            ))}
            <Group>
              <Button
                variant="light"
                size="xs"
                leftSection={<IconPlus size={14} />}
                onClick={() => field.pushValue(emptyClientIdentity())}
              >
                Add certificate
              </Button>
            </Group>
          </Stack>
        );
      }}
    />
  );
}

function IdentityRow({ form, index, byHost, onRemove }: { form: any; index: number; byHost: boolean; onRemove: () => void }) {
  const path = `tlsClientConfig.certIdentities[${index}]`;
  const text = (name: string, label: string, placeholder: string) => (
    <form.Field
      name={`${path}.${name}`}
      children={(f: any) => (
        <TextInput
          label={label}
          placeholder={placeholder}
          value={f.state.value ?? ""}
          onChange={(e) => f.handleChange(e.target.value)}
          size="xs"
        />
      )}
    />
  );
  return (
    <Paper withBorder p="sm" radius="md">
      <Stack gap="xs">
        <Group justify="space-between" align="flex-end" wrap="nowrap">
          {text("id", "Name", `certificate-${index + 1}`)}
          <ActionIcon
            color="red"
            variant="subtle"
            onClick={onRemove}
            aria-label={`Remove certificate ${index + 1}`}
          >
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
        <Group grow>
          {text("certFile", "Certificate Path", "/path/to/tenant.crt")}
          {text("keyFile", "Private Key Path", "/path/to/tenant.key")}
        </Group>
        {byHost ? (
          <form.Field
            name={`${path}.matchHosts`}
            children={(f: any) => (
              <TagsInput
                label="Routed hosts"
                description="Hosts this route matched the request on. Press Enter or comma after each."
                placeholder="shop.example.com"
                value={f.state.value ?? []}
                onChange={(v) => f.handleChange(v)}
                size="xs"
              />
            )}
          />
        ) : (
          <Group grow>
            {text("matchHeader", "Header", "X-Tenant")}
            {text("matchHeaderValue", "Value (blank matches any)", "acme")}
          </Group>
        )}
      </Stack>
    </Paper>
  );
}
