// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState, type ReactNode } from "react";
import { Badge, Button, Group, Modal, PasswordInput, Stack, Text, TextInput } from "@mantine/core";
import { IconLock } from "@tabler/icons-react";
import {
  STORED_SECRET_SENTINEL,
  isSecretReference,
  isStoredSecret,
  replacementValue,
} from "../../utils/storedSecret";

/** A confirmation required before a stored secret may be replaced. */
export type SecretReplaceConfirm = {
  title: string;
  /** What happens when the replacement is saved, said plainly. */
  consequences: ReactNode;
  confirmLabel: string;
};

export type StoredSecretInputProps = {
  label: string;
  /** The field's value as GET /v1/global returned it, or as edited since. */
  value: string | undefined;
  onChange: (value: string) => void;
  disabled?: boolean;
  /** An optional credential: offers to clear the stored value. */
  clearable?: boolean;
  description?: ReactNode;
  placeholder?: string;
  /** Offers to generate a replacement. */
  generate?: () => string;
  /** Asked before a stored value may be replaced -- a key rotation. */
  confirm?: SecretReplaceConfirm;
};

/**
 * A secret field in Settings. The gateway never returns a stored secret
 * (ADR 0028): it returns a placeholder, and saving the placeholder back keeps
 * the secret. So a stored secret is shown as "Stored", never as a value in the
 * input; the operator may replace it, and clear it where clearing is allowed.
 * Replacing starts from an empty field that keeps the stored secret until
 * something is typed, so an abandoned replacement never clears it.
 */
export function StoredSecretInput(props: StoredSecretInputProps) {
  const { label, value, onChange, disabled, clearable, description, placeholder, generate, confirm } = props;
  const [replacing, setReplacing] = useState(false);
  const [draft, setDraft] = useState("");
  const [cleared, setCleared] = useState(false);
  const [asking, setAsking] = useState<"replace" | "generate" | null>(null);

  const startReplacing = (how: "replace" | "generate") => {
    const next = how === "generate" && generate ? generate() : "";
    setDraft(next);
    setReplacing(true);
    onChange(replacementValue(next));
  };
  const request = (how: "replace" | "generate") => (confirm ? setAsking(how) : startReplacing(how));
  const keepStored = () => {
    setReplacing(false);
    setCleared(false);
    setDraft("");
    onChange(STORED_SECRET_SENTINEL);
  };

  const confirmModal = confirm && (
    <Modal opened={asking !== null} onClose={() => setAsking(null)} title={confirm.title} centered>
      <Stack gap="md">
        <Text size="sm">{confirm.consequences}</Text>
        <Group justify="flex-end">
          <Button variant="default" onClick={() => setAsking(null)}>Cancel</Button>
          <Button
            color="red"
            onClick={() => {
              const how = asking ?? "replace";
              setAsking(null);
              startReplacing(how);
            }}
          >
            {confirm.confirmLabel}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );

  if (cleared && value === "") {
    return (
      <Stack gap={4}>
        <Text size="sm" fw={500}>{label}</Text>
        <Group gap="xs">
          <Text size="xs" c="orange">The stored {label.toLowerCase()} will be removed when you save.</Text>
          <Button size="compact-xs" variant="subtle" onClick={keepStored}>Undo</Button>
        </Group>
      </Stack>
    );
  }

  if (isStoredSecret(value) && !replacing) {
    return (
      <Stack gap={4}>
        {confirmModal}
        <Text size="sm" fw={500}>{label}</Text>
        <Group gap="xs">
          <Badge variant="light" color="gray" leftSection={<IconLock size={12} />}>Stored</Badge>
          <Text size="xs" c="dimmed">Hidden. Kept unless you replace it.</Text>
          <Button size="compact-xs" variant="light" disabled={disabled} onClick={() => request("replace")}>
            Replace
          </Button>
          {generate && (
            <Button size="compact-xs" variant="subtle" disabled={disabled} onClick={() => request("generate")}>
              Generate new
            </Button>
          )}
          {clearable && (
            <Button
              size="compact-xs"
              variant="subtle"
              color="red"
              disabled={disabled}
              aria-label={`Clear the stored ${label.toLowerCase()}`}
              onClick={() => {
                setCleared(true);
                onChange("");
              }}
            >
              Clear
            </Button>
          )}
        </Group>
        {description && <Text size="xs" c="dimmed">{description}</Text>}
      </Stack>
    );
  }

  if (replacing) {
    return (
      <Stack gap={4}>
        <PasswordInput
          label={label}
          placeholder="Type the replacement"
          description={confirm ? confirm.consequences : description}
          disabled={disabled}
          value={draft}
          onChange={(e) => {
            setDraft(e.currentTarget.value);
            onChange(replacementValue(e.currentTarget.value));
          }}
          radius="md"
        />
        <Group gap="xs">
          <Button size="compact-xs" variant="subtle" onClick={keepStored}>Keep the stored value</Button>
        </Group>
      </Stack>
    );
  }

  if (isSecretReference(value)) {
    return (
      <TextInput
        label={label}
        description={description ?? "A reference to a secret held elsewhere; the gateway resolves it."}
        disabled={disabled}
        value={value}
        onChange={(e) => onChange(e.currentTarget.value)}
        radius="md"
      />
    );
  }

  return (
    <PasswordInput
      label={label}
      description={description}
      placeholder={placeholder}
      disabled={disabled}
      value={value ?? ""}
      onChange={(e) => onChange(e.currentTarget.value)}
      radius="md"
      rightSectionWidth={generate ? 80 : undefined}
      rightSection={
        generate ? (
          <Button size="compact-xs" variant="subtle" disabled={disabled} onClick={() => onChange(generate())}>
            Generate
          </Button>
        ) : undefined
      }
    />
  );
}
