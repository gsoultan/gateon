// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Stack, TextInput, Group, ActionIcon, Text, Button, Badge } from "@mantine/core";
import { IconLock, IconPlus, IconTrash } from "@tabler/icons-react";
import { StoredSecretInput } from "../settings/StoredSecretInput";
import { STORED_SECRET_SENTINEL, isSecretReference, isStoredSecret } from "../../utils/storedSecret";

interface KeyValueListProps {
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
  title: string;
  prefix: string;
  placeholderKey: string;
  placeholderValue: string;
  keyLabel?: string;
  valueLabel?: string;
}

/**
 * Rows of "<prefix><key>" config entries. The gateway never returns a stored
 * secret (ADR 0030): a header or query value that is a credential comes back as
 * the stored-secret placeholder and is shown as "Stored", kept unless replaced
 * or cleared. An API key is itself a key name, shown as
 * "key_<placeholder>_<fingerprint>": its row shows a stored key whose tenant
 * label may be edited, and deleting the row removes the key.
 */
export function KeyValueList({
  config,
  onChange,
  title,
  prefix,
  placeholderKey,
  placeholderValue,
  keyLabel = "Key",
  valueLabel = "Value",
}: KeyValueListProps) {
  const updateConfig = (key: string, value: string) => {
    onChange({ ...config, [key]: value });
  };

  const removeConfig = (key: string) => {
    const newConfig = { ...config };
    delete newConfig[key];
    onChange(newConfig);
  };

  const items = Object.entries(config || {})
    .filter(([k]) => k.startsWith(prefix))
    .map(([k, v]) => ({ fullKey: k, key: k.slice(prefix.length), value: v }));

  return (
    <Stack gap="xs">
      <Text size="sm" fw={500}>
        {title}
      </Text>
      {items.map((item, index) => {
        const storedKey = item.key.startsWith(STORED_SECRET_SENTINEL);
        const secretValue = isStoredSecret(item.value) || isSecretReference(item.value);
        return (
          // By position, as before: keyed by name, a row would remount on every
          // keystroke of a rename and drop the focus.
          <Group key={index} grow align="flex-start">
            {storedKey ? (
              <Stack gap={4}>
                <Text size="sm" fw={500}>{keyLabel}</Text>
                <Group gap="xs">
                  <Badge variant="light" color="gray" leftSection={<IconLock size={12} />}>Stored</Badge>
                  <Text size="xs" c="dimmed">Hidden. Delete the row to remove it.</Text>
                </Group>
              </Stack>
            ) : (
              <TextInput
                placeholder={placeholderKey}
                label={keyLabel}
                value={item.key}
                onChange={(e) => {
                  const newKey = prefix + e.currentTarget.value;
                  const newConfig = { ...config };
                  delete newConfig[item.fullKey];
                  newConfig[newKey] = item.value;
                  onChange(newConfig);
                }}
              />
            )}
            {secretValue ? (
              <StoredSecretInput
                label={valueLabel}
                value={item.value}
                onChange={(v) => updateConfig(item.fullKey, v)}
                clearable
              />
            ) : (
              <TextInput
                placeholder={placeholderValue}
                label={valueLabel}
                value={item.value}
                onChange={(e) => updateConfig(item.fullKey, e.currentTarget.value)}
              />
            )}
            <ActionIcon
              color="red"
              variant="light"
              onClick={() => removeConfig(item.fullKey)}
              mt={24}
              aria-label={storedKey ? `Remove the stored ${keyLabel.toLowerCase()}` : `Remove ${prefix}${item.key}`}
            >
              <IconTrash size={16} />
            </ActionIcon>
          </Group>
        );
      })}
      <Button
        variant="light"
        size="xs"
        leftSection={<IconPlus size={14} />}
        onClick={() => updateConfig(`${prefix}newKey_${Date.now()}`, "")}
        style={{ alignSelf: "flex-start" }}
      >
        Add {title}
      </Button>
    </Stack>
  );
}
