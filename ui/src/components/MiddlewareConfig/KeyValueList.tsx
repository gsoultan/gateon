import { Stack, TextInput, Group, ActionIcon, Text, Button } from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";

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

  const items = Object.entries(config)
    .filter(([k]) => k.startsWith(prefix))
    .map(([k, v]) => ({ fullKey: k, key: k.replace(prefix, ""), value: v }));

  return (
    <Stack gap="xs">
      <Text size="sm" fw={500}>
        {title}
      </Text>
      {items.map((item, index) => (
        <Group key={index} grow align="flex-start">
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
          <TextInput
            placeholder={placeholderValue}
            label={valueLabel}
            value={item.value}
            onChange={(e) => updateConfig(item.fullKey, e.currentTarget.value)}
          />
          <ActionIcon
            color="red"
            variant="light"
            onClick={() => removeConfig(item.fullKey)}
            mt={24}
          >
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
      ))}
      <Button
        variant="light"
        size="xs"
        leftSection={<IconPlus size={14} />}
        onClick={() => updateConfig(`${prefix}new_key_${Date.now()}`, "")}
        style={{ alignSelf: "flex-start" }}
      >
        Add {title}
      </Button>
    </Stack>
  );
}
