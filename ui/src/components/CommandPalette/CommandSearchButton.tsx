import { UnstyledButton, Group, Text, Kbd, Tooltip, ActionIcon } from "@mantine/core";
import { useOs } from "@mantine/hooks";
import { IconSearch } from "@tabler/icons-react";
import { useCommandPalette } from "./CommandPalette";

/**
 * CommandSearchButton is the header affordance that opens the ⌘K palette. On
 * wide screens it shows a search box with the platform shortcut hint; on small
 * screens it collapses to an icon-only button.
 */
export function CommandSearchButton() {
  const { open } = useCommandPalette();
  const os = useOs();
  const modKey = os === "macos" ? "⌘" : "Ctrl";

  return (
    <>
      <UnstyledButton
        onClick={open}
        visibleFrom="md"
        aria-label="Open command palette"
        px="sm"
        py={6}
        style={{
          borderRadius: "var(--mantine-radius-md)",
          border: "1px solid var(--mantine-color-default-border)",
          backgroundColor: "var(--mantine-color-default)",
          minWidth: 220,
        }}
      >
        <Group justify="space-between" wrap="nowrap" gap="sm">
          <Group gap={6} wrap="nowrap">
            <IconSearch size={16} />
            <Text size="sm" c="dimmed">
              Search…
            </Text>
          </Group>
          <Group gap={4} wrap="nowrap">
            <Kbd>{modKey}</Kbd>
            <Kbd>K</Kbd>
          </Group>
        </Group>
      </UnstyledButton>
      <Tooltip label="Search (⌘K)">
        <ActionIcon
          onClick={open}
          hiddenFrom="md"
          variant="default"
          size="md"
          radius="md"
          aria-label="Open command palette"
        >
          <IconSearch size={18} />
        </ActionIcon>
      </Tooltip>
    </>
  );
}
