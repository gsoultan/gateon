import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  Modal,
  TextInput,
  ScrollArea,
  Text,
  Group,
  Kbd,
  Stack,
  Box,
  UnstyledButton,
} from "@mantine/core";
import { useDisclosure, useHotkeys } from "@mantine/hooks";
import { IconSearch } from "@tabler/icons-react";
import { useCommands } from "./useCommands";
import type { Command } from "./types";

interface CommandPaletteContextValue {
  open: () => void;
}

const CommandPaletteContext = createContext<CommandPaletteContextValue | null>(
  null,
);

/** useCommandPalette exposes an imperative `open()` for the global palette. */
export function useCommandPalette(): CommandPaletteContextValue {
  const ctx = useContext(CommandPaletteContext);
  if (!ctx) {
    throw new Error("useCommandPalette must be used within CommandPaletteProvider");
  }
  return ctx;
}

/** Case-insensitive token match across label, description and keywords. */
function matches(cmd: Command, query: string): boolean {
  if (!query) return true;
  const haystack = [cmd.label, cmd.description ?? "", ...(cmd.keywords ?? [])]
    .join(" ")
    .toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((token) => haystack.includes(token));
}

/**
 * CommandPaletteProvider mounts a global ⌘K / Ctrl+K palette and exposes an
 * `open()` action to descendants. The palette offers fuzzy navigation across
 * every page plus quick actions (theme, sidebar, sign out) with full keyboard
 * control (Arrow keys + Enter, Escape to close).
 */
export function CommandPaletteProvider({ children }: { children: ReactNode }) {
  const [opened, { open, close }] = useDisclosure(false);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);

  const commands = useCommands(close);

  const filtered = useMemo(
    () => commands.filter((cmd) => matches(cmd, query)),
    [commands, query],
  );

  // Reset query/selection whenever the palette is (re)opened.
  useEffect(() => {
    if (opened) {
      setQuery("");
      setActiveIndex(0);
    }
  }, [opened]);

  // Keep the highlighted index within bounds as the result set shrinks.
  useEffect(() => {
    setActiveIndex((i) => Math.min(i, Math.max(0, filtered.length - 1)));
  }, [filtered.length]);

  useHotkeys([
    ["mod+K", () => (opened ? close() : open())],
  ]);

  const runActive = useCallback(() => {
    const cmd = filtered[activeIndex];
    if (cmd) cmd.perform();
  }, [filtered, activeIndex]);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveIndex((i) => Math.min(i + 1, filtered.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        runActive();
      }
    },
    [filtered.length, runActive],
  );

  const ctxValue = useMemo<CommandPaletteContextValue>(() => ({ open }), [open]);

  return (
    <CommandPaletteContext.Provider value={ctxValue}>
      {children}
      <Modal
        opened={opened}
        onClose={close}
        withCloseButton={false}
        size="lg"
        padding={0}
        radius="md"
        yOffset="12vh"
        scrollAreaComponent={ScrollArea.Autosize}
        aria-label="Command palette"
        trapFocus
      >
        <Box p="xs">
          <TextInput
            data-autofocus
            value={query}
            onChange={(e) => setQuery(e.currentTarget.value)}
            onKeyDown={onKeyDown}
            placeholder="Search pages and actions…"
            variant="unstyled"
            size="md"
            leftSection={<IconSearch size={18} />}
            aria-label="Search commands"
            styles={{ input: { fontSize: 16 } }}
          />
        </Box>
        <Box style={{ borderTop: "1px solid var(--mantine-color-default-border)" }} />
        <ScrollArea.Autosize mah={360} type="hover">
          {filtered.length === 0 ? (
            <Text c="dimmed" size="sm" ta="center" py="xl">
              No matching commands
            </Text>
          ) : (
            <CommandList
              commands={filtered}
              activeIndex={activeIndex}
              onHover={setActiveIndex}
              onSelect={(cmd) => cmd.perform()}
            />
          )}
        </ScrollArea.Autosize>
        <Group
          justify="space-between"
          px="sm"
          py={6}
          style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}
        >
          <Group gap={6}>
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd>
            <Text size="xs" c="dimmed">
              navigate
            </Text>
            <Kbd>↵</Kbd>
            <Text size="xs" c="dimmed">
              select
            </Text>
          </Group>
          <Group gap={6}>
            <Kbd>esc</Kbd>
            <Text size="xs" c="dimmed">
              close
            </Text>
          </Group>
        </Group>
      </Modal>
    </CommandPaletteContext.Provider>
  );
}

interface CommandListProps {
  commands: Command[];
  activeIndex: number;
  onHover: (index: number) => void;
  onSelect: (cmd: Command) => void;
}

/** CommandList renders the grouped, keyboard-highlightable results. */
function CommandList({ commands, activeIndex, onHover, onSelect }: CommandListProps) {
  const activeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    activeRef.current?.scrollIntoView({ block: "nearest" });
  }, [activeIndex]);

  let lastGroup = "";
  return (
    <Stack gap={0} py={4}>
      {commands.map((cmd, index) => {
        const showHeader = cmd.group !== lastGroup;
        lastGroup = cmd.group;
        const Icon = cmd.icon;
        const active = index === activeIndex;
        return (
          <Box key={cmd.id}>
            {showHeader && (
              <Text size="xs" fw={700} c="dimmed" px="sm" pt="xs" pb={4} tt="uppercase">
                {cmd.group}
              </Text>
            )}
            <UnstyledButton
              ref={active ? activeRef : undefined}
              onMouseMove={() => onHover(index)}
              onClick={() => onSelect(cmd)}
              px="sm"
              py={8}
              style={{
                display: "block",
                width: "100%",
                borderRadius: "var(--mantine-radius-sm)",
                backgroundColor: active
                  ? "var(--mantine-color-default-hover)"
                  : "transparent",
              }}
            >
              <Group gap="sm" wrap="nowrap">
                {Icon && <Icon size={18} stroke={1.5} />}
                <Box style={{ minWidth: 0 }}>
                  <Text size="sm" fw={600} truncate>
                    {cmd.label}
                  </Text>
                  {cmd.description && (
                    <Text size="xs" c="dimmed" truncate>
                      {cmd.description}
                    </Text>
                  )}
                </Box>
              </Group>
            </UnstyledButton>
          </Box>
        );
      })}
    </Stack>
  );
}
