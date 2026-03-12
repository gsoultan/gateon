import { useEffect, useState, useMemo } from "react";
import {
  Card,
  Group,
  Stack,
  Text,
  Title,
  ActionIcon,
  Tooltip,
  TextInput,
  Paper,
  ScrollArea,
  Badge,
  Box,
} from "@mantine/core";
import {
  IconPlayerPause,
  IconPlayerPlay,
  IconTrash,
  IconSearch,
  IconTerminal,
} from "@tabler/icons-react";
import { useAuthStore } from "../store/useAuthStore";

export default function LiveLogs({ height = 400 }: { height?: number }) {
  const [logs, setLogs] = useState<string[]>([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const baseUrl = import.meta.env.VITE_API_URL || "http://localhost:8080";
    const token = useAuthStore.getState().token;
    const wsUrl =
      baseUrl.replace("http", "ws") +
      "/v1/logs" +
      (token ? `?auth=${token}` : "");
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (event) => {
      if (!paused) {
        setLogs((prev) => {
          const newLogs = [event.data, ...prev];
          return newLogs.slice(0, 100);
        });
      }
    };

    return () => ws.close();
  }, [paused]);

  const filteredLogs = useMemo(() => {
    if (!search) return logs;
    return logs.filter((log) =>
      log.toLowerCase().includes(search.toLowerCase()),
    );
  }, [logs, search]);

  const getLogColor = (log: string) => {
    if (log.includes('"level":"error"') || log.includes("ERROR"))
      return "red.4";
    if (log.includes('"level":"warn"') || log.includes("WARN"))
      return "yellow.4";
    if (log.includes('"level":"debug"') || log.includes("DEBUG"))
      return "gray.5";
    return "blue.4";
  };

  const formatLog = (log: string) => {
    try {
      const parsed = JSON.parse(log);
      const time = parsed.ts
        ? new Date(parsed.ts * 1000).toLocaleTimeString()
        : "";
      const level = parsed.level ? parsed.level.toUpperCase() : "INFO";
      const msg = parsed.msg || "";
      const rest = { ...parsed };
      delete rest.ts;
      delete rest.level;
      delete rest.msg;

      return (
        <Group gap="xs" align="flex-start" wrap="nowrap">
          <Text
            size="xs"
            c="dimmed"
            ff="monospace"
            style={{ whiteSpace: "nowrap" }}
          >
            {time}
          </Text>
          <Badge
            size="xs"
            variant="light"
            color={getLogColor(log)}
            radius="sm"
            style={{ minWidth: 50 }}
          >
            {level}
          </Badge>
          <Stack gap={0} flex={1}>
            <Text size="xs" fw={600} c="gray.3" ff="monospace">
              {msg}
            </Text>
            {Object.keys(rest).length > 0 && (
              <Text
                size="xs"
                c="dimmed"
                ff="monospace"
                style={{ fontSize: 10 }}
              >
                {JSON.stringify(rest)}
              </Text>
            )}
          </Stack>
        </Group>
      );
    } catch (e) {
      return (
        <Text
          size="xs"
          ff="monospace"
          c="gray.4"
          style={{ wordBreak: "break-all" }}
        >
          {log}
        </Text>
      );
    }
  };

  return (
    <Card shadow="xs" padding="lg" radius="lg" withBorder>
      <Stack gap="sm">
        <Group justify="space-between">
          <Group gap="xs">
            <IconTerminal size={20} color="var(--mantine-color-indigo-6)" />
            <Title order={4} fw={700}>
              Live Logs
            </Title>
            <Badge
              size="xs"
              variant="dot"
              color={connected ? "green" : "red"}
              fw={700}
            >
              {connected ? "LIVE" : "OFFLINE"}
            </Badge>
            {paused && (
              <Badge size="xs" variant="filled" color="orange" fw={700}>
                PAUSED
              </Badge>
            )}
            {search && (
              <Badge size="xs" variant="light" color="gray" fw={600}>
                {filteredLogs.length} / {logs.length}
              </Badge>
            )}
          </Group>
          <Group gap="xs">
            <TextInput
              placeholder="Filter by text..."
              size="xs"
              leftSection={<IconSearch size={14} />}
              value={search}
              onChange={(e) => setSearch(e.currentTarget.value)}
              w={200}
              title="Filter logs by any text"
            />
            <Tooltip label={paused ? "Resume" : "Pause"}>
              <ActionIcon
                variant="light"
                color={paused ? "green" : "orange"}
                onClick={() => setPaused(!paused)}
              >
                {paused ? (
                  <IconPlayerPlay size={16} />
                ) : (
                  <IconPlayerPause size={16} />
                )}
              </ActionIcon>
            </Tooltip>
            <Tooltip label="Clear logs">
              <ActionIcon
                variant="light"
                color="red"
                onClick={() => setLogs([])}
                aria-label="Clear logs"
              >
                <IconTrash size={16} />
              </ActionIcon>
            </Tooltip>
          </Group>
        </Group>

        <Paper
          withBorder
          p={0}
          radius="md"
          bg="var(--mantine-color-black)"
          style={{
            border: "1px solid var(--mantine-color-default-border)",
            overflow: "hidden",
          }}
        >
          <ScrollArea h={height} offsetScrollbars scrollbarSize={8}>
            <Stack gap={4} p="xs">
              {filteredLogs.length === 0 && (
                <Text
                  size="xs"
                  c="dimmed"
                  ta="center"
                  py="xl"
                  style={{ fontFamily: "monospace" }}
                >
                  {search
                    ? "No logs match your filter. Change or clear the filter."
                    : "-- Waiting for incoming traffic --"}
                </Text>
              )}
              {filteredLogs.map((log, i) => (
                <Box
                  key={i}
                  py={2}
                  style={{
                    borderBottom: "1px solid var(--mantine-color-dark-6)",
                  }}
                >
                  {formatLog(log)}
                </Box>
              ))}
            </Stack>
          </ScrollArea>
        </Paper>
      </Stack>
    </Card>
  );
}
