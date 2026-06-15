import {
  useEffect,
  useRef,
  useState,
  useMemo,
  useDeferredValue,
  useCallback,
} from "react";
import {
  Card,
  Group,
  Stack,
  Text,
  Title,
  ActionIcon,
  Tooltip,
  TextInput,
  Select,
  Paper,
  ScrollArea,
  Badge,
  Box,
  Button,
} from "@mantine/core";
import {
  IconPlayerPause,
  IconPlayerPlay,
  IconTrash,
  IconSearch,
  IconTerminal,
  IconRobot,
} from "@tabler/icons-react";
import { useAuthStore } from "../store/useAuthStore";
import { useApiConfigStore } from "../store/useApiConfigStore";
import { useDisclosure } from "@mantine/hooks";
import { LogAIAnalyst } from "./LogAIAnalyst";

interface LiveLogsProps {
  height?: number;
}

// MAX_LOGS bounds retained rows so the live stream cannot grow memory without
// limit. FLUSH_INTERVAL_MS batches incoming WebSocket messages into a single
// state update per tick, avoiding a re-render per message under high traffic.
const MAX_LOGS = 100;
const FLUSH_INTERVAL_MS = 300;

export default function LiveLogs({ height = 400 }: LiveLogsProps) {
  const [logs, setLogs] = useState<{ id: string; raw: string }[]>([]);
  const logIdCounter = useRef(0);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const [search, setSearch] = useState("");
  const [routeFilter, setRouteFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [clientIpFilter, setClientIpFilter] = useState("");
  const apiUrl = useApiConfigStore((s) => s.apiUrl);
  const token = useAuthStore((s) => s.token);
  const [aiOpened, { open: openAI, close: closeAI }] = useDisclosure(false);

  // Deferring the filter inputs keeps typing responsive: the (potentially heavy)
  // re-filter over the log buffer runs against the deferred values, so keystrokes
  // aren't blocked by the list re-render.
  const deferredSearch = useDeferredValue(search);
  const deferredRouteFilter = useDeferredValue(routeFilter);
  const deferredStatusFilter = useDeferredValue(statusFilter);
  const deferredClientIpFilter = useDeferredValue(clientIpFilter);

  useEffect(() => {
    const base = apiUrl.replace(/\/$/, "");
    const baseUrl = base.startsWith("http")
      ? base.replace(/^http/, "ws")
      : `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${
          window.location.host
        }${base}`;

    // Skip sending __cookie__ sentinel as query param; browser sends the HttpOnly cookie automatically.
    const authParam =
      token && token !== "__cookie__"
        ? `?auth=${encodeURIComponent(token)}`
        : "";
    const wsUrl = `${baseUrl}/v1/logs${authParam}`;
    const ws = new WebSocket(wsUrl);

    // Buffer messages between flushes so a burst of WS frames coalesces into one
    // React state update instead of one per frame (prevents live-stream jank).
    const pending: { id: string; raw: string }[] = [];
    const flush = () => {
      if (pending.length === 0) return;
      const batch = pending.splice(0, pending.length).reverse();
      setLogs((prev) => [...batch, ...prev].slice(0, MAX_LOGS));
    };
    const flushTimer = setInterval(flush, FLUSH_INTERVAL_MS);

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (event) => {
      if (pausedRef.current) return;
      pending.push({
        id: `${Date.now()}-${logIdCounter.current++}`,
        raw: String(event.data),
      });
      // Cap the buffer too, so a flood while a tab is backgrounded stays bounded.
      if (pending.length > MAX_LOGS) {
        pending.splice(0, pending.length - MAX_LOGS);
      }
    };

    return () => {
      clearInterval(flushTimer);
      ws.close();
    };
  }, [apiUrl, token]);

  const routeOptions = useMemo(
    () =>
      Array.from(
        new Set(
          logs
            .map((entry) => {
              try {
                const parsed = JSON.parse(entry.raw) as Record<string, unknown>;
                return String(parsed.route ?? parsed.route_id ?? "").trim();
              } catch {
                return "";
              }
            })
            .filter(Boolean),
        ),
      ).sort((a, b) => a.localeCompare(b)),
    [logs],
  );

  const filteredLogs = useMemo(() => {
    const searchLower = deferredSearch.toLowerCase();
    const ipLower = deferredClientIpFilter.toLowerCase();
    return logs.filter((entry) => {
      const log = entry.raw;
      if (deferredSearch) {
        if (!log.toLowerCase().includes(searchLower)) return false;
      }
      if (deferredRouteFilter || deferredStatusFilter || deferredClientIpFilter) {
        try {
          const parsed = JSON.parse(log) as Record<string, unknown>;
          if (deferredRouteFilter) {
            const route = String(parsed.route ?? parsed.route_id ?? "").trim();
            if (route !== deferredRouteFilter) return false;
          }
          if (deferredStatusFilter) {
            const s = String(parsed.status ?? "");
            if (s !== deferredStatusFilter && !s.startsWith(deferredStatusFilter))
              return false;
          }
          if (deferredClientIpFilter) {
            const ip = String(
              parsed.ip ?? parsed.remote_addr ?? parsed.client_ip ?? "",
            ).toLowerCase();
            if (!ip.includes(ipLower)) return false;
          }
        } catch {
          return false;
        }
      }
      return true;
    });
  }, [
    logs,
    deferredSearch,
    deferredRouteFilter,
    deferredStatusFilter,
    deferredClientIpFilter,
  ]);

  const getLogColor = useCallback((log: string) => {
    if (log.includes('"level":"error"') || log.includes("ERROR"))
      return "red.4";
    if (log.includes('"level":"warn"') || log.includes("WARN"))
      return "yellow.4";
    if (log.includes('"level":"debug"') || log.includes("DEBUG"))
      return "gray.5";
    return "blue.4";
  }, []);

  const formatLog = useCallback((log: string) => {
    try {
      const parsed = JSON.parse(log) as Record<string, any>;
      const { time, level, message, ...rest } = parsed;
      
      const formattedTime = time ? new Date(String(time)).toLocaleTimeString() : "";
      const logLevel = level ? String(level).toUpperCase() : "INFO";
      const msg = message || "";

      return (
        <Group gap="xs" align="flex-start" wrap="nowrap">
          <Text
            size="xs"
            c="dimmed"
            ff="monospace"
            className="whitespace-nowrap"
          >
            {formattedTime}
          </Text>
          <Badge
            size="xs"
            variant="light"
            color={getLogColor(log)}
            radius="sm"
            className="min-w-[50px]"
          >
            {logLevel}
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
                className="text-[10px]"
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
  }, [getLogColor]);

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
              placeholder="Text search..."
              size="xs"
              leftSection={<IconSearch size={14} />}
              value={search}
              onChange={(e) => setSearch(e.currentTarget.value)}
              w={140}
              title="Filter by any text"
            />
            <Select
              placeholder="Route"
              size="xs"
              data={routeOptions}
              value={routeFilter}
              onChange={setRouteFilter}
              searchable
              clearable
              w={180}
              title="Filter by route"
            />
            <TextInput
              placeholder="Status (e.g. 200, 5xx)"
              size="xs"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.currentTarget.value)}
              w={110}
              title="Filter by HTTP status code"
            />
            <TextInput
              placeholder="Client IP"
              size="xs"
              value={clientIpFilter}
              onChange={(e) => setClientIpFilter(e.currentTarget.value)}
              w={110}
              title="Filter by client IP (ip, remote_addr)"
            />
            <Button
              size="compact-xs"
              variant="light"
              leftSection={<IconRobot size={14} />}
              onClick={openAI}
              disabled={logs.length === 0}
              mt={2}
            >
              AI Insight
            </Button>
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
          className="border-solid border-[var(--mantine-color-default-border)] overflow-hidden"
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
              {filteredLogs.map((entry) => (
                <Box
                  key={entry.id}
                  py={2}
                  className="border-b border-solid border-[var(--mantine-color-dark-6)]"
                >
                  {formatLog(entry.raw)}
                </Box>
              ))}
            </Stack>
          </ScrollArea>
        </Paper>
      </Stack>
      <LogAIAnalyst
        logs={logs.map((e) => e.raw)}
        opened={aiOpened}
        onClose={closeAI}
      />
    </Card>
  );
}
