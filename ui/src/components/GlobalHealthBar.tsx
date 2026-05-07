import {
  Group,
  Text,
  Tooltip,
  Box,
  useMantineColorScheme,
} from "@mantine/core";
import {
  IconRoute,
  IconServer,
  IconActivity,
  IconPlugConnected,
  IconAlertTriangle,
} from "@tabler/icons-react";
import {
  useGateonStatus,
  usePathStats,
  useAggStats,
  useRequestsPerSecond,
} from "../hooks/useGateon";

export function GlobalHealthBar() {
  const { data: status } = useGateonStatus();
  const { data: pathStats } = usePathStats();
  const { data: aggStats } = useAggStats();
  const reqPerSec = useRequestsPerSecond();
  const { colorScheme } = useMantineColorScheme();

  const totalReqs =
    pathStats?.reduce((s, p) => s + (p.request_count ?? 0), 0) ?? 0;
  const reqsLabel =
    totalReqs >= 1_000_000
      ? `${(totalReqs / 1_000_000).toFixed(1)}M`
      : totalReqs >= 1000
        ? `${(totalReqs / 1000).toFixed(1)}K`
        : String(totalReqs);

  const stats = [
    {
      icon: IconRoute,
      value: status?.routes_count ?? 0,
      label: "Routes",
      color: "var(--mantine-color-brand-6)",
    },
    {
      icon: IconServer,
      value: status?.services_count ?? 0,
      label: "Services",
      color: "var(--mantine-color-teal-6)",
    },
    {
      icon: IconActivity,
      value: reqPerSec > 0 ? `${reqPerSec}/s` : reqsLabel,
      label: reqPerSec > 0 ? "Req/s" : "Total Requests",
      color: "var(--mantine-color-orange-6)",
    },
    {
      icon: IconPlugConnected,
      value: aggStats?.active_connections ?? 0,
      label: "Active Connections",
      color: "var(--mantine-color-blue-6)",
    },
  ];

  const hasAlerts =
    (aggStats?.open_circuits ?? 0) + (aggStats?.half_open_circuits ?? 0) > 0;

  if (hasAlerts) {
    stats.push({
      icon: IconAlertTriangle,
      value:
        (aggStats?.open_circuits ?? 0) + (aggStats?.half_open_circuits ?? 0),
      label: "Circuits OPEN / HALF-OPEN",
      color: "var(--mantine-color-red-6)",
    });
  }

  const bg =
    colorScheme === "dark"
      ? "var(--mantine-color-dark-6)"
      : "var(--mantine-color-gray-1)";

  const borderColor = 
    colorScheme === "dark"
      ? "var(--mantine-color-dark-4)"
      : "var(--mantine-color-gray-3)";

  return (
    <Group gap={6} wrap="nowrap" style={{ flexShrink: 0 }}>
      {stats.map(({ icon: Icon, value, label, color }) => (
        <Tooltip key={label} label={label} openDelay={500}>
          <Box
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "2px 10px",
              borderRadius: "20px",
              backgroundColor: bg,
              border: `1px solid ${borderColor}`,
              height: 28,
            }}
          >
            <Icon size={12} color={color} stroke={2.5} />
            <Text size="xs" fw={700} lh={1} style={{ fontVariantNumeric: 'tabular-nums' }}>
              {value}
            </Text>
          </Box>
        </Tooltip>
      ))}
    </Group>
  );
}
