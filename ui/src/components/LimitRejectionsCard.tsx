import { Card, Stack, Text, Group, ThemeIcon, Loader, Box } from "@mantine/core";
import { IconShieldExclamation } from "@tabler/icons-react";
import { useLimitStatsHistory } from "../hooks/useGateon";
import { Sparkline } from "./Sparkline";
import type { LimitStats } from "../types/gateon";

function sumValues(obj: Record<string, number>): number {
  return Object.values(obj).reduce((a, b) => a + b, 0);
}

export function LimitRejectionsCard() {
  const { data, history, isLoading, error } = useLimitStatsHistory();

  if (error) return null;
  if (isLoading)
    return (
      <Card withBorder radius="lg" p="lg">
        <Group gap="sm">
          <Loader size="sm" />
          <Text size="sm" c="dimmed">
            Loading limit stats...
          </Text>
        </Group>
      </Card>
    );

  const stats = data as LimitStats | undefined;
  if (!stats) return null;

  const rateTotal = sumValues(stats.rate_limit_rejected as Record<string, number>);
  const inflightTotal = sumValues(stats.inflight_rejected as Record<string, number>);
  const bufferingTotal = sumValues(stats.buffering_rejected as Record<string, number>);
  const total = rateTotal + inflightTotal + bufferingTotal;

  if (total === 0 && history.length === 0) {
    return (
      <Card withBorder radius="lg" p="lg">
        <Group gap="md">
          <ThemeIcon size="lg" radius="md" color="green" variant="light">
            <IconShieldExclamation size={20} />
          </ThemeIcon>
          <Stack gap={2}>
            <Text size="sm" fw={600}>
              Limit Rejections
            </Text>
            <Text size="xs" c="dimmed">
              No rejections — rate limit, inflight, and buffering limits are within bounds
            </Text>
          </Stack>
        </Group>
      </Card>
    );
  }

  return (
    <Card withBorder radius="lg" p="lg">
      <Stack gap="md">
        <Group gap="md">
          <ThemeIcon size="lg" radius="md" color="orange" variant="light">
            <IconShieldExclamation size={20} />
          </ThemeIcon>
          <Stack gap={2}>
            <Text size="sm" fw={600}>
              Limit Rejections
            </Text>
            <Text size="xs" c="dimmed">
              Requests rejected by rate limit, inflight, or buffering
            </Text>
          </Stack>
        </Group>
        {history.length > 0 && history.some((v) => v > 0) && (
          <Box mb="xs">
            <Text size="xs" c="dimmed" mb={4}>
              Rejections per 5s (last 2 min)
            </Text>
            <Sparkline data={history} width={180} height={36} color="var(--mantine-color-orange-5)" />
          </Box>
        )}
        <Group gap="xl">
          {rateTotal > 0 && (
            <div>
              <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
                Rate Limit
              </Text>
              <Text size="lg" fw={700}>
                {rateTotal}
              </Text>
              <Text size="xs" c="dimmed">
                local: {(stats.rate_limit_rejected as Record<string, number>).local ?? 0} · redis: {(stats.rate_limit_rejected as Record<string, number>).redis ?? 0}
              </Text>
            </div>
          )}
          {inflightTotal > 0 && (
            <div>
              <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
                In-Flight
              </Text>
              <Text size="lg" fw={700}>
                {inflightTotal}
              </Text>
              <Text size="xs" c="dimmed">
                max_conn: {(stats.inflight_rejected as Record<string, number>).max_connections ?? 0} · per_ip: {(stats.inflight_rejected as Record<string, number>).max_connections_per_ip ?? 0}
              </Text>
            </div>
          )}
          {bufferingTotal > 0 && (
            <div>
              <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
                Buffering
              </Text>
              <Text size="lg" fw={700}>
                {bufferingTotal}
              </Text>
              <Text size="xs" c="dimmed">
                body size exceeded
              </Text>
            </div>
          )}
        </Group>
      </Stack>
    </Card>
  );
}
