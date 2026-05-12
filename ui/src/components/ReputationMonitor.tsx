import React from "react";
import {
  Card,
  Group,
  Stack,
  Text,
  Badge,
  Table,
  ScrollArea,
  Progress,
  ThemeIcon,
  Tooltip,
  Skeleton,
} from "@mantine/core";
import {
  IconUserExclamation,
  IconCircleCheck,
  IconAlertTriangle,
  IconActivity,
} from "@tabler/icons-react";
import { useReputations } from "../hooks/useReputations";

export function ReputationMonitor() {
  const { data, isLoading } = useReputations(20);

  if (isLoading) {
    return (
      <Card withBorder radius="md" p="md">
        <Group justify="space-between" mb="md">
          <Group>
            <Skeleton h={40} w={40} radius="md" />
            <Stack gap={4}>
              <Skeleton h={20} w={150} />
              <Skeleton h={12} w={200} />
            </Stack>
          </Group>
          <Skeleton h={20} w={60} radius="xl" />
        </Group>
        <Stack gap="xs">
          <Skeleton h={40} />
          <Skeleton h={40} />
          <Skeleton h={40} />
          <Skeleton h={40} />
          <Skeleton h={40} />
          <Skeleton h={40} />
        </Stack>
      </Card>
    );
  }

  const reputations = data?.reputations || [];

  const getScoreColor = (score: number) => {
    if (score >= 80) return "teal";
    if (score >= 50) return "yellow";
    if (score >= 20) return "orange";
    return "red";
  };

  return (
    <Card withBorder radius="md" p="md">
      <Group justify="space-between" mb="md">
        <Group>
          <ThemeIcon variant="light" color="blue" size="lg">
            <IconUserExclamation size={20} />
          </ThemeIcon>
          <Stack gap={0}>
            <Text fw={700}>Actor Reputation Monitor</Text>
            <Text size="xs" c="dimmed">Adaptive threat score for unique client fingerprints</Text>
          </Stack>
        </Group>
        <Badge variant="light" leftSection={<IconActivity size={12} />}>
          Real-time
        </Badge>
      </Group>

      <ScrollArea h={300}>
        <Table verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Fingerprint</Table.Th>
              <Table.Th>Trust Score</Table.Th>
              <Table.Th>Violations</Table.Th>
              <Table.Th>Last Activity</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {reputations.length === 0 ? (
              <Table.Tr>
                <Table.Td colSpan={4}>
                  <Text ta="center" c="dimmed" py="xl">No active high-risk fingerprints tracked.</Text>
                </Table.Td>
              </Table.Tr>
            ) : (
              reputations.map((rep) => (
                <Table.Tr key={rep.fingerprint}>
                  <Table.Td>
                    <Tooltip label={rep.fingerprint} withArrow>
                      <Text ff="monospace" size="xs">
                        {rep.fingerprint.substring(0, 12)}...
                      </Text>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td style={{ minWidth: 150 }}>
                    <Stack gap={4}>
                      <Group justify="space-between">
                        <Text size="xs" fw={700} c={getScoreColor(rep.score)}>
                          {rep.score.toFixed(0)}%
                        </Text>
                        {rep.score >= 80 ? (
                          <IconCircleCheck size={14} color="var(--mantine-color-teal-6)" />
                        ) : (
                          <IconAlertTriangle size={14} color="var(--mantine-color-orange-6)" />
                        )}
                      </Group>
                      <Progress 
                        value={rep.score} 
                        color={getScoreColor(rep.score)} 
                        size="sm" 
                        radius="xl"
                        animated={rep.score < 50}
                      />
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <Tooltip 
                      multiline 
                      w={220} 
                      withArrow 
                      label={
                        rep.history && rep.history.length > 0 
                          ? `Recent violations: ${rep.history.join(", ")}` 
                          : "No recorded violation history"
                      }
                    >
                      <Badge 
                        variant="light" 
                        color={rep.violation_count > 0 ? "red" : "gray"}
                        size="sm"
                      >
                        {rep.violation_count}
                      </Badge>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" c="dimmed">
                      {(() => {
                        const date = new Date(rep.last_event);
                        return isNaN(date.getTime()) ? 'N/A' : date.toLocaleTimeString();
                      })()}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))
            )}
          </Table.Tbody>
        </Table>
      </ScrollArea>
    </Card>
  );
}
