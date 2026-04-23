import React from "react";
import {
  Card,
  Group,
  Stack,
  Text,
  Title,
  Badge,
  Table,
  ScrollArea,
  Paper,
  ThemeIcon,
  SimpleGrid,
  Loader,
  Box,
  Alert,
  Tooltip,
} from "@mantine/core";
import {
  IconShieldExclamation,
  IconFingerprint,
  IconWorld,
  IconClock,
  IconInfoCircle,
  IconAlertTriangle,
  IconShieldCheck,
  IconLock,
} from "@tabler/icons-react";
import { useSecurityThreats } from "../hooks/useGateon";
import type { Anomaly } from "../types/gateon";

const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const color =
    severity === "critical"
      ? "red"
      : severity === "high"
      ? "orange"
      : severity === "medium"
      ? "yellow"
      : "blue";
  return (
    <Badge color={color} variant="filled" size="sm">
      {severity.toUpperCase()}
    </Badge>
  );
};

export default function SecurityPage() {
  const { data, isLoading, error } = useSecurityThreats(100);

  if (isLoading) {
    return (
      <Box p="xl" style={{ display: "flex", justifyContent: "center" }}>
        <Loader size="xl" />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert color="red" title="Error" icon={<IconAlertTriangle />}>
        Failed to load security threats: {(error as Error).message}
      </Alert>
    );
  }

  const threats = data?.threats || [];

  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Stack gap={0}>
          <Title order={2}>Security Insights</Title>
          <Text c="dimmed" size="sm">
            Recent security anomalies and potential threats detected by the system.
          </Text>
        </Stack>
        <Badge size="lg" color={threats.length > 0 ? "orange" : "teal"} leftSection={threats.length > 0 ? <IconShieldExclamation size={14} /> : <IconShieldCheck size={14} />}>
          {threats.length} Events Detected
        </Badge>
      </Group>

      <SimpleGrid cols={{ base: 1, md: 3 }}>
        <Paper withBorder p="md" radius="md">
          <Group justify="space-between">
            <Text size="xs" c="dimmed" fw={700}>THREAT LEVEL</Text>
            <IconShieldExclamation size={16} color="var(--mantine-color-red-6)" />
          </Group>
          <Title order={3} mt="xs">
            {threats.some(t => t.severity === "critical" || t.severity === "high") ? "High" : threats.length > 0 ? "Elevated" : "Normal"}
          </Title>
        </Paper>
        <Paper withBorder p="md" radius="md">
          <Group justify="space-between">
            <Text size="xs" c="dimmed" fw={700}>UNIQUE SOURCES</Text>
            <IconWorld size={16} color="var(--mantine-color-blue-6)" />
          </Group>
          <Title order={3} mt="xs">
            {new Set(threats.map(t => t.source)).size} IPs
          </Title>
        </Paper>
        <Paper withBorder p="md" radius="md">
          <Group justify="space-between">
            <Text size="xs" c="dimmed" fw={700}>TLS FINGERPRINTS</Text>
            <IconFingerprint size={16} color="var(--mantine-color-teal-6)" />
          </Group>
          <Title order={3} mt="xs">
            {new Set(threats.filter(t => !!t.ja3).map(t => t.ja3)).size} JA3
          </Title>
        </Paper>
      </SimpleGrid>

      <Card withBorder radius="md" p={0}>
        <ScrollArea h={600}>
          <Table verticalSpacing="sm" horizontalSpacing="md" highlightOnHover>
            <Table.Thead bg="var(--mantine-color-gray-0)">
              <Table.Tr>
                <Table.Th>Event</Table.Th>
                <Table.Th>Severity</Table.Th>
                <Table.Th>Source IP</Table.Th>
                <Table.Th>Location</Table.Th>
                <Table.Th>JA3 Fingerprint</Table.Th>
                <Table.Th>Time</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {threats.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={6}>
                    <Text align="center" py="xl" c="dimmed">No security threats detected recently.</Text>
                  </Table.Td>
                </Table.Tr>
              ) : (
                threats.map((threat, index) => (
                  <Table.Tr key={index}>
                    <Table.Td>
                      <Group gap="sm">
                        <ThemeIcon color="red" variant="light" size="sm">
                          <IconLock size={14} />
                        </ThemeIcon>
                        <Stack gap={0}>
                          <Text size="sm" fw={600}>{threat.type}</Text>
                          <Text size="xs" c="dimmed">{threat.description}</Text>
                        </Stack>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <SeverityBadge severity={threat.severity} />
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace">{threat.source}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs">
                        {threat.country_code && (
                          <img 
                            src={`https://flagcdn.com/16x12/${threat.country_code.toLowerCase()}.png`} 
                            alt={threat.country_name}
                          />
                        )}
                        <Text size="sm">{threat.country_name || "Unknown"}</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      {threat.ja3 ? (
                        <Tooltip label={threat.ja3}>
                          <Badge variant="outline" size="xs" ff="monospace" style={{ maxWidth: 100 }}>
                            {threat.ja3.substring(0, 12)}...
                          </Badge>
                        </Tooltip>
                      ) : (
                        <Text size="xs" c="dimmed">N/A</Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs">
                        <IconClock size={12} color="var(--mantine-color-gray-5)" />
                        <Text size="xs" c="dimmed">
                          {new Date(threat.timestamp).toLocaleString()}
                        </Text>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
      </Card>
    </Stack>
  );
}
