import React from "react";
import {
  Card,
  Group,
  Text,
  Badge,
  Stack,
  ThemeIcon,
  Button,
  Box,
  Title,
  Paper,
} from "@mantine/core";
import { IconShieldExclamation, IconArrowRight, IconLock } from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import { useSecurityThreats } from "../hooks/useGateon";

export function SecurityThreatsCard() {
  const { data, isLoading } = useSecurityThreats(5);

  const threats = data?.threats || [];
  const criticalThreats = threats.filter(t => t.severity === "critical" || t.severity === "high").length;

  return (
    <Card withBorder radius="md" p="lg" shadow="xs">
      <Group justify="space-between" mb="lg">
        <Group gap="xs">
          <ThemeIcon color="red" variant="light" size="md">
            <IconShieldExclamation size={18} />
          </ThemeIcon>
          <div>
            <Title order={5} fw={800} style={{ letterSpacing: -0.2 }}>Security Insights</Title>
            <Text size="xs" c="dimmed">Recent anomalies detected</Text>
          </div>
        </Group>
        <Badge color={criticalThreats > 0 ? "red" : threats.length > 0 ? "orange" : "teal"} size="sm">
          {threats.length} events
        </Badge>
      </Group>

      <Stack gap="xs">
        {isLoading ? (
          <Text size="sm" c="dimmed">Analyzing threats...</Text>
        ) : threats.length === 0 ? (
          <Paper withBorder p="md" radius="sm" style={{ borderStyle: 'dashed' }}>
            <Text size="xs" c="dimmed" ta="center">No security anomalies detected in the last session.</Text>
          </Paper>
        ) : (
          threats.map((threat, index) => (
            <Paper key={index} withBorder p="xs" radius="sm" bg="var(--mantine-color-default-hover)" style={{ transition: 'all 0.1s ease' }} className="hover:border-brand-5">
              <Group justify="space-between" wrap="nowrap">
                <Group gap="sm" wrap="nowrap">
                  <ThemeIcon color={threat.severity === "critical" ? "red" : "orange"} variant="light" size="sm">
                    <IconLock size={12} />
                  </ThemeIcon>
                  <Box style={{ overflow: "hidden" }}>
                    <Text size="xs" fw={700} truncate style={{ textTransform: 'uppercase', letterSpacing: 0.5 }}>{threat.type.replace(/_/g, ' ')}</Text>
                    <Text size="xs" c="dimmed" truncate>{threat.source}</Text>
                  </Box>
                </Group>
                <Badge variant="light" size="xs" color={threat.severity === "critical" ? "red" : "orange"}>
                  {threat.severity}
                </Badge>
              </Group>
            </Paper>
          ))
        )}
      </Stack>

      <Button
        component={Link}
        to="/security"
        variant="subtle"
        color="brand"
        fullWidth
        mt="md"
        rightSection={<IconArrowRight size={14} />}
        size="xs"
        fw={700}
      >
        Explore full security report
      </Button>
    </Card>
  );
}
