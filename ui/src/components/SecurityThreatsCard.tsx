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
} from "@mantine/core";
import { IconShieldExclamation, IconArrowRight, IconLock } from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import { useSecurityThreats } from "../hooks/useGateon";

export function SecurityThreatsCard() {
  const { data, isLoading } = useSecurityThreats(5);

  const threats = data?.threats || [];
  const criticalThreats = threats.filter(t => t.severity === "critical" || t.severity === "high").length;

  return (
    <Card withBorder radius="md" p="md">
      <Card.Section withBorder inheritPadding py="xs">
        <Group justify="space-between">
          <Group gap="xs">
            <IconShieldExclamation size={20} color="var(--mantine-color-red-6)" />
            <Text fw={700}>Security Insights</Text>
          </Group>
          <Badge color={criticalThreats > 0 ? "red" : threats.length > 0 ? "orange" : "teal"}>
            {threats.length} recent events
          </Badge>
        </Group>
      </Card.Section>

      <Stack mt="md" gap="sm">
        {isLoading ? (
          <Text size="sm" c="dimmed">Analyzing threats...</Text>
        ) : threats.length === 0 ? (
          <Text size="sm" c="dimmed">No security anomalies detected in the last session.</Text>
        ) : (
          threats.map((threat, index) => (
            <Group key={index} justify="space-between" wrap="nowrap">
              <Group gap="sm" wrap="nowrap">
                <ThemeIcon color={threat.severity === "critical" ? "red" : "orange"} variant="light" size="sm">
                  <IconLock size={12} />
                </ThemeIcon>
                <Box style={{ overflow: "hidden" }}>
                  <Text size="sm" fw={500} truncate>{threat.type}</Text>
                  <Text size="xs" c="dimmed" truncate>{threat.source}</Text>
                </Box>
              </Group>
              <Badge variant="dot" size="xs" color={threat.severity === "critical" ? "red" : "orange"}>
                {threat.severity}
              </Badge>
            </Group>
          ))
        )}
      </Stack>

      <Button
        component={Link}
        to="/security"
        variant="light"
        color="gray"
        fullWidth
        mt="md"
        rightSection={<IconArrowRight size={14} />}
        size="xs"
      >
        View Security Dashboard
      </Button>
    </Card>
  );
}
