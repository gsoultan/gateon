// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, Group, Alert, Paper, Box, ActionIcon, Tooltip, Code, CopyButton } from "@mantine/core";
import { IconInfoCircle, IconBolt, IconCopy, IconCheck } from "@tabler/icons-react";

// The process-level environment variables that matter at high throughput.
// Read-only: they are set where the gateway is started, not saved here.
export function PerformanceEnvCard() {
  return (
    <Card withBorder padding="xl" radius="lg" shadow="xs">
      <Stack gap="lg">
        <Group gap="md">
          <Paper p="xs" radius="md" bg="orange.6">
            <IconBolt size={20} color="white" />
          </Paper>
          <div>
            <Title order={4} fw={700}>
              Performance & High-Throughput
            </Title>
            <Text c="dimmed" size="xs">
              Environment variables for 100k+ req/s. Set before starting the gateway.
            </Text>
          </div>
        </Group>
        <Alert icon={<IconInfoCircle size={16} />} color="orange" variant="light" radius="md">
          These are process-level env vars. Configure before starting Gateon or via your deployment (Docker, Kubernetes, systemd).
        </Alert>
        <Stack gap="sm">
          <Box>
            <Text size="sm" fw={600} mb={4}>Entrypoint Rate Limit</Text>
            <Text size="xs" c="dimmed" mb={4}>
              Per-IP requests/sec. Use <Code>0</Code> to disable for high throughput.
            </Text>
            <Group gap="xs">
              <Code block style={{ flex: 1 }}>GATEON_ENTRYPOINT_RATE_LIMIT_QPS=0</Code>
              <CopyButton value="GATEON_ENTRYPOINT_RATE_LIMIT_QPS=0">
                {({ copied, copy }) => (
                  <Tooltip label={copied ? "Copied" : "Copy"}>
                    <ActionIcon color={copied ? "teal" : "gray"} variant="subtle" onClick={copy}>
                      {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                    </ActionIcon>
                  </Tooltip>
                )}
              </CopyButton>
            </Group>
          </Box>
          <Box>
            <Text size="sm" fw={600} mb={4}>Access Log Sampling</Text>
            <Text size="xs" c="dimmed" mb={4}>
              Log 1 in N requests. Use <Code>1000</Code> or <Code>10000</Code> for high traffic.
            </Text>
            <Group gap="xs">
              <Code block style={{ flex: 1 }}>GATEON_ACCESS_LOG_SAMPLE_RATE=1000</Code>
              <CopyButton value="GATEON_ACCESS_LOG_SAMPLE_RATE=1000">
                {({ copied, copy }) => (
                  <Tooltip label={copied ? "Copied" : "Copy"}>
                    <ActionIcon color={copied ? "teal" : "gray"} variant="subtle" onClick={copy}>
                      {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                    </ActionIcon>
                  </Tooltip>
                )}
              </CopyButton>
            </Group>
          </Box>
        </Stack>
      </Stack>
    </Card>
  );
}
