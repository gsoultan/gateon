import React from "react";
import {
  Modal,
  Stack,
  Group,
  Text,
  Badge,
  Divider,
  Grid,
  ThemeIcon,
  Paper,
  Box,
  Code,
  Title,
  Tooltip,
  ActionIcon,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconShieldExclamation,
  IconClock,
  IconWorld,
  IconFingerprint,
  IconRoute,
  IconAlertCircle,
  IconCheck,
  IconMap2,
  IconShieldOff,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { Modal as MantineModal, Button, Alert } from "@mantine/core";
import { useRemoveMitigation } from "../hooks/useGateon";
import type { Anomaly } from "../types/gateon";
import TraceVisualizer from "./Diagnostics/TraceVisualizer";

interface SecurityAnomalyModalProps {
  anomaly: Anomaly | null;
  opened: boolean;
  onClose: () => void;
}

export function SecurityAnomalyModal({ anomaly, opened, onClose }: SecurityAnomalyModalProps) {
  const [traceOpened, { open: openTrace, close: closeTrace }] = useDisclosure(false);
  const [confirmOpened, { open: openConfirm, close: closeConfirm }] = useDisclosure(false);
  const removeMitigation = useRemoveMitigation();

  if (!anomaly) return null;

  const getSeverityColor = (severity: string) => {
    switch ((severity || '').toLowerCase()) {
      case "critical":
        return "red";
      case "high":
        return "orange";
      case "medium":
        return "yellow";
      case "low":
        return "blue";
      default:
        return "gray";
    }
  };

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={
        <Group gap="sm">
          <ThemeIcon color={getSeverityColor(anomaly.severity)} variant="light">
            <IconShieldExclamation size={18} />
          </ThemeIcon>
          <Text fw={700}>Security Incident Details</Text>
        </Group>
      }
      size="lg"
      radius="md"
    >
      <Stack gap="md">
        <Paper withBorder p="md" radius="md" bg="var(--mantine-color-default-hover)">
          <Group justify="space-between" align="flex-start" wrap="nowrap">
            <Stack gap={4}>
              <Text size="xs" c="dimmed" fw={700} tt="uppercase">
                Incident Type
              </Text>
              <Title order={4}>{(anomaly.type || '').replace(/_/g, " ")}</Title>
            </Stack>
            <Badge size="lg" color={getSeverityColor(anomaly.severity)} variant="filled">
              {(anomaly.severity || 'unknown').toUpperCase()}
            </Badge>
          </Group>
          <Text size="sm" mt="sm">
            {anomaly.description}
          </Text>

          {anomaly.mitigated && (
            <Button
              mt="md"
              variant="light"
              color="red"
              leftSection={<IconShieldOff size={16} />}
              onClick={openConfirm}
              fullWidth
            >
              Remove Mitigation / Allow IP
            </Button>
          )}
        </Paper>

        <Grid>
          <Grid.Col span={{ base: 12, sm: 6 }}>
            <Stack gap="xs">
              <Group gap="xs">
                <IconClock size={16} c="dimmed" />
                <Text size="sm" fw={600}>
                  Timestamp
                </Text>
              </Group>
              <Text size="sm" ml={26}>
                {new Date(anomaly.timestamp).toLocaleString()}
              </Text>
            </Stack>
          </Grid.Col>
          <Grid.Col span={{ base: 12, sm: 6 }}>
            <Stack gap="xs">
              <Group gap="xs">
                <IconWorld size={16} c="dimmed" />
                <Text size="sm" fw={600}>
                  Source IP
                </Text>
              </Group>
              <Group gap="xs" ml={26} wrap="nowrap">
                <Text size="sm" ff="monospace">
                  {anomaly.source}
                </Text>
                <Tooltip label="Visual Trace">
                  <ActionIcon 
                    variant="light" 
                    size="xs" 
                    color="brand" 
                    onClick={openTrace}
                  >
                    <IconMap2 size={12} />
                  </ActionIcon>
                </Tooltip>
                {anomaly.country_code && (
                  <Badge
                    variant="light"
                    size="xs"
                    leftSection={
                      <img
                        src={`https://flagcdn.com/16x12/${anomaly.country_code.toLowerCase()}.png`}
                        alt={anomaly.country_name}
                        style={{ borderRadius: 1, display: 'block' }}
                      />
                    }
                  >
                    {anomaly.country_name}
                  </Badge>
                )}
              </Group>
            </Stack>
          </Grid.Col>

          {anomaly.route_id && (
            <Grid.Col span={12}>
              <Stack gap="xs">
                <Group gap="xs">
                  <IconRoute size={16} c="dimmed" />
                  <Text size="sm" fw={600}>
                    Target Route
                  </Text>
                </Group>
                <Box ml={26}>
                  <Badge color="gray" variant="light" tt="none">
                    Route: {anomaly.route_id}
                  </Badge>
                  {anomaly.request_uri && (
                    <Text
                      size="xs"
                      ff="monospace"
                      c="dimmed"
                      mt={4}
                      style={{ wordBreak: "break-all" }}
                    >
                      {anomaly.request_uri}
                    </Text>
                  )}
                </Box>
              </Stack>
            </Grid.Col>
          )}

          {(anomaly.ja3 || anomaly.ja4) && (
            <Grid.Col span={12}>
              <Stack gap="xs">
                <Group gap="xs">
                  <IconFingerprint size={16} c="dimmed" />
                  <Text size="sm" fw={600}>
                    TLS Fingerprints
                  </Text>
                </Group>
                <Stack gap={4} ml={26}>
                  {anomaly.ja3 && (
                    <Group gap="xs" wrap="nowrap">
                      <Text size="xs" fw={700} w={40}>
                        JA3:
                      </Text>
                      <Code color="blue" variant="light" style={{ flex: 1, overflow: 'auto' }}>
                        {anomaly.ja3}
                      </Code>
                    </Group>
                  )}
                  {anomaly.ja4 && (
                    <Group gap="xs" wrap="nowrap">
                      <Text size="xs" fw={700} w={40}>
                        JA4+:
                      </Text>
                      <Code color="violet" variant="light" style={{ flex: 1, overflow: 'auto' }}>
                        {anomaly.ja4}
                      </Code>
                    </Group>
                  )}
                </Stack>
              </Stack>
            </Grid.Col>
          )}
        </Grid>

        <Divider />

        <Stack gap="xs">
          <Group gap="xs">
            <IconAlertCircle size={16} color="var(--mantine-color-blue-6)" />
            <Text size="sm" fw={600}>
              Recommendation
            </Text>
          </Group>
          <Paper withBorder p="sm" radius="md" bg="var(--mantine-color-blue-light)">
            <Text size="sm">{anomaly.recommendation}</Text>
          </Paper>
        </Stack>

        <Group justify="space-between">
          <Group gap="xs">
            <Text size="xs" c="dimmed">
              Mitigation Status:
            </Text>
            {anomaly.mitigated ? (
              <Badge color="teal" variant="light" leftSection={<IconCheck size={12} />}>
                Mitigated
              </Badge>
            ) : (
              <Badge color="red" variant="light" leftSection={<IconShieldExclamation size={12} />}>
                Active / Not Mitigated
              </Badge>
            )}
          </Group>
          {anomaly.score !== undefined && (
            <Group gap="xs">
              <Text size="xs" c="dimmed">
                Risk Score:
              </Text>
              <Badge
                variant="outline"
                color={anomaly.score > 70 ? "red" : anomaly.score > 40 ? "orange" : "blue"}
              >
                {anomaly.score}/100
              </Badge>
            </Group>
          )}
        </Group>
      </Stack>

      <TraceVisualizer 
        opened={traceOpened}
        onClose={closeTrace}
        targetIp={anomaly.source}
      />

      <MantineModal
        opened={confirmOpened}
        onClose={closeConfirm}
        title={<Text fw={700}>Confirm Mitigation Removal</Text>}
        centered
        size="sm"
        zIndex={1100}
      >
        <Stack gap="md">
          <Alert color="red" icon={<IconAlertTriangle size={16} />}>
            Are you sure you want to remove the mitigation for IP <b>{anomaly.source}</b>? 
            This will allow the IP to access your services again.
          </Alert>
          <Group justify="flex-end" gap="sm">
            <Button variant="default" onClick={closeConfirm}>Cancel</Button>
            <Button 
              color="red" 
              onClick={() => {
                removeMitigation.mutate(anomaly.source, {
                  onSuccess: () => {
                    closeConfirm();
                    onClose();
                  }
                });
              }}
              loading={removeMitigation.isPending}
            >
              Confirm Removal
            </Button>
          </Group>
        </Stack>
      </MantineModal>
    </Modal>
  );
}
