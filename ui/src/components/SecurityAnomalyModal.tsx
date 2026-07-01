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
  Button,
  Alert,
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
  IconDeviceLaptop,
  IconDatabase,
  IconNotes,
} from "@tabler/icons-react";
import { useRemoveMitigation, useApplyRecommendation } from "../hooks/useGateon";
import { notifications } from "@mantine/notifications";
import type { Anomaly } from "../types/gateon";
import TraceVisualizer from "./Diagnostics/TraceVisualizer";
import { getSeverityColor } from "../utils/security";

interface SecurityAnomalyModalProps {
  anomaly: Anomaly | null;
  opened: boolean;
  onClose: () => void;
}

export function SecurityAnomalyModal({ anomaly, opened, onClose }: SecurityAnomalyModalProps) {
  const [traceOpened, { open: openTrace, close: closeTrace }] = useDisclosure(false);
  const [confirmOpened, { open: openConfirm, close: closeConfirm }] = useDisclosure(false);
  const removeMitigation = useRemoveMitigation();
  const applyRecommendation = useApplyRecommendation();

  if (!anomaly) return null;

  const handleApplyFalsePositive = async () => {
    try {
      const res = await applyRecommendation.mutateAsync({
        anomaly_type: anomaly.type,
        source: anomaly.source,
        threat_id: anomaly.id,
      });
      if (res.success) {
        notifications.show({
          title: "Recommendation Applied",
          message: res.message,
          color: "green",
        });
        onClose();
      } else {
        notifications.show({
          title: "Failed to Apply",
          message: res.message,
          color: "red",
        });
      }
    } catch (err) {
      notifications.show({
        title: "Error",
        message: err instanceof Error ? err.message : "An unexpected error occurred",
        color: "red",
      });
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
            <Group grow mt="md">
              <Button
                variant="light"
                color="red"
                leftSection={<IconShieldOff size={16} />}
                onClick={openConfirm}
              >
                Remove Mitigation / Allow IP
              </Button>
              <Button
                variant="light"
                color="blue"
                leftSection={<IconCheck size={16} />}
                onClick={handleApplyFalsePositive}
                loading={applyRecommendation.isPending}
              >
                Mark as False Positive (Auto-Fix)
              </Button>
            </Group>
          )}
        </Paper>

        <Grid>
          <Grid.Col span={{ base: 12, sm: 6 }}>
            <Stack gap="xs">
              <Group gap="xs">
                <IconClock size={16} color="var(--mantine-color-dimmed)" />
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
                <IconWorld size={16} color="var(--mantine-color-dimmed)" />
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
                  <IconRoute size={16} color="var(--mantine-color-dimmed)" />
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
                  <IconFingerprint size={16} color="var(--mantine-color-dimmed)" />
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

          {anomaly.user_agent && (
            <Grid.Col span={12}>
              <Stack gap="xs">
                <Group gap="xs">
                  <IconDeviceLaptop size={16} color="var(--mantine-color-dimmed)" />
                  <Text size="sm" fw={600}>
                    User Agent
                  </Text>
                </Group>
                <Text size="xs" ml={26} c="dimmed" ff="monospace">
                  {anomaly.user_agent}
                </Text>
              </Stack>
            </Grid.Col>
          )}
        </Grid>

        {(anomaly.confidence !== undefined || anomaly.entropy !== undefined || (anomaly.cluster_size ?? 0) > 0) && (
          <>
            <Divider label="Advanced Metrics" labelPosition="center" />
            <Grid grow>
              {anomaly.confidence !== undefined && (
                <Grid.Col span={{ base: 6, sm: 4 }}>
                  <Stack gap={2} align="center">
                    <Text size="xs" c="dimmed" fw={700}>CONFIDENCE</Text>
                    <Badge variant="light" color={anomaly.confidence > 0.8 ? "red" : "orange"} size="lg">
                      {Math.round(anomaly.confidence * 100)}%
                    </Badge>
                  </Stack>
                </Grid.Col>
              )}
              {anomaly.entropy !== undefined && anomaly.entropy > 0 && (
                <Grid.Col span={{ base: 6, sm: 4 }}>
                  <Stack gap={2} align="center">
                    <Text size="xs" c="dimmed" fw={700}>ENTROPY (UA)</Text>
                    <Badge variant="light" color={anomaly.entropy < 1.0 ? "red" : "blue"} size="lg">
                      {anomaly.entropy.toFixed(2)}
                    </Badge>
                  </Stack>
                </Grid.Col>
              )}
              {(anomaly.cluster_size ?? 0) > 0 && (
                <Grid.Col span={{ base: 6, sm: 4 }}>
                  <Stack gap={2} align="center">
                    <Text size="xs" c="dimmed" fw={700}>CLUSTER SIZE</Text>
                    <Badge variant="light" color="violet" size="lg">
                      {anomaly.cluster_size} IPs
                    </Badge>
                  </Stack>
                </Grid.Col>
              )}
            </Grid>
          </>
        )}

        {(anomaly.request_headers || anomaly.request_body) && (
          <>
            <Divider label="Request Details" labelPosition="center" />
            <Stack gap="xs">
              <Group gap="xs">
                <Badge variant="light" color="blue" radius="sm">
                  {anomaly.http_method || "GET"}
                </Badge>
                <Text size="xs" ff="monospace" c="dimmed" style={{ wordBreak: "break-all" }}>
                  {anomaly.request_uri}
                </Text>
              </Group>

              {anomaly.request_headers && (
                <Stack gap={4}>
                  <Group gap={4}>
                    <IconNotes size={14} color="var(--mantine-color-dimmed)" />
                    <Text size="xs" fw={700}>
                      Request Headers
                    </Text>
                  </Group>
                  <Code block style={{ fontSize: "10px", maxHeight: "150px", overflow: "auto" }}>
                    {anomaly.request_headers}
                  </Code>
                </Stack>
              )}

              {anomaly.request_body && (
                <Stack gap={4}>
                  <Group gap={4}>
                    <IconDatabase size={14} color="var(--mantine-color-dimmed)" />
                    <Text size="xs" fw={700}>
                      Request Payload
                    </Text>
                  </Group>
                  <Code block style={{ fontSize: "10px", maxHeight: "150px", overflow: "auto" }}>
                    {anomaly.request_body}
                  </Code>
                </Stack>
              )}
            </Stack>
          </>
        )}

        {(anomaly.response_headers || anomaly.response_body) && (
          <>
            <Divider label="Response Details" labelPosition="center" />
            <Stack gap="xs">
              {anomaly.response_headers && (
                <Stack gap={4}>
                  <Group gap={4}>
                    <IconNotes size={14} color="var(--mantine-color-dimmed)" />
                    <Text size="xs" fw={700}>
                      Response Headers
                    </Text>
                  </Group>
                  <Code block style={{ fontSize: "10px", maxHeight: "150px", overflow: "auto" }}>
                    {anomaly.response_headers}
                  </Code>
                </Stack>
              )}

              {anomaly.response_body && (
                <Stack gap={4}>
                  <Group gap={4}>
                    <IconDatabase size={14} color="var(--mantine-color-dimmed)" />
                    <Text size="xs" fw={700}>
                      Response Body
                    </Text>
                  </Group>
                  <Code block style={{ fontSize: "10px", maxHeight: "150px", overflow: "auto" }}>
                    {anomaly.response_body}
                  </Code>
                </Stack>
              )}
            </Stack>
          </>
        )}

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

      <Modal
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
      </Modal>
    </Modal>
  );
}
