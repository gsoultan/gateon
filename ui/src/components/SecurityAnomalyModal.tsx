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
  List,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useMemo } from "react";
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
  IconBrain,
  IconInfoCircle,
  IconShieldCheck,
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

  const triggeredRules = useMemo(() => {
    if (!anomaly?.triggered_rules) return [];
    try {
      return JSON.parse(anomaly.triggered_rules) as number[];
    } catch {
      return [];
    }
  }, [anomaly?.triggered_rules]);

  if (!anomaly) return null;

  const parseRecommendation = (rec: string) => {
    if (!rec) return { general: "", insight: null };
    const parts = rec.split("Smart Insight:");
    if (parts.length > 1) {
      return {
        general: parts[0].trim(),
        insight: parts[1].trim(),
      };
    }
    return { general: rec, insight: null };
  };

  const { general, insight } = parseRecommendation(anomaly.recommendation);

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
        {triggeredRules.length > 0 && anomaly.mitigated && (
          <Alert
            variant="light"
            color="blue"
            title="One-Click Resolution Available"
            icon={<IconShieldCheck size={18} />}
            mb="md"
          >
            <Stack gap="xs">
              <Text size="sm">
                Gateon has identified {triggeredRules.length} specific security rule{triggeredRules.length > 1 ? 's' : ''} that might be causing a false positive. Click below to whitelist these rules for this path and restore the client's reputation.
              </Text>
              <Group>
                <Button
                  variant="filled"
                  size="xs"
                  color="blue"
                  leftSection={<IconCheck size={14} />}
                  loading={applyRecommendation.isPending}
                  onClick={handleApplyFalsePositive}
                >
                  Whitelist Rules & Allow IP
                </Button>
              </Group>
            </Stack>
          </Alert>
        )}

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
          <Box mt="sm">
            {anomaly.description.includes("•") || anomaly.description.includes("[") ? (
              <Stack gap={4}>
                {anomaly.description.split("\n").filter(l => l.trim() !== "").map((line, i) => {
                  const isHeader = line.startsWith("[") && line.endsWith("]");
                  const isBullet = line.startsWith("•");
                  return (
                    <Text
                      key={i}
                      size={isHeader ? "xs" : "sm"}
                      ff={isBullet ? "monospace" : undefined}
                      fw={isHeader ? 700 : undefined}
                      tt={isHeader ? "uppercase" : undefined}
                      c={isHeader ? "dimmed" : (isBullet ? undefined : "dimmed")}
                      mt={isHeader && i > 0 ? "xs" : undefined}
                    >
                      {isHeader ? line.replace(/[\[\]]/g, "") : line}
                    </Text>
                  );
                })}
              </Stack>
            ) : (
              <Text size="sm">{anomaly.description}</Text>
            )}
          </Box>

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
            <Divider label="Security Intelligence Metrics" labelPosition="center" />
            <Grid grow>
              {anomaly.confidence !== undefined && (
                <Grid.Col span={{ base: 6, sm: 4 }}>
                  <Tooltip label="Likelihood that this detection is accurate based on statistical patterns.">
                    <Stack gap={2} align="center">
                      <Group gap={4}>
                        <IconInfoCircle size={10} color="dimmed" />
                        <Text size="xs" c="dimmed" fw={700}>CONFIDENCE</Text>
                      </Group>
                      <Badge variant="light" color={anomaly.confidence > 0.8 ? "red" : "orange"} size="lg">
                        {Math.round(anomaly.confidence * 100)}%
                      </Badge>
                    </Stack>
                  </Tooltip>
                </Grid.Col>
              )}
              {anomaly.entropy !== undefined && anomaly.entropy > 0 && (
                <Grid.Col span={{ base: 6, sm: 4 }}>
                  <Tooltip label="Measures randomness in the payload. High entropy often indicates encrypted/encoded tokens, while low entropy is typical for common text.">
                    <Stack gap={2} align="center">
                      <Group gap={4}>
                        <IconInfoCircle size={10} color="dimmed" />
                        <Text size="xs" c="dimmed" fw={700}>ENTROPY</Text>
                      </Group>
                      <Badge variant="light" color={anomaly.entropy < 1.0 ? "red" : anomaly.entropy > 5.0 ? "blue" : "teal"} size="lg">
                        {anomaly.entropy.toFixed(2)}
                      </Badge>
                    </Stack>
                  </Tooltip>
                </Grid.Col>
              )}
              {(anomaly.cluster_size ?? 0) > 0 && (
                <Grid.Col span={{ base: 6, sm: 4 }}>
                  <Tooltip label="Number of unique IPs involved in this specific threat pattern across the network.">
                    <Stack gap={2} align="center">
                      <Group gap={4}>
                        <IconInfoCircle size={10} color="dimmed" />
                        <Text size="xs" c="dimmed" fw={700}>CLUSTER SIZE</Text>
                      </Group>
                      <Badge variant="light" color="violet" size="lg">
                        {anomaly.cluster_size} IPs
                      </Badge>
                    </Stack>
                  </Tooltip>
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

        {insight && (
          <>
            <Divider 
              label={
                <Group gap={4}>
                  <IconBrain size={14} />
                  <Text size="xs" fw={700}>SMART INSIGHTS</Text>
                </Group>
              } 
              labelPosition="center" 
              color="blue"
            />
            <Alert 
              variant="light" 
              color="blue" 
              title="Intelligence Analysis" 
              icon={<IconBrain size={16} />}
              radius="md"
            >
              <Stack gap="xs">
                {insight.includes("•") ? (
                  <List size="sm" spacing="xs" icon={<ThemeIcon color="blue" size={16} radius="xl"><IconCheck size={10} /></ThemeIcon>}>
                    {insight.split("\n").filter(l => l.trim().startsWith("•")).map((line, i) => (
                      <List.Item key={i}>
                        <Text size="sm">{line.replace("•", "").trim()}</Text>
                      </List.Item>
                    ))}
                  </List>
                ) : (
                  <Text size="sm">{insight}</Text>
                )}
                
                {insight.toLowerCase().includes("false positive") && (
                  <Alert color="teal" variant="outline" p="xs" mt="xs">
                    <Group gap="xs">
                      <IconShieldCheck size={16} />
                      <Text size="xs" fw={600}>Smart engine suggests this might be a false positive. Auto-fix is recommended.</Text>
                    </Group>
                  </Alert>
                )}
              </Stack>
            </Alert>
          </>
        )}

        <Stack gap="xs">
          <Group gap="xs">
            <IconAlertCircle size={16} color="var(--mantine-color-blue-6)" />
            <Text size="sm" fw={600}>
              Recommendation
            </Text>
          </Group>
          <Paper withBorder p="sm" radius="md" bg="var(--mantine-color-blue-light)">
            <Text size="sm">{general || "No specific recommendation available."}</Text>
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
