import React, { useState } from "react";
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
  Tooltip,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconShieldExclamation, IconArrowRight, IconLock, IconMap2 } from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import { useSecurityThreats } from "../hooks/useGateon";
import { SecurityAnomalyModal } from "./SecurityAnomalyModal";
import type { Anomaly } from "../types/gateon";
import TraceVisualizer from "./Diagnostics/TraceVisualizer";

export function SecurityThreatsCard() {
  const { data, isLoading } = useSecurityThreats(5);
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const [traceIp, setTraceIp] = useState<string>("");
  const [traceOpened, { open: openTrace, close: closeTrace }] = useDisclosure(false);

  const handleAnomalyClick = (anomaly: Anomaly) => {
    setSelectedAnomaly(anomaly);
    open();
  };

  const handleTraceClick = (e: React.MouseEvent, ip: string) => {
    e.stopPropagation();
    setTraceIp(ip);
    openTrace();
  };

  const threats = data?.threats || [];
  const criticalThreats = threats.filter(t => t.severity === "critical" || t.severity === "high").length;
  const mitigatedCount = threats.filter(t => t.mitigated).length;

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
        <Group gap={5}>
          {mitigatedCount > 0 && (
            <Badge color="teal" variant="light" size="sm">
              {mitigatedCount} mitigated
            </Badge>
          )}
          <Badge color={criticalThreats > 0 ? "red" : threats.length > 0 ? "orange" : "teal"} size="sm">
            {threats.length} events
          </Badge>
        </Group>
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
            <Paper 
              key={index} 
              withBorder 
              p="xs" 
              radius="sm" 
              bg="var(--mantine-color-default-hover)" 
              style={{ transition: 'all 0.1s ease', cursor: 'pointer' }} 
              className="hover:border-brand-5"
              onClick={() => handleAnomalyClick(threat)}
            >
              <Group justify="space-between" wrap="nowrap">
                <Group gap="sm" wrap="nowrap">
                  <ThemeIcon color={threat.severity === "critical" ? "red" : "orange"} variant="light" size="sm">
                    <IconLock size={12} />
                  </ThemeIcon>
                  <Box style={{ overflow: "hidden", flex: 1 }}>
                    <Group gap="xs" wrap="nowrap">
                      <Text size="xs" fw={700} truncate style={{ textTransform: 'uppercase', letterSpacing: 0.5 }}>
                        {threat.type?.replace(/_/g, ' ') || 'UNKNOWN THREAT'}
                      </Text>
                      {threat.mitigated && (
                        <Badge color="teal" variant="light" size="xs">Mitigated</Badge>
                      )}
                    </Group>
                    <Group gap={4} wrap="nowrap">
                      <Text 
                        size="xs" 
                        c="brand" 
                        fw={600} 
                        truncate 
                        style={{ cursor: 'pointer', textDecoration: 'underline', textDecorationStyle: 'dashed' }}
                        onClick={(e) => handleTraceClick(e, threat.source)}
                      >
                        {threat.source}
                      </Text>
                      <Tooltip label="Visual Trace">
                        <IconMap2 
                          size={10} 
                          style={{ cursor: 'pointer', opacity: 0.6 }}
                          onClick={(e) => handleTraceClick(e, threat.source)}
                        />
                      </Tooltip>
                      {threat.route_id && (
                        <>
                          <Text size="xs" c="dimmed">•</Text>
                          <Text size="xs" c="brand" fw={600} truncate>{threat.route_id}</Text>
                        </>
                      )}
                    </Group>
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
        to="/security-center"
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

      <SecurityAnomalyModal 
        anomaly={selectedAnomaly}
        opened={opened}
        onClose={close}
      />

      <TraceVisualizer 
        opened={traceOpened}
        onClose={closeTrace}
        targetIp={traceIp}
      />
    </Card>
  );
}
