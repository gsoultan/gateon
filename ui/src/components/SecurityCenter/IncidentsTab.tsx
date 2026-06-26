import {
  Card,
  Group,
  Stack,
  Text,
  Badge,
  Table,
  Loader,
  Alert,
  Center,
  SimpleGrid,
  Tooltip,
  ThemeIcon,
  Code,
} from "@mantine/core";
import {
  IconAlertTriangle,
  IconShieldCheck,
  IconBroadcast,
  IconNetwork,
  IconRadar2,
} from "@tabler/icons-react";
import { useSecurityIncidents } from "../../hooks/useSecurityIncidents";
import { useSecurityPosture } from "../../hooks/useSecurityPosture";
import { useTableDensity } from "../../hooks/useTableDensity";
import { getSeverityColor } from "../../utils/security";
import { format } from "date-fns";

function PostureStatusCards() {
  const { data: posture } = useSecurityPosture();
  if (!posture) return null;

  const waf = posture.waf;
  const siem = posture.siem;
  const sig = posture.signatures;

  return (
    <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
      <Card withBorder radius="md" padding="md">
        <Group justify="space-between" wrap="nowrap">
          <Stack gap={2}>
            <Text size="xs" c="dimmed" fw={700} tt="uppercase">
              WAF
            </Text>
            <Badge color={waf.enabled ? "teal" : "gray"} variant="light">
              {waf.enabled ? "Protecting all routes" : "Disabled"}
            </Badge>
          </Stack>
          <ThemeIcon color={waf.enabled ? "teal" : "gray"} variant="light" size="lg" radius="md">
            <IconShieldCheck size={20} />
          </ThemeIcon>
        </Group>
      </Card>

      <Card withBorder radius="md" padding="md">
        <Group justify="space-between" wrap="nowrap">
          <Stack gap={2}>
            <Text size="xs" c="dimmed" fw={700} tt="uppercase">
              Signature engine
            </Text>
            <Badge color={sig.enabled ? "blue" : "gray"} variant="light">
              {sig.enabled ? `${sig.rule_count} rules active` : "Disabled"}
            </Badge>
          </Stack>
          <ThemeIcon color={sig.enabled ? "blue" : "gray"} variant="light" size="lg" radius="md">
            <IconRadar2 size={20} />
          </ThemeIcon>
        </Group>
      </Card>

      <Card withBorder radius="md" padding="md">
        <Group justify="space-between" wrap="nowrap">
          <Stack gap={2}>
            <Text size="xs" c="dimmed" fw={700} tt="uppercase">
              SIEM export
            </Text>
            {siem.enabled ? (
              <Tooltip label={`${siem.transport?.toUpperCase()} · ${siem.format?.toUpperCase()} · ${siem.endpoint}`}>
                <Badge color="grape" variant="light">
                  Shipping · {siem.stats.shipped} sent
                </Badge>
              </Tooltip>
            ) : (
              <Badge color="gray" variant="light">
                Not configured
              </Badge>
            )}
          </Stack>
          <ThemeIcon color={siem.enabled ? "grape" : "gray"} variant="light" size="lg" radius="md">
            <IconBroadcast size={20} />
          </ThemeIcon>
        </Group>
        {siem.enabled && siem.stats.dropped > 0 && (
          <Text size="xs" c="orange" mt={4}>
            {siem.stats.dropped} dropped (queue full)
          </Text>
        )}
      </Card>

      <Card withBorder radius="md" padding="md">
        <Group justify="space-between" wrap="nowrap">
          <Stack gap={2}>
            <Text size="xs" c="dimmed" fw={700} tt="uppercase">
              ClamAV
            </Text>
            <Badge color={posture.clamav.installed ? "teal" : "gray"} variant="light">
              {posture.clamav.installed ? "Installed" : posture.clamav.enabled ? "Enabled" : "Off"}
            </Badge>
          </Stack>
          <ThemeIcon color={posture.clamav.installed ? "teal" : "gray"} variant="light" size="lg" radius="md">
            <IconNetwork size={20} />
          </ThemeIcon>
        </Group>
      </Card>
    </SimpleGrid>
  );
}

export function IncidentsTab() {
  const { data, isLoading, error } = useSecurityIncidents(100);
  const density = useTableDensity();
  const incidents = data?.incidents ?? [];

  return (
    <Stack gap="lg">
      <PostureStatusCards />

      <Card withBorder radius="md">
        <Group justify="space-between" mb="md">
          <Stack gap={2}>
            <Text fw={700}>Correlated Incidents</Text>
            <Text size="xs" c="dimmed">
              Higher-level findings raised when multiple related detections from one
              source cross a threshold, annotated with MITRE ATT&amp;CK techniques.
            </Text>
          </Stack>
          {data && (
            <Badge variant="light" color="blue">
              {data.total_seen} total · {data.retained} retained
            </Badge>
          )}
        </Group>

        {isLoading && (
          <Center py="xl">
            <Loader />
          </Center>
        )}

        {error && (
          <Alert color="red" icon={<IconAlertTriangle size={16} />}>
            Failed to load incidents.
          </Alert>
        )}

        {!isLoading && !error && incidents.length === 0 && (
          <Center py="xl">
            <Stack align="center" gap="xs">
              <ThemeIcon color="teal" variant="light" size="xl" radius="md">
                <IconShieldCheck size={28} />
              </ThemeIcon>
              <Text fw={500}>No correlated incidents</Text>
              <Text size="sm" c="dimmed" ta="center" maw={420}>
                Incidents appear when several related threats from the same source are
                detected within the correlation window. A quiet list is a good sign.
              </Text>
            </Stack>
          </Center>
        )}

        {!isLoading && !error && incidents.length > 0 && (
          <Table.ScrollContainer minWidth={760}>
            <Table
              striped
              highlightOnHover
              verticalSpacing={density.verticalSpacing}
              horizontalSpacing={density.horizontalSpacing}
              fontSize={density.fontSize}
            >
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Severity</Table.Th>
                  <Table.Th>Source</Table.Th>
                  <Table.Th>Signals</Table.Th>
                  <Table.Th>MITRE ATT&amp;CK</Table.Th>
                  <Table.Th>Score</Table.Th>
                  <Table.Th>Last seen</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {incidents.map((inc) => (
                  <Table.Tr key={inc.id}>
                    <Table.Td>
                      <Badge color={getSeverityColor(inc.severity)} variant="filled">
                        {inc.severity || "unknown"}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Stack gap={2}>
                        <Code>{inc.source_ip || inc.source_key}</Code>
                        {inc.countries && inc.countries.length > 0 && (
                          <Text size="xs" c="dimmed">
                            {inc.countries.join(", ")}
                          </Text>
                        )}
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        <Badge size="sm" variant="light" color="orange">
                          {inc.signal_count} signals
                        </Badge>
                        {inc.signal_types.map((t) => (
                          <Badge key={t} size="xs" variant="outline" color="gray">
                            {t.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {inc.techniques.length === 0 && (
                          <Text size="xs" c="dimmed">
                            —
                          </Text>
                        )}
                        {inc.techniques.map((tech) => (
                          <Tooltip key={tech.id} label={`${tech.name} (${tech.tactic})`}>
                            <Badge size="sm" variant="light" color="red">
                              {tech.id}
                            </Badge>
                          </Tooltip>
                        ))}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text fw={600}>{inc.score.toFixed(1)}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" c="dimmed">
                        {inc.last_seen ? format(new Date(inc.last_seen), "MMM d, HH:mm:ss") : "—"}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>
    </Stack>
  );
}
