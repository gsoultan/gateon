import {
  Title,
  Text,
  Stack,
  Group,
  Paper,
  Badge,
  ThemeIcon,
  Card,
  ScrollArea,
  LoadingOverlay,
} from "@mantine/core";
import {
  IconArrowRight,
  IconCircles,
  IconRoute,
  IconServer,
  IconNetwork,
} from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../hooks/useGateon";
import { type Route, type Service, type EntryPoint, EntryPointType } from "../types/gateon";

export default function TopologyPage() {
  const { data: routes, isLoading: loadingRoutes } = useQuery<Route[]>({
    queryKey: ["routes", "all"],
    queryFn: async () => {
      const res = await apiFetch("/v1/routes?page_size=1000");
      const data = await res.json();
      return data.routes || [];
    },
  });

  const { data: services, isLoading: loadingServices } = useQuery<Service[]>({
    queryKey: ["services", "all"],
    queryFn: async () => {
      const res = await apiFetch("/v1/services?page_size=1000");
      const data = await res.json();
      return data.services || [];
    },
  });

  const { data: entrypoints, isLoading: loadingEps } = useQuery<EntryPoint[]>({
    queryKey: ["entrypoints", "all"],
    queryFn: async () => {
      const res = await apiFetch("/v1/entrypoints?page_size=1000");
      const data = await res.json();
      return data.entry_points || [];
    },
  });

  const isLoading = loadingRoutes || loadingServices || loadingEps;

  return (
    <Stack gap="xl" pos="relative">
      <LoadingOverlay visible={isLoading} />
      <Group justify="space-between">
        <div>
          <Title order={2}>Traffic Topology</Title>
          <Text size="sm" c="dimmed">
            Visual flow of traffic from entrypoints to backend services.
          </Text>
        </div>
      </Group>

      <ScrollArea h="calc(100vh - 200px)">
        <Stack gap={40} p="md">
          {entrypoints?.map((ep) => (
            <Card key={ep.id} withBorder shadow="xs" radius="md">
              <Stack gap="md">
                <Group gap="xs">
                  <ThemeIcon color="blue" variant="light" size="lg">
                    <IconNetwork size={20} />
                  </ThemeIcon>
                  <div>
                    <Text fw={700}>{ep.name || ep.id}</Text>
                    <Text size="xs" c="dimmed">{ep.address}</Text>
                  </div>
                  <Badge variant="outline" size="sm">{EntryPointType[ep.type] || ep.type}</Badge>
                </Group>

                <Stack gap="sm" pl={40}>
                  {routes
                    ?.filter((r) => {
                      const epIdMatch = r.entrypoints?.includes(ep.id);
                      const allEntries = !r.entrypoints || r.entrypoints.length === 0;

                      if (ep.type === EntryPointType.TCP || ep.type === EntryPointType.UDP) {
                        const typeMatch =
                          (ep.type === EntryPointType.TCP && r.type === "tcp") ||
                          (ep.type === EntryPointType.UDP && r.type === "udp");
                        return epIdMatch && typeMatch;
                      }

                      const isWebCompatible = ["http", "grpc", "graphql"].includes(r.type);
                      return (epIdMatch || allEntries) && isWebCompatible;
                    })
                    .map((r) => (
                      <Group key={r.id} align="flex-start" wrap="nowrap">
                        <IconArrowRight size={16} color="gray" style={{ marginTop: 8 }} />
                        <Paper withBorder p="xs" radius="md" flex={1}>
                          <Stack gap={4}>
                            <Group justify="space-between">
                              <Group gap="xs">
                                <IconRoute size={14} color="var(--mantine-color-orange-filled)" />
                                <Text size="sm" fw={600}>{r.name || r.id}</Text>
                              </Group>
                              <Badge size="xs" color="orange">{r.type}</Badge>
                            </Group>
                            <Text size="xs" c="dimmed" fs="italic">{r.rule}</Text>

                            <Group mt="xs" align="center" gap="xs">
                              <IconArrowRight size={12} color="gray" />
                              {(() => {
                                const svc = services?.find((s) => s.id === r.service_id);
                                return svc ? (
                                  <Paper bg="gray.0" px="xs" py={4} radius="xs" withBorder flex={1}>
                                    <Group justify="space-between">
                                      <Group gap="xs">
                                        <IconServer size={12} color="var(--mantine-color-blue-filled)" />
                                        <Text size="xs" fw={600}>{svc.name}</Text>
                                      </Group>
                                      <Text size="xs" c="dimmed">
                                        {svc.weighted_targets?.length || 0} targets
                                      </Text>
                                    </Group>
                                  </Paper>
                                ) : (
                                  <Text size="xs" c="red">Service not found: {r.service_id}</Text>
                                );
                              })()}
                            </Group>
                          </Stack>
                        </Paper>
                      </Group>
                    ))}
                </Stack>
              </Stack>
            </Card>
          ))}
        </Stack>
      </ScrollArea>
    </Stack>
  );
}
