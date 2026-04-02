import {
  Title,
  Text,
  Stack,
  Group,
  LoadingOverlay,
} from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../hooks/useGateon";
import { type Route, type Service, type EntryPoint, type Middleware } from "../types/gateon";
import { TopologyGraph } from "../components/TopologyGraph";

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

  const { data: middlewares, isLoading: loadingMws } = useQuery<Middleware[]>({
    queryKey: ["middlewares", "all"],
    queryFn: async () => {
      const res = await apiFetch("/v1/middlewares?page_size=1000");
      const data = await res.json();
      return data.middlewares || [];
    },
  });

  const isLoading = loadingRoutes || loadingServices || loadingEps || loadingMws;

  return (
    <Stack gap="xl" pos="relative" h="100%">
      <LoadingOverlay visible={isLoading} />
      <Group justify="space-between">
        <div>
          <Title order={2}>Traffic Topology</Title>
          <Text size="sm" c="dimmed">
            Animated visual flow of traffic from entrypoints to backend services through middlewares.
          </Text>
        </div>
      </Group>

      {entrypoints && routes && services && middlewares && (
        <TopologyGraph
          entrypoints={entrypoints}
          routes={routes}
          services={services}
          middlewares={middlewares}
        />
      )}
    </Stack>
  );
}
