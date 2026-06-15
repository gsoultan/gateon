import { Suspense, lazy, useState } from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  Group,
  Button,
  Drawer,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconPlus } from "@tabler/icons-react";
import { apiFetch, getApiErrorMessage } from "../hooks/useGateon";
import { usePermissions } from "../hooks/usePermissions";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import type { ListRoutesResponse, Route } from "../types/gateon";

const RouteForm = lazy(() => import("../components/RouteForm"));
const RouteList = lazy(() => import("../components/RouteList"));

const ROUTE_LIST_FALLBACK = (
  <Card withBorder h={300}>
    <Text>Loading routes...</Text>
  </Card>
);
const FORM_FALLBACK = <Text>Loading form...</Text>;

export default function RoutesPage() {
  const { canWrite } = usePermissions();
  const [opened, { open, close }] = useDisclosure(false);
  const [editingRoute, setEditingRoute] = useState<Route | null>(null);
  const queryClient = useQueryClient();

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiFetch(`/v1/routes/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error(await res.text());
      return true;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["routes"] });
      notifications.show({
        title: "Route Deleted",
        message: "The route has been successfully removed.",
        color: "green",
      });
    },
    onError: (err: unknown) => {
      notifications.show({
        title: "Error",
        message: getApiErrorMessage(err),
        color: "red",
      });
    },
  });

  const handleEdit = (route: Route) => {
    setEditingRoute(route);
    open();
  };

  const handleCreate = () => {
    setEditingRoute(null);
    open();
  };

  const pauseMutation = useMutation({
    mutationFn: async (route: Route) => {
      const res = await apiFetch("/v1/routes", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...route, disabled: !route.disabled }),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    // Optimistically flip `disabled` across every cached routes query so the
    // pause/resume toggle feels instant, snapshotting the prior state so we can
    // roll back if the server rejects the change.
    onMutate: async (route: Route) => {
      await queryClient.cancelQueries({ queryKey: ["routes"] });
      const snapshots = queryClient.getQueriesData<ListRoutesResponse>({
        queryKey: ["routes"],
      });
      queryClient.setQueriesData<ListRoutesResponse>(
        { queryKey: ["routes"] },
        (current) =>
          current
            ? {
                ...current,
                routes: current.routes.map((r) =>
                  r.id === route.id ? { ...r, disabled: !route.disabled } : r,
                ),
              }
            : current,
      );
      return { snapshots };
    },
    onSuccess: (_data, route) => {
      notifications.show({
        title: route.disabled ? "Route Resumed" : "Route Paused",
        message: `"${route.name || route.id}" is now ${route.disabled ? "active" : "paused"}.`,
        color: "blue",
      });
    },
    onError: (err: unknown, _route, context) => {
      // Restore the pre-mutation cache for every affected query.
      context?.snapshots.forEach(([key, data]) => {
        queryClient.setQueryData(key, data);
      });
      notifications.show({
        title: "Error",
        message: getApiErrorMessage(err),
        color: "red",
      });
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["routes"] });
    },
  });

  const handleClone = (route: Route) => {
    setEditingRoute({
      ...route,
      id: "",
      name: `${route.name || route.id} (copy)`,
    });
    open();
  };

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="center">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            Routes
          </Title>
          <Text c="dimmed" size="sm" fw={500}>
            Manage your API gateway routes and their policies.
          </Text>
        </div>
        {canWrite && (
          <Button
            leftSection={<IconPlus size={18} />}
            onClick={handleCreate}
            size="md"
            radius="md"
          >
            Create Route
          </Button>
        )}
      </Group>

      <Suspense fallback={ROUTE_LIST_FALLBACK}>
        <RouteList
          onEdit={handleEdit}
          onClone={handleClone}
          onPause={(route) => pauseMutation.mutate(route)}
          onDelete={(id) => deleteMutation.mutate(id)}
          readOnly={!canWrite}
        />
      </Suspense>

      <Drawer
        opened={opened}
        onClose={close}
        title={
          <Text fw={800} size="xl" style={{ letterSpacing: -0.5 }}>
            {editingRoute?.id ? "Edit Route" : editingRoute ? "Clone Route" : "Create New Route"}
          </Text>
        }
        position="right"
        size="70%"
        padding="xl"
        styles={{
          header: {
            borderBottom: "1px solid var(--mantine-color-dark-4)",
            marginBottom: "xl",
          },
          content: { boxShadow: "var(--mantine-shadow-xl)" },
        }}
      >
        <Suspense fallback={FORM_FALLBACK}>
          <RouteForm onSuccess={close} initialData={editingRoute} />
        </Suspense>
      </Drawer>
    </Stack>
  );
}
