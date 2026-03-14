import { useMemo, useState } from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  Group,
  Button,
  Drawer,
  Table,
  ActionIcon,
  Badge,
  TextInput,
  Center,
  Box,
  Menu,
  Tooltip,
  Paper,
  SimpleGrid,
  Code,
  Pagination,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconPlus,
  IconAccessPoint,
  IconSearch,
  IconDotsVertical,
  IconEdit,
  IconTrash,
  IconActivity,
  IconShieldLock,
  IconWorld,
  IconLock,
  IconLockOff,
} from "@tabler/icons-react";
import { useEntryPoints, apiFetch, getApiErrorMessage } from "../hooks/useGateon";
import { usePermissions } from "../hooks/usePermissions";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { EntryPointForm } from "../components/EntryPointForm";
import type { EntryPoint } from "../types/gateon";

export default function EntryPointsPage() {
  const { canWrite } = usePermissions();
  const [opened, { open, close }] = useDisclosure(false);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const { data, isLoading } = useEntryPoints({
    page: page - 1,
    page_size: pageSize,
    search: search,
  });
  const queryClient = useQueryClient();

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiFetch(
        `/v1/entrypoints/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      );
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["entrypoints"] });
      notifications.show({
        title: "EntryPoint Deleted",
        message: "The entrypoint has been successfully removed.",
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

  const [editingEP, setEditingEP] = useState<EntryPoint | null>(null);

  const handleEdit = (ep: EntryPoint) => {
    setEditingEP(ep);
    open();
  };

  const handleCreate = () => {
    setEditingEP(null);
    open();
  };

  const entryPoints = data?.entry_points || [];
  const totalCount = data?.total_count || 0;

  const stats = useMemo(() => {
    return {
      total: totalCount,
      http: entryPoints.filter((ep) => [0, 1, 4, 5].includes(ep.type)).length,
      tls: entryPoints.filter((ep) => ep.tls?.enabled).length,
    };
  }, [entryPoints, totalCount]);

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="center">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            EntryPoints
          </Title>
          <Text c="dimmed" size="sm" fw={500}>
            Configure network entrypoints and listening addresses.
          </Text>
        </div>
        {canWrite && (
          <Button
            leftSection={<IconPlus size={18} />}
            onClick={handleCreate}
            size="md"
            radius="md"
            variant="gradient"
            gradient={{ from: "blue", to: "cyan" }}
          >
            Create EntryPoint
          </Button>
        )}
      </Group>

      <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
        <Paper p="md" radius="lg" withBorder shadow="xs">
          <Group>
            <ActionIcon variant="light" color="blue" size="xl" radius="md">
              <IconAccessPoint size={24} />
            </ActionIcon>
            <div>
              <Text
                size="xs"
                c="dimmed"
                fw={800}
                style={{ textTransform: "uppercase", letterSpacing: 1 }}
              >
                Total
              </Text>
              <Text fw={800} size="xl">
                {stats.total}
              </Text>
            </div>
          </Group>
        </Paper>
        <Paper p="md" radius="lg" withBorder shadow="xs">
          <Group>
            <ActionIcon variant="light" color="teal" size="xl" radius="md">
              <IconWorld size={24} />
            </ActionIcon>
            <div>
              <Text
                size="xs"
                c="dimmed"
                fw={800}
                style={{ textTransform: "uppercase", letterSpacing: 1 }}
              >
                Web Services
              </Text>
              <Text fw={800} size="xl">
                {stats.http}
              </Text>
            </div>
          </Group>
        </Paper>
        <Paper p="md" radius="lg" withBorder shadow="xs">
          <Group>
            <ActionIcon variant="light" color="indigo" size="xl" radius="md">
              <IconShieldLock size={24} />
            </ActionIcon>
            <div>
              <Text
                size="xs"
                c="dimmed"
                fw={800}
                style={{ textTransform: "uppercase", letterSpacing: 1 }}
              >
                TLS Enabled
              </Text>
              <Text fw={800} size="xl">
                {stats.tls}
              </Text>
            </div>
          </Group>
        </Paper>
      </SimpleGrid>

      <Card shadow="xs" padding="lg" radius="lg" withBorder>
        <Stack gap="md">
          <TextInput
            placeholder="Search entrypoints..."
            leftSection={<IconSearch size={16} />}
            value={search}
            onChange={(e) => {
              setSearch(e.currentTarget.value);
              setPage(1);
            }}
            size="xs"
            w={300}
          />

          <Box style={{ overflowX: "auto" }}>
            <Table verticalSpacing="md" highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>ID / Name</Table.Th>
                  <Table.Th>Address</Table.Th>
                  <Table.Th>Protocol</Table.Th>
                  <Table.Th>TLS</Table.Th>
                  <Table.Th>Access Log</Table.Th>
                  <Table.Th w={80}>Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {entryPoints.length === 0 && !isLoading && (
                  <Table.Tr>
                    <Table.Td colSpan={6}>
                      <Center py={40}>
                        <Text c="dimmed">No entrypoints found.</Text>
                      </Center>
                    </Table.Td>
                  </Table.Tr>
                )}
                {entryPoints.map((ep) => (
                  <Table.Tr key={ep.id}>
                    <Table.Td>
                      <Group gap="sm">
                        <ActionIcon variant="light" color="indigo" radius="md">
                          <IconAccessPoint size={16} />
                        </ActionIcon>
                        <Stack gap={0}>
                          <Text fw={700} size="sm">
                            {ep.name || ep.id}
                          </Text>
                          <Text size="xs" c="dimmed" ff="monospace">
                            {ep.id}
                          </Text>
                        </Stack>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Code color="blue" variant="light" fw={700}>
                        {ep.address}
                      </Code>
                    </Table.Td>
                    <Table.Td>
                      <Badge
                        variant="dot"
                        color={ep.protocol === 1 ? "orange" : "blue"}
                        radius="sm"
                      >
                        {ep.protocol === 1 ? "UDP" : "TCP"}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      {ep.tls?.enabled ? (
                        <Badge
                          variant="filled"
                          color="teal"
                          size="sm"
                          leftSection={<IconLock size={10} />}
                        >
                          TLS
                        </Badge>
                      ) : (
                        <Badge
                          variant="outline"
                          color="gray"
                          size="sm"
                          leftSection={<IconLockOff size={10} />}
                        >
                          Plain
                        </Badge>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Badge
                        variant={ep.access_log_enabled ? "light" : "outline"}
                        color={ep.access_log_enabled ? "blue" : "gray"}
                        size="sm"
                      >
                        {ep.access_log_enabled ? "Active" : "Disabled"}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      {canWrite && (
                        <Group gap="xs">
                          <Menu
                            shadow="md"
                            position="bottom-end"
                            transitionProps={{ transition: "pop-top-right" }}
                          >
                            <Menu.Target>
                              <ActionIcon variant="subtle" color="gray">
                                <IconDotsVertical size={16} />
                              </ActionIcon>
                            </Menu.Target>
                            <Menu.Dropdown>
                              <Menu.Label>EntryPoint Actions</Menu.Label>
                              <Menu.Item
                                leftSection={<IconEdit size={14} />}
                                onClick={() => handleEdit(ep)}
                              >
                                Edit
                              </Menu.Item>
                              <Menu.Divider />
                              <Menu.Item
                                leftSection={<IconTrash size={14} />}
                                color="red"
                                onClick={() => deleteMutation.mutate(ep.id)}
                              >
                                Delete
                              </Menu.Item>
                            </Menu.Dropdown>
                          </Menu>
                        </Group>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Box>

          {totalCount > pageSize && (
            <Group justify="center" mt="md">
              <Pagination
                total={Math.ceil(totalCount / pageSize)}
                value={page}
                onChange={setPage}
                size="sm"
              />
            </Group>
          )}
        </Stack>
      </Card>

      <Drawer
        opened={opened}
        onClose={close}
        title={
          <Text fw={800} size="xl" style={{ letterSpacing: -0.5 }}>
            {editingEP ? "Edit EntryPoint" : "Create New EntryPoint"}
          </Text>
        }
        position="right"
        size="40%"
        padding="xl"
        styles={{
          header: {
            borderBottom: "1px solid var(--mantine-color-default-border)",
            marginBottom: "xl",
          },
          content: { boxShadow: "var(--mantine-shadow-xl)" },
        }}
      >
        <EntryPointForm onSuccess={close} initialData={editingEP} />
      </Drawer>
    </Stack>
  );
}
