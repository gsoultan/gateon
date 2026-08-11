// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
  Divider,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useIsMobile } from "../hooks/useMobile";
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
import { useTableDensity } from "../hooks/useTableDensity";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { EntryPointForm } from "../components/EntryPointForm";
import type { EntryPoint } from "../types/gateon";

export default function EntryPointsPage() {
  const { canWrite } = usePermissions();
  const isMobile = useIsMobile();
  const density = useTableDensity();
  const [opened, { open, close }] = useDisclosure(false);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const { data, isLoading } = useEntryPoints({
    page: page - 1,
    pageSize: pageSize,
    search: search,
  });
  const queryClient = useQueryClient();

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiFetch(
        `/v1/entryPoints/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      );
      if (!res.ok) throw new Error(await res.text());
      return true;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["entryPoints"] });
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

  const entryPoints = data?.entryPoints || [];
  const totalCount = data?.totalCount || 0;

  const stats = useMemo(() => {
    return {
      total: totalCount,
      http: entryPoints.filter((ep) => [0, 1, 4, 5].includes(ep.type)).length,
      tls: entryPoints.filter((ep) => ep.tls?.enabled).length,
    };
  }, [entryPoints, totalCount]);

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="center" wrap="wrap" gap="md">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            EntryPoints
          </Title>
          <Text c="dimmed" size="sm" fw={500}>
            Configure network entryPoints and listening addresses.
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
            fullWidth={isMobile}
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
            placeholder="Search entryPoints..."
            leftSection={<IconSearch size={16} />}
            value={search}
            onChange={(e) => {
              setSearch(e.currentTarget.value);
              setPage(1);
            }}
            size="xs"
            w={isMobile ? "100%" : 300}
          />

          <Box style={{ overflowX: isMobile ? undefined : "auto" }}>
            {isMobile ? (
              <Stack gap="md">
                {entryPoints.length === 0 && !isLoading && (
                  <Center py={40}>
                    <Text c="dimmed">No entryPoints found.</Text>
                  </Center>
                )}
                {entryPoints.map((ep) => (
                  <Card key={ep.id} withBorder radius="md" p="md">
                    <Stack gap="xs">
                      <Group justify="space-between" align="flex-start">
                        <Group gap="sm" wrap="nowrap">
                          <ActionIcon variant="light" color="indigo" radius="md">
                            <IconAccessPoint size={16} />
                          </ActionIcon>
                          <Stack gap={0}>
                            <Text fw={700} size="sm" truncate>
                              {ep.name || ep.id}
                            </Text>
                            <Text size="xs" c="dimmed" ff="monospace" truncate>
                              {ep.id}
                            </Text>
                          </Stack>
                        </Group>
                        {canWrite && (
                          <Menu shadow="md" position="bottom-end">
                            <Menu.Target>
                              <ActionIcon variant="subtle" color="gray">
                                <IconDotsVertical size={16} />
                              </ActionIcon>
                            </Menu.Target>
                            <Menu.Dropdown>
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
                        )}
                      </Group>
                      <Divider variant="dashed" />
                      <SimpleGrid cols={2} spacing="xs">
                        <Box>
                          <Text size="xs" c="dimmed" fw={700} style={{ textTransform: "uppercase" }}>Address</Text>
                          <Text size="xs" ff="monospace" fw={700}>{ep.address}</Text>
                        </Box>
                        <Box>
                          <Text size="xs" c="dimmed" fw={700} style={{ textTransform: "uppercase" }}>Protocol</Text>
                          <Badge size="xs" color={ep.protocol === 1 ? "orange" : "blue"}>{ep.protocol === 1 ? "UDP" : "TCP"}</Badge>
                        </Box>
                        <Box>
                          <Text size="xs" c="dimmed" fw={700} style={{ textTransform: "uppercase" }}>Security</Text>
                          {ep.tls?.enabled ? (
                            <Badge variant="filled" color="teal" size="xs" leftSection={<IconLock size={10} />}>TLS</Badge>
                          ) : (
                            <Badge variant="outline" color="gray" size="xs" leftSection={<IconLockOff size={10} />}>Plain</Badge>
                          )}
                        </Box>
                        <Box>
                          <Text size="xs" c="dimmed" fw={700} style={{ textTransform: "uppercase" }}>Logs</Text>
                          <Badge size="xs" color={ep.accessLogEnabled ? "blue" : "gray"}>{ep.accessLogEnabled ? "Active" : "Disabled"}</Badge>
                        </Box>
                      </SimpleGrid>
                    </Stack>
                  </Card>
                ))}
              </Stack>
            ) : (
              <Table {...density} highlightOnHover>
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
                          <Text c="dimmed">No entryPoints found.</Text>
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
                          variant={ep.accessLogEnabled ? "light" : "outline"}
                          color={ep.accessLogEnabled ? "blue" : "gray"}
                          size="sm"
                        >
                          {ep.accessLogEnabled ? "Active" : "Disabled"}
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
            )}
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
