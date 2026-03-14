import { useState } from "react";
import {
  Card,
  Title,
  Stack,
  Group,
  Badge,
  Text,
  TextInput,
  Select,
  Table,
  ActionIcon,
  Menu,
  Pagination,
  Box,
  Skeleton,
  SimpleGrid,
  Center,
  Code,
  Tooltip,
} from "@mantine/core";
import { useRoutes } from "../hooks/useGateon";
import { RouteStats } from "./RouteStats";
import { RouteSparklineCell } from "./RouteSparklineCell";
import {
  IconSearch,
  IconDotsVertical,
  IconEdit,
  IconCopy,
  IconTrash,
  IconPlayerPause,
  IconRouteOff,
  IconLock,
  IconSettingsAutomation,
  IconWorld,
} from "@tabler/icons-react";
import type { Route } from "../types/gateon";

export default function RouteList({
  limit,
  onEdit,
  onClone,
  onDelete,
  onPause,
  readOnly,
}: {
  limit?: number;
  onEdit?: (route: Route) => void;
  onClone?: (route: Route) => void;
  onPause?: (route: Route) => void;
  onDelete?: (id: string) => void;
  readOnly?: boolean;
}) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [typeFilter, setTypeFilter] = useState<string | null>("all");
  const [hostFilter, setHostFilter] = useState("");
  const [pathFilter, setPathFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "paused">("all");
  const pageSize = 10;

  const { data, isLoading } = useRoutes({
    page: page - 1,
    page_size: limit || pageSize,
    search: search || undefined,
    type: typeFilter && typeFilter !== "all" ? typeFilter : undefined,
    host: hostFilter.trim() || undefined,
    path: pathFilter.trim() || undefined,
    status: statusFilter !== "all" ? statusFilter : undefined,
  });

  const routes = data?.routes || [];
  const totalCount = data?.total_count ?? 0;

  if (isLoading)
    return (
      <Card shadow="sm" padding="lg" radius="md" withBorder>
        <Stack gap="md">
          <Group justify="space-between">
            <Skeleton h={30} w={150} />
            {!limit && <Skeleton h={30} w={300} />}
          </Group>
          <Skeleton h={200} />
        </Stack>
      </Card>
    );

  return (
    <Card shadow="xs" padding="lg" radius="lg" withBorder>
      <Stack gap="md">
        <Group justify="space-between" wrap="wrap" gap="md">
          <Group gap="xs">
            <Title order={4} fw={700}>
              Active Routes
            </Title>
            <Badge variant="light" color="indigo" size="sm" radius="md">
              {totalCount} route{totalCount !== 1 ? "s" : ""}
            </Badge>
          </Group>
          {!limit && (
            <Group gap="xs" wrap="wrap">
              <TextInput
                placeholder="Search ID, name, rule, service..."
                leftSection={<IconSearch size={16} />}
                value={search}
                onChange={(e) => {
                  setSearch(e.currentTarget.value);
                  setPage(1);
                }}
                size="xs"
                miw={200}
                style={{ flex: 1, minWidth: 180 }}
              />
              <TextInput
                placeholder="Host (e.g. api.example.com)"
                leftSection={<IconWorld size={14} />}
                value={hostFilter}
                onChange={(e) => {
                  setHostFilter(e.currentTarget.value);
                  setPage(1);
                }}
                size="xs"
                w={160}
              />
              <TextInput
                placeholder="Path (e.g. /api/v1)"
                value={pathFilter}
                onChange={(e) => {
                  setPathFilter(e.currentTarget.value);
                  setPage(1);
                }}
                size="xs"
                w={140}
              />
              <Select
                placeholder="Type"
                size="xs"
                w={100}
                value={typeFilter}
                onChange={(v) => {
                  setTypeFilter(v ?? "all");
                  setPage(1);
                }}
                data={[
                  { value: "all", label: "All" },
                  { value: "http", label: "HTTP" },
                  { value: "grpc", label: "gRPC" },
                  { value: "graphql", label: "GraphQL" },
                ]}
              />
              <Select
                placeholder="Status"
                size="xs"
                w={95}
                value={statusFilter}
                onChange={(v) => {
                  setStatusFilter((v as "all" | "active" | "paused") ?? "all");
                  setPage(1);
                }}
                data={[
                  { value: "all", label: "All" },
                  { value: "active", label: "Active" },
                  { value: "paused", label: "Paused" },
                ]}
              />
            </Group>
          )}
        </Group>

        <Box style={{ overflowX: "auto" }}>
          <Table
            verticalSpacing="md"
            horizontalSpacing="md"
            withRowBorders
            highlightOnHover
          >
            <Table.Thead>
              <Table.Tr bg="var(--mantine-color-default-hover)">
                <Table.Th
                  style={{
                    fontSize: 11,
                    textTransform: "uppercase",
                    letterSpacing: 1,
                    color: "var(--mantine-color-dimmed)",
                    fontWeight: 800,
                  }}
                >
                  Route / Priority
                </Table.Th>
                <Table.Th
                  style={{
                    fontSize: 11,
                    textTransform: "uppercase",
                    letterSpacing: 1,
                    color: "var(--mantine-color-dimmed)",
                    fontWeight: 800,
                  }}
                >
                  Type / Entry
                </Table.Th>
                <Table.Th
                  style={{
                    fontSize: 11,
                    textTransform: "uppercase",
                    letterSpacing: 1,
                    color: "var(--mantine-color-dimmed)",
                    fontWeight: 800,
                  }}
                >
                  Matching Rule
                </Table.Th>
                <Table.Th
                  style={{
                    fontSize: 11,
                    textTransform: "uppercase",
                    letterSpacing: 1,
                    color: "var(--mantine-color-dimmed)",
                    fontWeight: 800,
                  }}
                >
                  Upstream
                </Table.Th>
                <Table.Th
                  style={{
                    fontSize: 11,
                    textTransform: "uppercase",
                    letterSpacing: 1,
                    color: "var(--mantine-color-dimmed)",
                    fontWeight: 800,
                  }}
                >
                  Pipeline
                </Table.Th>
                {!limit && (
                  <Table.Th
                    w={70}
                    style={{
                      fontSize: 11,
                      textTransform: "uppercase",
                      letterSpacing: 1,
                      color: "var(--mantine-color-dimmed)",
                      fontWeight: 800,
                    }}
                  >
                    Activity
                  </Table.Th>
                )}
                {!readOnly && (
                  <Table.Th
                    w={80}
                    style={{
                      fontSize: 11,
                      textTransform: "uppercase",
                      letterSpacing: 1,
                      color: "var(--mantine-color-dimmed)",
                      fontWeight: 800,
                    }}
                  >
                    Actions
                  </Table.Th>
                )}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {routes.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={limit ? 6 : 7}>
                    <Center py={40}>
                      <Stack align="center" gap="xs">
                        <IconRouteOff
                          size={40}
                          color="var(--mantine-color-dimmed)"
                          stroke={1}
                        />
                        <Text ta="center" c="dimmed" size="sm">
                          No routes found.
                        </Text>
                      </Stack>
                    </Center>
                  </Table.Td>
                </Table.Tr>
              )}
              {routes.map((route) => (
                <Table.Tr key={route.id}>
                  <Table.Td>
                    <Stack gap={2}>
                      <Text fw={700} size="sm">
                        {route.name || route.id}
                      </Text>
                      <Group gap={4}>
                        <Code
                          color="indigo.3"
                          variant="light"
                          style={{ fontSize: 10 }}
                        >
                          {route.id}
                        </Code>
                        {route.priority !== 0 && (
                          <Badge size="xs" variant="filled" color="gray">
                            P: {route.priority}
                          </Badge>
                        )}
                      </Group>
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <Stack gap={4}>
                      <Badge
                        size="sm"
                        variant="light"
                        color={route.type === "grpc" ? "blue" : route.type === "graphql" ? "violet" : "indigo"}
                      >
                        {route.type.toUpperCase()}
                      </Badge>
                      {route.disabled && (
                        <Badge size="xs" variant="filled" color="gray">
                          PAUSED
                        </Badge>
                      )}
                      {route.entrypoints && route.entrypoints.length > 0 ? (
                        <Group gap={4}>
                          {route.entrypoints.map((ep) => (
                            <Badge key={ep} size="xs" variant="outline">
                              {ep}
                            </Badge>
                          ))}
                        </Group>
                      ) : (
                        <Badge size="xs" variant="dot" color="gray">
                          All Entries
                        </Badge>
                      )}
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <Tooltip
                      label={route.rule}
                      position="top"
                      multiline
                      style={{ maxWidth: 400 }}
                    >
                      <Code
                        color="blue"
                        variant="light"
                        style={{ fontSize: 10, cursor: "help" }}
                      >
                        {route.rule.length > 50
                          ? route.rule.substring(0, 47) + "..."
                          : route.rule}
                      </Code>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>
                    <Group gap="xs">
                      <Badge size="sm" variant="light" color="teal">
                        {route.service_id}
                      </Badge>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      {route.tls && (
                        <Tooltip label="TLS Enabled">
                          <ActionIcon size="sm" color="green" variant="light">
                            <IconLock size={14} />
                          </ActionIcon>
                        </Tooltip>
                      )}
                      {route.middlewares && route.middlewares.length > 0 && (
                        <Badge
                          size="xs"
                          variant="light"
                          color="indigo"
                          leftSection={<IconSettingsAutomation size={10} />}
                        >
                          {route.middlewares.length}
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                  {!limit && (
                    <Table.Td>
                      <RouteSparklineCell routeId={route.id} />
                    </Table.Td>
                  )}
                  {!readOnly && (
                    <Table.Td>
                      <Menu
                        shadow="md"
                        width={200}
                        position="bottom-end"
                        transitionProps={{ transition: "pop-top-right" }}
                      >
                        <Menu.Target>
                          <ActionIcon variant="subtle" color="gray">
                            <IconDotsVertical size={16} />
                          </ActionIcon>
                        </Menu.Target>
                        <Menu.Dropdown>
                          <Menu.Label>Manage Route</Menu.Label>
                          <Menu.Item
                            leftSection={<IconEdit size={14} />}
                            onClick={() => onEdit?.(route)}
                          >
                            Edit
                          </Menu.Item>
                          <Menu.Item
                            leftSection={<IconCopy size={14} />}
                            onClick={() => onClone?.(route)}
                          >
                            Clone
                          </Menu.Item>
                          <Menu.Item
                            leftSection={<IconPlayerPause size={14} />}
                            onClick={() => onPause?.(route)}
                          >
                            {route.disabled ? "Resume" : "Pause"}
                          </Menu.Item>
                          <Menu.Divider />
                          <Menu.Item
                            leftSection={<IconTrash size={14} />}
                            color="red"
                            onClick={() => onDelete?.(route.id)}
                          >
                            Delete
                          </Menu.Item>
                        </Menu.Dropdown>
                      </Menu>
                    </Table.Td>
                  )}
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Box>

        {!limit && totalCount > pageSize && (
          <Group justify="center" mt="md">
            <Pagination
              total={Math.ceil(totalCount / pageSize)}
              value={page}
              onChange={setPage}
              size="sm"
            />
          </Group>
        )}

        {routes.length > 0 && (
          <Box
            pt="md"
            style={{
              borderTop: "1px solid var(--mantine-color-default-border)",
            }}
          >
            <Title
              order={6}
              mb="sm"
              c="dimmed"
              fw={800}
              style={{ textTransform: "uppercase", letterSpacing: 1 }}
            >
              Live Metrics Preview
            </Title>
            <SimpleGrid cols={{ base: 1, md: 3 }} spacing="md">
              {routes.slice(0, 3).map((route) => (
                <RouteStats key={route.id} routeId={route.id} />
              ))}
            </SimpleGrid>
            {routes.length > 3 && (
              <Text size="xs" c="dimmed" ta="center" mt="sm">
                Showing top 3 routes metrics.
              </Text>
            )}
          </Box>
        )}
      </Stack>
    </Card>
  );
}
