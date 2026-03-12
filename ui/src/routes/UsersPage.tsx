import { useState } from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  Table,
  Group,
  Button,
  ActionIcon,
  Badge,
  Modal,
  TextInput,
  PasswordInput,
  Select,
  Paper,
  Tooltip,
  Pagination,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useForm } from "@mantine/form";
import {
  IconUserPlus,
  IconTrash,
  IconEdit,
  IconShieldLock,
  IconUsers,
  IconSearch,
} from "@tabler/icons-react";
import { useUsers, apiFetch } from "../hooks/useGateon";
import type { User } from "../types/gateon";
import { useAuthStore } from "../store/useAuthStore";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8080";

export default function UsersPage() {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const { data, refetch, isLoading } = useUsers({
    page: page - 1,
    page_size: pageSize,
    search: search,
  });
  const [opened, { open, close }] = useDisclosure(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const currentUser = useAuthStore((state) => state.user);
  const token = useAuthStore((state) => state.token);

  const form = useForm({
    initialValues: {
      username: "",
      password: "",
      role: "viewer" as User["role"],
    },
    validate: {
      username: (value: string) =>
        value.length < 2 ? "Username is too short" : null,
      role: (value: string) => (!value ? "Role is required" : null),
    },
  });

  const handleEdit = (user: User) => {
    setEditingUser(user);
    form.setValues({
      username: user.username,
      password: "",
      role: user.role,
    });
    open();
  };

  const handleCreate = () => {
    setEditingUser(null);
    form.reset();
    open();
  };

  const handleSubmit = async (values: typeof form.values) => {
    try {
      const res = await apiFetch("/v1/users", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          id: editingUser?.id,
          ...values,
        }),
      });

      if (res.ok) {
        refetch();
        close();
      }
    } catch (err) {
      console.error("Failed to save user", err);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this user?")) return;

    try {
      const res = await apiFetch(`/v1/users/${id}`, {
        method: "DELETE",
      });

      if (res.ok) {
        refetch();
      }
    } catch (err) {
      console.error("Failed to delete user", err);
    }
  };

  const totalCount = data?.total_count || 0;
  const users = data?.users || [];

  const rows = users.map((user) => (
    <Table.Tr key={user.id}>
      <Table.Td>
        <Group gap="sm">
          <IconShieldLock size={16} color="var(--mantine-color-dimmed)" />
          <Text size="sm" fw={500}>
            {user.username}
          </Text>
          {currentUser?.id === user.id && (
            <Badge size="xs" variant="light">
              You
            </Badge>
          )}
        </Group>
      </Table.Td>
      <Table.Td>
        <Badge
          color={
            user.role === "admin"
              ? "red"
              : user.role === "operator"
                ? "blue"
                : "gray"
          }
          variant="light"
        >
          {user.role}
        </Badge>
      </Table.Td>
      <Table.Td>
        <Group gap={0} justify="flex-end">
          <Tooltip label="Edit user">
            <ActionIcon
              variant="subtle"
              color="gray"
              onClick={() => handleEdit(user)}
              disabled={currentUser?.role !== "admin"}
            >
              <IconEdit size={16} />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Delete user">
            <ActionIcon
              variant="subtle"
              color="red"
              onClick={() => handleDelete(user.id)}
              disabled={
                currentUser?.role !== "admin" || currentUser?.id === user.id
              }
            >
              <IconTrash size={16} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Table.Td>
    </Table.Tr>
  ));

  return (
    <Stack gap="xl">
      <Group justify="space-between">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            User Management ({totalCount})
          </Title>
          <Text c="dimmed" size="sm">
            Manage system administrators and operators using Role Based Access
            Control.
          </Text>
        </div>
        <Group>
          <TextInput
            placeholder="Search users..."
            leftSection={<IconSearch size={16} />}
            size="xs"
            w={250}
            value={search}
            onChange={(e) => {
              setSearch(e.currentTarget.value);
              setPage(1);
            }}
          />
          <Button
            leftSection={<IconUserPlus size={18} />}
            onClick={handleCreate}
            disabled={currentUser?.role !== "admin"}
            radius="md"
          >
            Add User
          </Button>
        </Group>
      </Group>

      <Card withBorder padding="xl" radius="lg" shadow="xs">
        <Table verticalSpacing="md">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Username</Table.Th>
              <Table.Th>Role</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {isLoading ? (
              <Table.Tr>
                <Table.Td colSpan={3}>
                  <Text ta="center" py="xl" c="dimmed">
                    Loading users...
                  </Text>
                </Table.Td>
              </Table.Tr>
            ) : rows?.length === 0 ? (
              <Table.Tr>
                <Table.Td colSpan={3}>
                  <Text ta="center" py="xl" c="dimmed">
                    No users found
                  </Text>
                </Table.Td>
              </Table.Tr>
            ) : (
              rows
            )}
          </Table.Tbody>
        </Table>
        {totalCount > pageSize && (
          <Group justify="center" py="md" style={{ borderTop: '1px solid var(--mantine-color-default-border)' }}>
            <Pagination
              total={Math.ceil(totalCount / pageSize)}
              value={page}
              onChange={setPage}
              size="sm"
            />
          </Group>
        )}
      </Card>

      <Modal
        opened={opened}
        onClose={close}
        title={
          <Group gap="xs">
            <IconUsers size={20} />
            <Text fw={700}>
              {editingUser ? "Edit User" : "Create New User"}
            </Text>
          </Group>
        }
        radius="md"
      >
        <form onSubmit={form.onSubmit(handleSubmit)}>
          <Stack gap="md">
            <TextInput
              label="Username"
              placeholder="Enter username"
              required
              {...form.getInputProps("username")}
            />
            <PasswordInput
              label={editingUser ? "New Password (optional)" : "Password"}
              placeholder="Enter password"
              required={!editingUser}
              {...form.getInputProps("password")}
            />
            <Select
              label="Role"
              placeholder="Select role"
              data={[
                { label: "Administrator (Full Access)", value: "admin" },
                { label: "Operator (Read/Write Config)", value: "operator" },
                { label: "Viewer (Read Only)", value: "viewer" },
              ]}
              required
              {...form.getInputProps("role")}
            />
            <Button type="submit" mt="md" fullWidth>
              {editingUser ? "Update User" : "Create User"}
            </Button>
          </Stack>
        </form>
      </Modal>

      <Paper withBorder p="md" radius="md" bg="blue.0">
        <Group gap="xs" align="flex-start" wrap="nowrap">
          <IconShieldLock
            size={20}
            color="var(--mantine-color-blue-6)"
            style={{ marginTop: 2 }}
          />
          <div>
            <Text size="sm" fw={700} c="blue.9">
              Role Capabilities
            </Text>
            <Stack gap={4} mt={4}>
              <Text size="xs" c="blue.8">
                • <b>Admin:</b> Full access including user management and system
                configuration.
              </Text>
              <Text size="xs" c="blue.8">
                • <b>Operator:</b> Can manage routes, services, and middleware
                but cannot manage users.
              </Text>
              <Text size="xs" c="blue.8">
                • <b>Viewer:</b> Read-only access to all dashboards and
                configurations.
              </Text>
            </Stack>
          </div>
        </Group>
      </Paper>
    </Stack>
  );
}
