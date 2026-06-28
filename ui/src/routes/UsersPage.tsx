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
  IconKey,
  IconShieldLock,
  IconUsers,
  IconSearch,
  IconBan,
  IconUserCheck,
} from "@tabler/icons-react";
import { useUsers, apiFetch } from "../hooks/useGateon";
import { useTableDensity } from "../hooks/useTableDensity";
import type { User } from "../types/gateon";
import { useAuthStore } from "../store/useAuthStore";
import { TwoFactorModal } from "../components/TwoFactorModal";

export default function UsersPage() {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const density = useTableDensity();
  const { data, refetch, isLoading } = useUsers({
    page: page - 1,
    page_size: pageSize,
    search: search,
  });
  const [opened, { open, close }] = useDisclosure(false);
  const [pwOpened, { open: pwOpen, close: pwClose }] = useDisclosure(false);
  const [tfaOpened, { open: tfaOpen, close: tfaClose }] = useDisclosure(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [targetUser, setTargetUser] = useState<User | null>(null);
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

  const handleChangePassword = (user: User) => {
    setTargetUser(user);
    passwordForm.reset();
    pwOpen();
  };

  const isAdmin = currentUser?.role === "admin";

  // putUser persists a partial change while preserving the rest of the user's
  // state, so toggling one flag never silently resets the others (the backend
  // applies disabled and two_factor_pending from whatever the body contains).
  const putUser = async (user: User, changes: Partial<User>) => {
    try {
      const res = await apiFetch("/v1/users", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: user.id,
          username: user.username,
          role: user.role,
          disabled: user.disabled ?? false,
          two_factor_pending: user.two_factor_pending ?? false,
          two_factor_enabled: user.two_factor_enabled ?? false,
          ...changes,
        }),
      });
      if (res.ok) refetch();
    } catch (err) {
      console.error("Failed to update user", err);
    }
  };

  const handleToggleDisabled = (user: User) => {
    putUser(user, { disabled: !user.disabled });
  };

  const handle2FA = (user: User) => {
    // Self-service: the account owner manages their own 2FA via the enrollment
    // modal (only they ever see the secret).
    if (currentUser?.id === user.id) {
      setTargetUser(user);
      tfaOpen();
      return;
    }
    // Admin acting on another user: an admin can only MANDATE 2FA (set/clear the
    // pending requirement); they never see the secret. The user enrolls on their
    // next login. Mandating is a no-op once 2FA is already enabled.
    if (isAdmin && !user.two_factor_enabled) {
      putUser(user, { two_factor_pending: !user.two_factor_pending });
    }
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

  const passwordForm = useForm({
    initialValues: {
      password: "",
      confirmPassword: "",
    },
    validate: {
      password: (value) => (value.length < 6 ? "Password must be at least 6 characters" : null),
      confirmPassword: (value, values) => (value !== values.password ? "Passwords do not match" : null),
    },
  });

  const handlePasswordSubmit = async (values: typeof passwordForm.values) => {
    if (!targetUser) return;
    try {
      const res = await apiFetch("/v1/users/password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          id: targetUser.id,
          password: values.password,
        }),
      });

      if (res.ok) {
        pwClose();
      }
    } catch (err) {
      console.error("Failed to change password", err);
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
          {user.disabled && (
            <Badge size="xs" color="red" variant="light">
              Disabled
            </Badge>
          )}
          {user.two_factor_enabled ? (
            <Badge size="xs" color="green" variant="light">
              2FA
            </Badge>
          ) : user.two_factor_pending ? (
            <Badge size="xs" color="orange" variant="light">
              2FA pending
            </Badge>
          ) : null}
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
          <Tooltip label="Change password">
            <ActionIcon
              variant="subtle"
              color="blue"
              onClick={() => handleChangePassword(user)}
              disabled={currentUser?.role !== "admin" && currentUser?.id !== user.id}
            >
              <IconKey size={16} />
            </ActionIcon>
          </Tooltip>
          <Tooltip
            label={
              currentUser?.id === user.id
                ? "Manage your two-factor authentication"
                : user.two_factor_enabled
                  ? "User has 2FA enabled"
                  : user.two_factor_pending
                    ? "2FA required — click to cancel requirement"
                    : "Require this user to set up 2FA"
            }
          >
            <ActionIcon
              variant="subtle"
              color={
                user.two_factor_enabled
                  ? "green"
                  : user.two_factor_pending
                    ? "orange"
                    : "gray"
              }
              onClick={() => handle2FA(user)}
              disabled={
                !(
                  currentUser?.id === user.id ||
                  (isAdmin && !user.two_factor_enabled)
                )
              }
            >
              <IconShieldLock size={16} />
            </ActionIcon>
          </Tooltip>
          <Tooltip label={user.disabled ? "Enable user" : "Disable user"}>
            <ActionIcon
              variant="subtle"
              color={user.disabled ? "green" : "orange"}
              onClick={() => handleToggleDisabled(user)}
              disabled={!isAdmin || currentUser?.id === user.id}
            >
              {user.disabled ? (
                <IconUserCheck size={16} />
              ) : (
                <IconBan size={16} />
              )}
            </ActionIcon>
          </Tooltip>
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
        <Table {...density}>
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
            {!editingUser && (
              <PasswordInput
                label="Password"
                placeholder="Enter password"
                required
                {...form.getInputProps("password")}
              />
            )}
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

      <Modal
        opened={pwOpened}
        onClose={pwClose}
        title={
          <Group gap="xs">
            <IconKey size={20} />
            <Text fw={700}>
              Change Password for {targetUser?.username}
            </Text>
          </Group>
        }
        radius="md"
      >
        <form onSubmit={passwordForm.onSubmit(handlePasswordSubmit)}>
          <Stack gap="md">
            <PasswordInput
              label="New Password"
              placeholder="Enter new password"
              required
              {...passwordForm.getInputProps("password")}
            />
            <PasswordInput
              label="Confirm New Password"
              placeholder="Confirm new password"
              required
              {...passwordForm.getInputProps("confirmPassword")}
            />
            <Button type="submit" mt="md" fullWidth color="blue">
              Change Password
            </Button>
          </Stack>
        </form>
      </Modal>

      {targetUser && (
        <TwoFactorModal
          opened={tfaOpened}
          onClose={tfaClose}
          user={targetUser}
          onSuccess={() => refetch()}
        />
      )}

      <Paper withBorder p="md" radius="md" bg="light-dark(var(--mantine-color-blue-0), var(--mantine-color-dark-8))">
        <Group gap="xs" align="flex-start" wrap="nowrap">
          <IconShieldLock
            size={20}
            color="var(--mantine-color-blue-6)"
            style={{ marginTop: 2 }}
          />
          <div>
            <Text size="sm" fw={700} c="light-dark(var(--mantine-color-blue-9), var(--mantine-color-blue-2))">
              Role Capabilities
            </Text>
            <Stack gap={4} mt={4}>
              <Text size="xs" c="light-dark(var(--mantine-color-blue-8), var(--mantine-color-blue-3))">
                • <b>Admin:</b> Full access including user management and system
                configuration.
              </Text>
              <Text size="xs" c="light-dark(var(--mantine-color-blue-8), var(--mantine-color-blue-3))">
                • <b>Operator:</b> Can manage routes, services, and middleware
                but cannot manage users.
              </Text>
              <Text size="xs" c="light-dark(var(--mantine-color-blue-8), var(--mantine-color-blue-3))">
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
