// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState, useEffect } from "react";
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
  Center,
  Divider,
  Menu,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { useNavigate } from "@tanstack/react-router";
import {
  IconCheck,
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
import { useIsMobile } from "../hooks/useMobile";
import type { User } from "../types/gateon";
import { useAuthStore } from "../store/useAuthStore";
import { TwoFactorModal } from "../components/TwoFactorModal";
import { QueryError } from "../components/QueryError";
import { ChangePasswordForm } from "../components/ChangePasswordForm";
import { queryClient } from "../queryClient";
import { ConfirmDeleteModal } from "../components/ConfirmDelete";
import { notifyError, notifySuccess } from "../utils/notify";
import { userSaveRefusalMessage } from "../components/userSaveMessages";

export default function UsersPage() {
  const [search, setSearch] = useState("");
  const isMobile = useIsMobile();
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const density = useTableDensity();
  const { data, refetch, isLoading, isError, error } = useUsers({
    page: page - 1,
    pageSize: pageSize,
    search: search,
  });
  const [opened, { open, close }] = useDisclosure(false);
  const [pwOpened, { open: pwOpen, close: pwClose }] = useDisclosure(false);
  const [tfaOpened, { open: tfaOpen, close: tfaClose }] = useDisclosure(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [targetUser, setTargetUser] = useState<User | null>(null);
  const [pendingDelete, setPendingDelete] = useState<User | null>(null);
  const currentUser = useAuthStore((state) => state.user);
  const token = useAuthStore((state) => state.token);
  const logout = useAuthStore((state) => state.logout);
  const navigate = useNavigate();

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
    pwOpen();
  };

  // Your own password change ends every session the account has, this one
  // included, so go to the sign-in page rather than let the next request fail.
  const handlePasswordChanged = (user: User) => {
    const own = currentUser?.id === user.id;
    notifications.show({
      title: "Password changed",
      message: own ? "Sign in again with your new password." : `The password for ${user.username} was changed.`,
      color: "green",
      icon: <IconCheck size={16} />,
    });
    pwClose();
    if (own) {
      queryClient.clear();
      logout();
      void navigate({ to: "/login" });
    }
  };

  const isAdmin = currentUser?.role === "admin";

  if (!isAdmin) {
    return (
      <Center style={{ height: '50vh' }}>
        <Stack align="center" gap="xs">
          <IconShieldLock size={48} color="var(--mantine-color-red-6)" />
          <Title order={2}>Access Denied</Title>
          <Text c="dimmed">You do not have permission to manage system users.</Text>
        </Stack>
      </Center>
    );
  }

  // putUser persists a partial change while preserving the rest of the user's
  // state, so toggling one flag never silently resets the others (the backend
  // applies disabled and twoFactorPending from whatever the body contains).
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
          twoFactorPending: user.twoFactorPending ?? false,
          twoFactorEnabled: user.twoFactorEnabled ?? false,
          ...changes,
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      refetch();
    } catch (err) {
      // A refused change used to vanish into the console, leaving the row as
      // it was with nothing to say the click had failed.
      notifyError(err, { title: `Could not update user "${user.username}"` });
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
    if (isAdmin && !user.twoFactorEnabled) {
      putUser(user, { twoFactorPending: !user.twoFactorPending });
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

      // A taken username is refused (409) and nothing is written; say so in
      // the dashboard's words and keep the form open to pick another name.
      const refusal = userSaveRefusalMessage(res.status);
      if (refusal) {
        notifyError(null, { title: "Could not save user", message: refusal });
        return;
      }
      // A refused save used to do nothing at all: no message, the form still
      // open, and no way to tell a rejected account from a slow one.
      if (!res.ok) throw new Error(await res.text());
      notifySuccess(`User "${values.username}" saved.`);
      refetch();
      close();
    } catch (err) {
      notifyError(err, { title: "Could not save user" });
    }
  };

  // Deleting asked "Are you sure you want to delete this user?" -- the same
  // question on every row. The confirmation names the account now.
  const confirmDelete = async () => {
    const user = pendingDelete;
    setPendingDelete(null);
    if (!user) return;
    try {
      const res = await apiFetch(`/v1/users/${encodeURIComponent(user.id)}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error(await res.text());
      notifySuccess(`User "${user.username}" deleted.`);
      refetch();
    } catch (err) {
      notifyError(err, { title: `Could not delete user "${user.username}"` });
    }
  };

  const totalCount = data?.totalCount || 0;
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
          {user.twoFactorEnabled ? (
            <Badge size="xs" color="green" variant="light">
              2FA
            </Badge>
          ) : user.twoFactorPending ? (
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
              aria-label={`Change password for ${user.username}`}
              disabled={currentUser?.role !== "admin" && currentUser?.id !== user.id}
            >
              <IconKey size={16} />
            </ActionIcon>
          </Tooltip>
          <Tooltip
            label={
              currentUser?.id === user.id
                ? "Manage your two-factor authentication"
                : user.twoFactorEnabled
                  ? "User has 2FA enabled"
                  : user.twoFactorPending
                    ? "2FA required — click to cancel requirement"
                    : "Require this user to set up 2FA"
            }
          >
            <ActionIcon
              variant="subtle"
              color={
                user.twoFactorEnabled
                  ? "green"
                  : user.twoFactorPending
                    ? "orange"
                    : "gray"
              }
              onClick={() => handle2FA(user)}
              aria-label={`Two-factor authentication for ${user.username}`}
              disabled={
                !(
                  currentUser?.id === user.id ||
                  (isAdmin && !user.twoFactorEnabled)
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
              aria-label={user.disabled ? `Enable user ${user.username}` : `Disable user ${user.username}`}
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
              aria-label={`Edit user ${user.username}`}
              disabled={currentUser?.role !== "admin"}
            >
              <IconEdit size={16} />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Delete user">
            <ActionIcon
              variant="subtle"
              color="red"
              onClick={() => setPendingDelete(user)}
              aria-label={`Delete user ${user.username}`}
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
      <Group justify="space-between" wrap="wrap" gap="md">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            User Management ({totalCount})
          </Title>
          <Text c="dimmed" size="sm">
            Manage system administrators and operators using Role Based Access
            Control.
          </Text>
        </div>
        <Group wrap={isMobile ? "wrap" : "nowrap"} style={{ flex: isMobile ? "1 1 100%" : "none" }}>
          <TextInput
            placeholder="Search users..."
            leftSection={<IconSearch size={16} />}
            size="xs"
            w={isMobile ? "100%" : 250}
            style={{ flex: isMobile ? "1 1 100%" : "none" }}
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
            fullWidth={isMobile}
          >
            Add User
          </Button>
        </Group>
      </Group>

      <Card withBorder padding={isMobile ? "sm" : "xl"} radius="lg" shadow="xs">
        {isMobile ? (
          <Stack gap="md">
            {isError ? (
              <QueryError error={error} what="users" onRetry={() => refetch()} />
            ) : isLoading ? (
               <Text ta="center" py="xl" c="dimmed">Loading users...</Text>
            ) : users.length === 0 ? (
               <Text ta="center" py="xl" c="dimmed">No users found</Text>
            ) : (
              users.map((user) => (
                <Card key={user.id} withBorder radius="md" p="md">
                  <Stack gap="xs">
                    <Group justify="space-between" align="flex-start">
                      <Stack gap={2}>
                        <Group gap="xs">
                          <Text fw={700} size="sm">{user.username}</Text>
                          {currentUser?.id === user.id && <Badge size="xs" variant="light">You</Badge>}
                        </Group>
                        <Badge
                          size="xs"
                          color={user.role === "admin" ? "red" : user.role === "operator" ? "blue" : "gray"}
                          variant="light"
                        >
                          {user.role}
                        </Badge>
                      </Stack>
                      <Group gap={4}>
                         {user.disabled && <Badge size="xs" color="red" variant="light">Disabled</Badge>}
                         {user.twoFactorEnabled ? (
                            <Badge size="xs" color="green" variant="light">2FA</Badge>
                          ) : user.twoFactorPending ? (
                            <Badge size="xs" color="orange" variant="light">2FA pending</Badge>
                          ) : null}
                      </Group>
                    </Group>
                    <Divider variant="dashed" />
                    <Group justify="flex-end" gap="xs">
                      <Tooltip label="Change password">
                        <ActionIcon
                          variant="light"
                          color="blue"
                          onClick={() => handleChangePassword(user)}
              aria-label={`Change password for ${user.username}`}
                          disabled={currentUser?.role !== "admin" && currentUser?.id !== user.id}
                        >
                          <IconKey size={16} />
                        </ActionIcon>
                      </Tooltip>
                      <ActionIcon
                        variant="light"
                        color={user.twoFactorEnabled ? "green" : user.twoFactorPending ? "orange" : "gray"}
                        onClick={() => handle2FA(user)}
              aria-label={`Two-factor authentication for ${user.username}`}
                        disabled={!(currentUser?.id === user.id || (isAdmin && !user.twoFactorEnabled))}
                      >
                        <IconShieldLock size={16} />
                      </ActionIcon>
                      <ActionIcon
                        variant="light"
                        color={user.disabled ? "green" : "orange"}
                        onClick={() => handleToggleDisabled(user)}
              aria-label={user.disabled ? `Enable user ${user.username}` : `Disable user ${user.username}`}
                        disabled={!isAdmin || currentUser?.id === user.id}
                      >
                        {user.disabled ? <IconUserCheck size={16} /> : <IconBan size={16} />}
                      </ActionIcon>
                      <ActionIcon
                        variant="light"
                        color="gray"
                        onClick={() => handleEdit(user)}
              aria-label={`Edit user ${user.username}`}
                        disabled={currentUser?.role !== "admin"}
                      >
                        <IconEdit size={16} />
                      </ActionIcon>
                      <ActionIcon
                        variant="light"
                        color="red"
                        onClick={() => setPendingDelete(user)}
              aria-label={`Delete user ${user.username}`}
                        disabled={currentUser?.role !== "admin" || currentUser?.id === user.id}
                      >
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Group>
                  </Stack>
                </Card>
              ))
            )}
          </Stack>
        ) : (
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
        )}
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
              // Choosing the option already chosen used to clear it (Mantine's
              // default), so re-picking the preselected Viewer left the form
              // refusing to submit with "Role is required".
              allowDeselect={false}
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
        {targetUser && (
          <ChangePasswordForm
            userId={targetUser.id}
            own={currentUser?.id === targetUser.id}
            onChanged={() => handlePasswordChanged(targetUser)}
          />
        )}
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

      <ConfirmDeleteModal
        target={pendingDelete ? { kind: "user", name: pendingDelete.username } : null}
        consequence="Their sessions end and the account can no longer log in."
        onCancel={() => setPendingDelete(null)}
        onConfirm={() => void confirmDelete()}
      />
    </Stack>
  );
}
