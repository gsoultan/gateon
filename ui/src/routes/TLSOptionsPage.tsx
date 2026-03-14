import { useState } from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  TextInput,
  Button,
  Group,
  Table,
  Tooltip,
  ScrollArea,
  Modal,
  MultiSelect,
  TagsInput,
  ActionIcon,
  Badge,
  Code,
  Switch,
  Select,
  Pagination,
} from "@mantine/core";
import {
  IconPlus,
  IconTrash,
  IconPencil,
  IconShieldLock,
  IconCheck,
} from "@tabler/icons-react";
import { useDisclosure } from "@mantine/hooks";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import type { TLSOption } from "../types/gateon";
import { useTLSOptions, apiFetch, getApiErrorMessage } from "../hooks/useGateon";
import { usePermissions } from "../hooks/usePermissions";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8080";

const TLS_VERSIONS = [
  { label: "TLS 1.2", value: "TLS1.2" },
  { label: "TLS 1.3", value: "TLS1.3" },
];

const CIPHER_SUITES = [
  "TLS_RSA_WITH_AES_128_CBC_SHA",
  "TLS_RSA_WITH_AES_256_CBC_SHA",
  "TLS_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
  "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
];

export default function TLSOptionsPage() {
  const { canWrite } = usePermissions();
  const queryClient = useQueryClient();
  const [opened, { open, close }] = useDisclosure(false);
  const [editingOption, setEditingOption] = useState<TLSOption | null>(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const { data, isLoading } = useTLSOptions({
    page: page - 1,
    page_size: pageSize,
    search: search,
  });

  const mutation = useMutation({
    mutationFn: async (opt: TLSOption) => {
      const res = await apiFetch("/v1/tls-options", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(opt),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tlsoptions"] });
      notifications.show({
        title: "TLS Option Saved",
        message: "The TLS configuration has been updated.",
        color: "green",
        icon: <IconCheck size={18} />,
      });
      close();
    },
    onError: (err: unknown) => {
      notifications.show({
        title: "Error Saving TLS Option",
        message: getApiErrorMessage(err),
        color: "red",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiFetch(
        `/v1/tls-options/${encodeURIComponent(id)}`,
        {
          method: "DELETE",
        },
      );
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tlsoptions"] });
      notifications.show({
        title: "TLS Option Deleted",
        message: "The TLS option has been removed.",
        color: "blue",
      });
    },
  });

  const startAdd = () => {
    setEditingOption({
      id: "",
      name: "",
      min_tls_version: "TLS1.2",
      max_tls_version: "TLS1.3",
      cipher_suites: [],
      prefer_server_cipher_suites: true,
      sni_strict: false,
      alpn_protocols: ["h2", "http/1.1"],
    });
    open();
  };

  const startEdit = (opt: TLSOption) => {
    setEditingOption({ ...opt });
    open();
  };

  const handleSave = () => {
    if (editingOption) {
      mutation.mutate(editingOption);
    }
  };

  const tlsOptions = data?.tls_options || [];
  const totalCount = data?.total_count || 0;

  return (
    <Stack gap="xl">
      <Group justify="space-between" mb="md">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            TLS Options ({totalCount})
          </Title>
          <Text c="dimmed" size="sm">
            Configure specialized TLS parameters for your routes.
          </Text>
        </div>
        <Group>
          <TextInput
            placeholder="Search TLS options..."
            size="xs"
            w={250}
            value={search}
            onChange={(e) => {
              setSearch(e.currentTarget.value);
              setPage(1);
            }}
          />
          {canWrite && (
            <Button
              leftSection={<IconPlus size={16} />}
              onClick={startAdd}
              radius="md"
            >
              Add TLS Option
            </Button>
          )}
        </Group>
      </Group>

      <Card withBorder padding={0} radius="lg" shadow="xs">
        <ScrollArea>
          <Table verticalSpacing="md" horizontalSpacing="xl">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>ID / Name</Table.Th>
                <Table.Th>Versions</Table.Th>
                <Table.Th>Cipher Suites</Table.Th>
                <Table.Th>Strict SNI</Table.Th>
                <Table.Th style={{ width: 100 }}>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {isLoading ? (
                <Table.Tr>
                  <Table.Td colSpan={5} align="center">
                    <Text py="xl">Loading...</Text>
                  </Table.Td>
                </Table.Tr>
              ) : tlsOptions.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={5} align="center">
                    <Stack align="center" py="xl" gap="xs">
                      <IconShieldLock size={40} color="gray" />
                      <Text c="dimmed">No TLS options configured</Text>
                    </Stack>
                  </Table.Td>
                </Table.Tr>
              ) : (
                tlsOptions.map((opt) => (
                  <Table.Tr key={opt.id}>
                    <Table.Td>
                      <Stack gap={2}>
                        <Text fw={700} size="sm">
                          {opt.name || "Unnamed"}
                        </Text>
                        <Code
                          color="blue"
                          variant="light"
                          style={{ fontSize: 10 }}
                        >
                          {opt.id}
                        </Code>
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        <Badge size="xs" variant="outline">
                          {opt.min_tls_version || "TLS1.2"}
                        </Badge>
                        <Text size="xs">to</Text>
                        <Badge size="xs" variant="outline">
                          {opt.max_tls_version || "TLS1.3"}
                        </Badge>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" c="dimmed">
                        {opt.cipher_suites && opt.cipher_suites.length > 0
                          ? `${opt.cipher_suites.length} selected`
                          : "Default"}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge
                        color={opt.sni_strict ? "red" : "gray"}
                        variant="light"
                      >
                        {opt.sni_strict ? "Yes" : "No"}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      {canWrite && (
                        <Group gap="xs" justify="flex-end">
                          <Tooltip label="Edit">
                            <ActionIcon
                              variant="subtle"
                              color="blue"
                              onClick={() => startEdit(opt)}
                            >
                              <IconPencil size={16} />
                            </ActionIcon>
                          </Tooltip>
                          <Tooltip label="Remove">
                            <ActionIcon
                              variant="subtle"
                              color="red"
                              onClick={() => {
                                if (
                                  confirm(
                                    "Are you sure you want to delete this TLS option?",
                                  )
                                ) {
                                  deleteMutation.mutate(opt.id);
                                }
                              }}
                            >
                              <IconTrash size={16} />
                            </ActionIcon>
                          </Tooltip>
                        </Group>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
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
        title={editingOption?.id ? "Edit TLS Option" : "Add TLS Option"}
        radius="lg"
        size="lg"
      >
        <Stack gap="md">
          <TextInput
            label="Friendly Name"
            placeholder="Modern Security Policy"
            value={editingOption?.name || ""}
            onChange={(e) =>
              editingOption &&
              setEditingOption({
                ...editingOption,
                name: e.currentTarget.value,
              })
            }
            radius="md"
            size="md"
          />

          <Group grow>
            <Select
              label="Min TLS Version"
              data={TLS_VERSIONS}
              value={editingOption?.min_tls_version || "TLS1.2"}
              onChange={(val) =>
                editingOption &&
                setEditingOption({
                  ...editingOption,
                  min_tls_version: val || "TLS1.2",
                })
              }
            />
            <Select
              label="Max TLS Version"
              data={TLS_VERSIONS}
              value={editingOption?.max_tls_version || "TLS1.3"}
              onChange={(val) =>
                editingOption &&
                setEditingOption({
                  ...editingOption,
                  max_tls_version: val || "TLS1.3",
                })
              }
            />
          </Group>

          <MultiSelect
            label="Cipher Suites"
            description="Only effective for TLS 1.2 and below. TLS 1.3 ciphers are not configurable."
            placeholder="Select cipher suites"
            data={CIPHER_SUITES}
            value={editingOption?.cipher_suites || []}
            onChange={(val) =>
              editingOption &&
              setEditingOption({ ...editingOption, cipher_suites: val })
            }
            searchable
            clearable
            disabled={editingOption?.min_tls_version === "TLS1.3"}
          />

          <TagsInput
            label="ALPN Protocols"
            placeholder="e.g. h2, http/1.1"
            data={["h2", "http/1.1", "grpc-exp"]}
            value={editingOption?.alpn_protocols || []}
            onChange={(val) =>
              editingOption &&
              setEditingOption({ ...editingOption, alpn_protocols: val })
            }
            clearable
          />

          <Group grow>
            <Switch
              label="Prefer Server Cipher Suites"
              checked={editingOption?.prefer_server_cipher_suites || false}
              onChange={(e) =>
                editingOption &&
                setEditingOption({
                  ...editingOption,
                  prefer_server_cipher_suites: e.currentTarget.checked,
                })
              }
            />
            <Switch
              label="Strict SNI"
              description="Reject requests without SNI or with mismatched SNI"
              checked={editingOption?.sni_strict || false}
              onChange={(e) =>
                editingOption &&
                setEditingOption({
                  ...editingOption,
                  sni_strict: e.currentTarget.checked,
                })
              }
            />
          </Group>

          <Button
            onClick={handleSave}
            radius="md"
            mt="md"
            loading={mutation.isPending}
            disabled={!editingOption?.id}
          >
            Save TLS Option
          </Button>
        </Stack>
      </Modal>
    </Stack>
  );
}
