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
  Select,
  ActionIcon,
  Badge,
  Code,
  JsonInput,
  Tabs,
  Pagination,
} from "@mantine/core";
import {
  IconPlus,
  IconTrash,
  IconPencil,
  IconSettingsAutomation,
  IconInfoCircle,
  IconCheck,
  IconSettings,
  IconCode,
} from "@tabler/icons-react";
import { useDisclosure } from "@mantine/hooks";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import type { Middleware } from "../types/gateon";
import { useMiddlewares, apiFetch } from "../hooks/useGateon";
import { MiddlewareConfigEditor } from "../components/MiddlewareConfigEditor";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8080";

export default function MiddlewaresPage() {
  const queryClient = useQueryClient();
  const [opened, { open, close }] = useDisclosure(false);
  const [editingMW, setEditingMW] = useState<Middleware | null>(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const { data, isLoading } = useMiddlewares({
    page: page - 1,
    page_size: pageSize,
    search: search,
  });

  const mutation = useMutation({
    mutationFn: async (mw: Middleware) => {
      const res = await apiFetch("/v1/middlewares", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(mw),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["middlewares"] });
      notifications.show({
        title: "Middleware Saved",
        message: "The middleware configuration has been updated.",
        color: "green",
        icon: <IconCheck size={18} />,
      });
      close();
    },
    onError: (err) => {
      notifications.show({
        title: "Error Saving Middleware",
        message: err.message,
        color: "red",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiFetch(
        `/v1/middlewares/${encodeURIComponent(id)}`,
        {
          method: "DELETE",
        },
      );
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["middlewares"] });
      notifications.show({
        title: "Middleware Deleted",
        message: "The middleware has been removed.",
        color: "blue",
      });
    },
  });

  const startAdd = () => {
    setEditingMW({ id: "", name: "", type: "ratelimit", config: {} });
    open();
  };

  const startEdit = (mw: Middleware) => {
    setEditingMW({ ...mw });
    open();
  };

  const handleSave = () => {
    if (editingMW) {
      mutation.mutate(editingMW);
    }
  };

  const middlewares = data?.middlewares || [];
  const totalCount = data?.total_count || 0;

  return (
    <Stack gap="xl">
      <Group justify="space-between" mb="md">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            Middlewares ({totalCount})
          </Title>
          <Text c="dimmed" size="sm">
            Define reusable middleware policies for your routes.
          </Text>
        </div>
        <Group>
          <TextInput
            placeholder="Search middlewares..."
            size="xs"
            w={250}
            value={search}
            onChange={(e) => {
              setSearch(e.currentTarget.value);
              setPage(1);
            }}
          />
          <Button
            leftSection={<IconPlus size={16} />}
            onClick={startAdd}
            radius="md"
          >
            Add Middleware
          </Button>
        </Group>
      </Group>

      <Card withBorder padding={0} radius="lg" shadow="xs">
        <ScrollArea>
          <Table verticalSpacing="md" horizontalSpacing="xl">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>ID / Name</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th>Config Preview</Table.Th>
                <Table.Th style={{ width: 100 }}>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {isLoading ? (
                <Table.Tr>
                  <Table.Td colSpan={4} align="center">
                    <Text py="xl">Loading...</Text>
                  </Table.Td>
                </Table.Tr>
              ) : middlewares.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={4} align="center">
                    <Stack align="center" py="xl" gap="xs">
                      <IconSettingsAutomation size={40} color="dimmed" />
                      <Text c="dimmed">No middlewares configured</Text>
                    </Stack>
                  </Table.Td>
                </Table.Tr>
              ) : (
                middlewares.map((mw) => (
                  <Table.Tr key={mw.id}>
                    <Table.Td>
                      <Stack gap={2}>
                        <Text fw={700} size="sm">
                          {mw.name || "Unnamed"}
                        </Text>
                        <Code
                          color="blue"
                          variant="light"
                          style={{ fontSize: 10 }}
                        >
                          {mw.id}
                        </Code>
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" radius="sm">
                        {mw.type}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text
                        size="xs"
                        c="dimmed"
                        truncate="end"
                        style={{ maxWidth: 300 }}
                      >
                        {JSON.stringify(mw.config)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap="xs" justify="flex-end">
                        <Tooltip label="Edit">
                          <ActionIcon
                            variant="subtle"
                            color="blue"
                            onClick={() => startEdit(mw)}
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
                                  "Are you sure you want to delete this middleware?",
                                )
                              ) {
                                deleteMutation.mutate(mw.id);
                              }
                            }}
                          >
                            <IconTrash size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Group>
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
        title={editingMW?.id ? "Edit Middleware" : "Add Middleware"}
        radius="lg"
        size="lg"
      >
        <Stack gap="md">
          <TextInput
            label="Friendly Name"
            placeholder="Global Rate Limit"
            value={editingMW?.name || ""}
            onChange={(e) =>
              editingMW &&
              setEditingMW({ ...editingMW, name: e.currentTarget.value })
            }
            radius="md"
            size="md"
          />

          <Select
            label="Type"
            data={[
              { label: "Rate Limiting", value: "ratelimit" },
              { label: "In-Flight Requests (conn limit)", value: "inflightreq" },
              { label: "Buffering (max body)", value: "buffering" },
              { label: "Authentication", value: "auth" },
              { label: "Header Manipulation", value: "headers" },
              { label: "Path Rewrite", value: "rewrite" },
              { label: "Add Prefix", value: "addprefix" },
              { label: "Strip Prefix", value: "stripprefix" },
              { label: "Strip Prefix Regex", value: "stripprefixregex" },
              { label: "Replace Path", value: "replacepath" },
              { label: "Replace Path Regex", value: "replacepathregex" },
              { label: "Gzip Compression", value: "compress" },
              { label: "Forward Auth", value: "forwardauth" },
              { label: "CORS", value: "cors" },
              { label: "IP Filter", value: "ipfilter" },
              { label: "Response Cache", value: "cache" },
              { label: "gRPC-Web", value: "grpcweb" },
              { label: "Custom Errors", value: "errors" },
              { label: "Retry", value: "retry" },
              { label: "Access Logging", value: "accesslog" },
              { label: "Prometheus Metrics", value: "metrics" },
            ]}
            value={editingMW?.type || "ratelimit"}
            onChange={(val) =>
              editingMW &&
              setEditingMW({ ...editingMW, type: val || "ratelimit" })
            }
            radius="md"
          />

          <Tabs defaultValue="config" variant="pills" radius="md">
            <Tabs.List mb="md">
              <Tabs.Tab value="config" leftSection={<IconSettings size={14} />}>
                Config
              </Tabs.Tab>
              <Tabs.Tab value="raw" leftSection={<IconCode size={14} />}>
                Raw JSON
              </Tabs.Tab>
            </Tabs.List>

            <Tabs.Panel value="config">
              <Card withBorder radius="md">
                <MiddlewareConfigEditor
                  type={editingMW?.type || "ratelimit"}
                  config={editingMW?.config || {}}
                  onChange={(config) =>
                    editingMW && setEditingMW({ ...editingMW, config })
                  }
                />
              </Card>
            </Tabs.Panel>

            <Tabs.Panel value="raw">
              <JsonInput
                label="Configuration (JSON)"
                placeholder='{ "requests_per_minute": "100", "burst": "20" }'
                validationError="Invalid JSON"
                formatOnBlur
                autosize
                minRows={4}
                value={JSON.stringify(editingMW?.config || {}, null, 2)}
                onChange={(val) => {
                  try {
                    const parsed = JSON.parse(val);
                    if (editingMW)
                      setEditingMW({ ...editingMW, config: parsed });
                  } catch (e) {}
                }}
                radius="md"
              />

              <Group gap="xs" mt="xs">
                <IconInfoCircle size={14} color="blue" />
                <Text size="xs" c="dimmed">
                  {editingMW?.type === "ratelimit" &&
                    "Keys: requests_per_minute, burst, per_ip (true/false), storage (local/redis)"}
                  {editingMW?.type === "inflightreq" &&
                    "Keys: amount (required), per_ip (true/false)"}
                  {editingMW?.type === "buffering" &&
                    "Keys: max_request_body_bytes (required)"}
                  {editingMW?.type === "auth" &&
                    "Keys: type (jwt/apikey/basic); jwt: issuer, audience, secret; apikey: header, key_X=value; basic: username, password, users (user:pass,), realm"}
                  {editingMW?.type === "headers" &&
                    "Keys: sts_seconds, sts_include_subdomains, sts_preload, force_sts_header; add_request_X, set_request_X, add_response_X, set_response_X, del_request_X, del_response_X"}
                  {editingMW?.type === "rewrite" &&
                    "Keys: path, pattern, replacement, query_X"}
                  {editingMW?.type === "addprefix" && "Keys: prefix"}
                  {editingMW?.type === "stripprefix" &&
                    "Keys: prefixes (comma separated)"}
                  {editingMW?.type === "stripprefixregex" && "Keys: regex"}
                  {editingMW?.type === "replacepath" && "Keys: path"}
                  {editingMW?.type === "replacepathregex" &&
                    "Keys: pattern, replacement"}
                  {editingMW?.type === "cors" &&
                    "Keys: allowed_origins, allowed_methods, allowed_headers, exposed_headers, allow_credentials (true/false), max_age"}
                  {editingMW?.type === "compress" &&
                    "Keys: min_response_body_bytes (1024), excluded_content_types, included_content_types, max_buffer_bytes"}
                  {editingMW?.type === "forwardauth" &&
                    "Keys: address (required), auth_response_headers, auth_request_headers, trust_forward_header, forward_body, preserve_request_method, max_body_size, tls_insecure_skip_verify"}
                  {editingMW?.type === "grpcweb" && "No config needed"}
                  {editingMW?.type === "errors" &&
                    "Keys: status_codes (comma separated), page_404, page_500, etc."}
                  {editingMW?.type === "retry" && "Keys: attempts"}
                </Text>
              </Group>
            </Tabs.Panel>
          </Tabs>

          <Button
            onClick={handleSave}
            radius="md"
            mt="md"
            loading={mutation.isPending}
            disabled={!editingMW?.id}
          >
            Save Middleware
          </Button>
        </Stack>
      </Modal>
    </Stack>
  );
}
