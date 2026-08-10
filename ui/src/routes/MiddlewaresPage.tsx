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
  Box,
  Divider,
  Center,
  Menu,
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
  IconDotsVertical,
  IconSearch,
} from "@tabler/icons-react";
import { useDisclosure } from "@mantine/hooks";
import { useIsMobile } from "../hooks/useMobile";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import type { Middleware } from "../types/gateon";
import { useMiddlewares, useMiddlewareRoutes, apiFetch, getApiErrorMessage } from "../hooks/useGateon";
import { usePermissions } from "../hooks/usePermissions";
import { useTableDensity } from "../hooks/useTableDensity";
import { MiddlewareConfigEditor } from "../components/MiddlewareConfig";
import { QueryError } from "../components/QueryError";

export default function MiddlewaresPage() {
  const { canWrite } = usePermissions();
  const isMobile = useIsMobile();
  const density = useTableDensity();
  const queryClient = useQueryClient();
  const [opened, { open, close }] = useDisclosure(false);
  const [deleteTarget, setDeleteTarget] = useState<Middleware | null>(null);
  const [editingMW, setEditingMW] = useState<Middleware | null>(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const { data: routesData } = useMiddlewareRoutes(deleteTarget?.id ?? null);
  const affectedRoutes = routesData?.routes ?? [];

  const { data, isLoading, isError, error, refetch } = useMiddlewares({
    page: page - 1,
    pageSize: pageSize,
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
    onError: (err: unknown) => {
      notifications.show({
        title: "Error Saving Middleware",
        message: getApiErrorMessage(err),
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
      return true;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["middlewares"] });
      setDeleteTarget(null);
      notifications.show({
        title: "Middleware Deleted",
        message: "The middleware has been removed.",
        color: "blue",
      });
    },
    onError: (err: unknown) => {
      notifications.show({
        title: "Error Deleting Middleware",
        message: getApiErrorMessage(err),
        color: "red",
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
  const totalCount = data?.totalCount || 0;

  return (
    <Stack gap="xl">
      <Group justify="space-between" wrap="wrap" gap="md">
        <div>
          <Title order={2} fw={800} style={{ letterSpacing: -1 }}>
            Middlewares ({totalCount})
          </Title>
          <Text c="dimmed" size="sm">
            Define reusable middleware policies for your routes.
          </Text>
        </div>
        <Group wrap={isMobile ? "wrap" : "nowrap"} style={{ flex: isMobile ? "1 1 100%" : "none" }}>
          <TextInput
            placeholder="Search middlewares..."
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
          {canWrite && (
            <Button
              leftSection={<IconPlus size={16} />}
              onClick={startAdd}
              radius="md"
              fullWidth={isMobile}
            >
              Add Middleware
            </Button>
          )}
        </Group>
      </Group>

      <Card withBorder padding={isMobile ? "sm" : 0} radius="lg" shadow="xs">
        {isMobile ? (
          <Stack gap="md">
            {isError ? (
              <QueryError error={error} what="middlewares" onRetry={() => refetch()} />
            ) : isLoading ? (
               <Text ta="center" py="xl" c="dimmed">Loading...</Text>
            ) : middlewares.length === 0 ? (
               <Center py="xl">
                 <Stack align="center" gap="xs">
                   <IconSettingsAutomation size={40} color="dimmed" />
                   <Text c="dimmed">No middlewares configured</Text>
                 </Stack>
               </Center>
            ) : (
              middlewares.map((mw) => (
                <Card key={mw.id} withBorder radius="md" p="md">
                  <Stack gap="xs">
                    <Group justify="space-between" align="flex-start">
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
                      <Group gap={4}>
                        <Badge size="xs" variant="light" radius="sm">
                          {mw.type}
                        </Badge>
                        {canWrite && (
                          <Menu shadow="md" position="bottom-end">
                            <Menu.Target>
                              <ActionIcon variant="subtle" color="gray">
                                <IconDotsVertical size={16} />
                              </ActionIcon>
                            </Menu.Target>
                            <Menu.Dropdown>
                              <Menu.Item
                                leftSection={<IconPencil size={14} />}
                                onClick={() => startEdit(mw)}
                              >
                                Edit
                              </Menu.Item>
                              <Menu.Divider />
                              <Menu.Item
                                leftSection={<IconTrash size={14} />}
                                color="red"
                                onClick={() => setDeleteTarget(mw)}
                              >
                                Delete
                              </Menu.Item>
                            </Menu.Dropdown>
                          </Menu>
                        )}
                      </Group>
                    </Group>
                    <Divider variant="dashed" />
                    <Box>
                      <Text size="xs" c="dimmed" fw={700} style={{ textTransform: "uppercase" }}>Config Preview</Text>
                      <Text size="xs" c="dimmed" lineClamp={2} style={{ wordBreak: 'break-all' }}>
                        {mw.type === "wasm"
                          ? mw.wasmBlob
                            ? `WASM Module (${Math.round((mw.wasmBlob.length * 0.75) / 1024)} KB)`
                            : "No module uploaded"
                          : JSON.stringify(mw.config)}
                      </Text>
                    </Box>
                  </Stack>
                </Card>
              ))
            )}
          </Stack>
        ) : (
          <ScrollArea>
            <Table {...density}>
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
                          {mw.type === "wasm"
                            ? mw.wasmBlob
                              ? `WASM Module (${Math.round((mw.wasmBlob.length * 0.75) / 1024)} KB)`
                              : "No module uploaded"
                            : JSON.stringify(mw.config)}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        {canWrite && (
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
                                onClick={() => setDeleteTarget(mw)}
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
              { label: "Forwarded Headers (X-Forwarded-Proto)", value: "forwardedheaders" },
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
              { label: "WAF (Coraza)", value: "waf" },
              { label: "Cloudflare Turnstile", value: "turnstile" },
              { label: "GeoIP", value: "geoip" },
              { label: "HMAC Signature", value: "hmac" },
              { label: "WebAssembly (WASM)", value: "wasm" },
              { label: "Response Cache", value: "cache" },
              { label: "Body Transformation", value: "transform" },
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
            <Tabs.List mb="md" className="scrollable-tabs-list">
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
                  wasmBlob={editingMW?.wasmBlob}
                  onWasmBlobChange={(blob) =>
                    editingMW && setEditingMW({ ...editingMW, wasmBlob: blob })
                  }
                />
              </Card>
            </Tabs.Panel>

            <Tabs.Panel value="raw">
              <JsonInput
                label="Configuration (JSON)"
                placeholder='{ "requestsPerMinute": "100", "burst": "20" }'
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
                    "Keys: requestsPerMinute, burst, perIp (true/false), storage (local/redis)"}
                  {editingMW?.type === "inflightreq" &&
                    "Keys: amount (required), perIp (true/false)"}
                  {editingMW?.type === "buffering" &&
                    "Keys: maxRequestBodyBytes (required)"}
                  {editingMW?.type === "auth" &&
                    "Keys: type (jwt/oidc/oauth2/paseto/apikey/basic); jwt: issuer, audience, jwksUrl, secret; oidc: issuer, audience; oauth2: introspectionUrl, clientId, clientSecret; paseto: secret; apikey: header, key_X=value; basic: username, password, users (user:pass,), realm"}
                  {editingMW?.type === "headers" &&
                    "Keys: stsSeconds, stsIncludeSubdomains, stsPreload, forceStsHeader; addRequest_X, setRequest_X, addResponse_X, setResponse_X, delRequest_X, delResponse_X"}
                  {editingMW?.type === "forwardedheaders" &&
                    "Keys: proto (http/https — force X-Forwarded-Proto), trustForwardHeader (true/false — honor inbound X-Forwarded-Proto on this route even when the peer is outside GATEON_TRUSTED_PROXIES)"}
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
                    "Keys: allowedOrigins, allowedMethods, allowedHeaders, exposedHeaders, allowCredentials (true/false), maxAge"}
                  {editingMW?.type === "compress" &&
                    "Keys: algorithm (auto/gzip/br), minResponseBodyBytes (1024), excludedContentTypes, includedContentTypes, maxBufferBytes"}
                  {editingMW?.type === "geoip" &&
                    "Keys: dbPath (required), header (default X-Forwarded-For), allowCountries, denyCountries, blockStatusCode"}
                  {editingMW?.type === "forwardauth" &&
                    "Keys: address (required), authResponseHeaders, authRequestHeaders, trustForwardHeader, forwardBody, preserveRequestMethod, maxBodySize, tlsInsecureSkipVerify"}
                  {editingMW?.type === "grpcweb" &&
                    "Required for grpc routes called from browsers. No config. Add to route and attach this middleware."}
                  {editingMW?.type === "errors" &&
                    "Keys: statusCodes (comma separated), page_404, page_500, etc."}
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
            disabled={!editingMW?.name}
          >
            Save Middleware
          </Button>
        </Stack>
      </Modal>

      <Modal
        opened={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        title="Delete Middleware"
        radius="lg"
      >
        <Stack gap="md">
          {deleteTarget && (
            <>
              <Text size="sm">
                Delete &quot;{deleteTarget.name || deleteTarget.id}&quot;? This
                will remove it from all routes that use it.
              </Text>
              {affectedRoutes.length > 0 && (
                <Stack gap="xs">
                  <Text size="sm" fw={600}>
                    Used by {affectedRoutes.length} route
                    {affectedRoutes.length !== 1 ? "s" : ""}:
                  </Text>
                  <ScrollArea h={120} type="auto">
                    {affectedRoutes.map((r) => (
                      <Code
                        key={r.id}
                        fz="xs"
                        variant="light"
                        display="block"
                        mb={4}
                      >
                        {r.id} — {r.rule}
                      </Code>
                    ))}
                  </ScrollArea>
                </Stack>
              )}
              <Group justify="flex-end" mt="md">
                <Button
                  variant="default"
                  radius="md"
                  onClick={() => setDeleteTarget(null)}
                >
                  Cancel
                </Button>
                <Button
                  color="red"
                  radius="md"
                  loading={deleteMutation.isPending}
                  onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
                >
                  Delete
                </Button>
              </Group>
            </>
          )}
        </Stack>
      </Modal>
    </Stack>
  );
}
