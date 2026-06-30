import React, { useState } from "react";
import {
  Card,
  Stack,
  TextInput,
  Select,
  Button,
  Group,
  Text,
  Title,
  Alert,
  List,
  ThemeIcon,
  Divider,
  Paper,
  Code,
  Badge,
  SimpleGrid,
} from "@mantine/core";
import {
  IconWorld,
  IconShieldCheck,
  IconShieldX,
  IconInfoCircle,
  IconCheck,
  IconX,
} from "@tabler/icons-react";
import { validateCORS } from "../../hooks/api";
import type { ValidateCORSResponse } from "../../types/gateon";

const CORSValidator: React.FC = () => {
  const [url, setUrl] = useState("");
  const [origin, setOrigin] = useState("");
  const [method, setMethod] = useState("GET");
  const [headers, setHeaders] = useState("");
  const [acrm, setAcrm] = useState("POST");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ValidateCORSResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleValidate = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const headerMap: Record<string, string> = {};
      if (method === "OPTIONS") {
        headerMap["Access-Control-Request-Method"] = acrm;
        if (headers) {
           headerMap["Access-Control-Request-Headers"] = headers;
        }
      } else {
        // For regular requests, we might want to simulate some headers
        if (headers) {
           headers.split(",").forEach(h => {
             const trimmed = h.trim();
             if (trimmed) headerMap[trimmed] = "test-value";
           });
        }
      }

      const res = await validateCORS({
        url,
        origin,
        method,
        headers: headerMap,
      });
      setResult(res);
    } catch (err: any) {
      setError(err.message || "Failed to validate CORS");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Stack gap="md">
      <Card withBorder radius="lg" p="xl">
        <Stack gap="lg">
          <Group justify="space-between">
            <Stack gap={0}>
              <Title order={3}>CORS Validator</Title>
              <Text c="dimmed" size="sm">
                Test how Gateon will handle CORS requests for a specific URL and Origin.
              </Text>
            </Stack>
            <ThemeIcon size={44} radius="md" variant="light" color="blue">
              <IconWorld size={24} />
            </ThemeIcon>
          </Group>

          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <TextInput
              label="Target URL"
              placeholder="https://your-gateon.com/api/v1/resource"
              value={url}
              onChange={(e) => setUrl(e.currentTarget.value)}
              required
            />
            <TextInput
              label="Origin"
              placeholder="https://your-frontend.com"
              value={origin}
              onChange={(e) => setOrigin(e.currentTarget.value)}
              required
            />
            <Select
              label="HTTP Method"
              data={["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}
              value={method}
              onChange={(val) => setMethod(val || "GET")}
            />
            {method === "OPTIONS" ? (
               <Select
                label="Preflight Method (ACRM)"
                data={["GET", "POST", "PUT", "PATCH", "DELETE"]}
                value={acrm}
                onChange={(val) => setAcrm(val || "POST")}
              />
            ) : (
              <TextInput
                label="Request Headers (comma separated)"
                placeholder="Content-Type, Authorization, X-Custom"
                value={headers}
                onChange={(e) => setHeaders(e.currentTarget.value)}
              />
            )}
            {method === "OPTIONS" && (
               <TextInput
                label="Preflight Headers (ACRH)"
                placeholder="Content-Type, Authorization, X-Custom"
                value={headers}
                onChange={(e) => setHeaders(e.currentTarget.value)}
              />
            )}
          </SimpleGrid>

          <Button
            onClick={handleValidate}
            loading={loading}
            size="md"
            radius="md"
            leftSection={<IconShieldCheck size={18} />}
          >
            Validate CORS Configuration
          </Button>
        </Stack>
      </Card>

      {error && (
        <Alert icon={<IconInfoCircle size={16} />} title="Error" color="red" radius="md">
          {error}
        </Alert>
      )}

      {result && (
        <Stack gap="md">
          <Alert
            icon={result.is_allowed ? <IconShieldCheck size={20} /> : <IconShieldX size={20} />}
            title={result.is_allowed ? "Allowed" : "Blocked"}
            color={result.is_allowed ? "teal" : "red"}
            radius="lg"
            variant="light"
          >
            <Text fw={700} size="lg">{result.message}</Text>
          </Alert>

          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
            <Card withBorder radius="lg" p="md">
              <Title order={4} mb="sm">Diagnostic Checks</Title>
              <List
                spacing="xs"
                size="sm"
                center
                icon={
                  <ThemeIcon color="teal" size={20} radius="xl">
                    <IconCheck size={12} />
                  </ThemeIcon>
                }
              >
                {result.checks.map((check, i) => {
                  const isFailed = check.includes("FAILED");
                  return (
                    <List.Item
                      key={i}
                      icon={
                        <ThemeIcon color={isFailed ? "red" : "teal"} size={20} radius="xl">
                          {isFailed ? <IconX size={12} /> : <IconCheck size={12} />}
                        </ThemeIcon>
                      }
                    >
                      {check}
                    </List.Item>
                  );
                })}
              </List>
            </Card>

            <Stack gap="md">
                <Card withBorder radius="lg" p="md">
                  <Title order={4} mb="sm">Expected Response Headers</Title>
                  {Object.keys(result.response_headers).length > 0 ? (
                    <Stack gap="xs">
                      {Object.entries(result.response_headers).map(([k, v]) => (
                        <Group key={k} justify="space-between" wrap="nowrap">
                          <Text size="xs" fw={700} style={{ fontFamily: "monospace" }}>{k}</Text>
                          <Badge variant="dot" size="sm" style={{ textTransform: "none", fontFamily: "monospace" }}>{v}</Badge>
                        </Group>
                      ))}
                    </Stack>
                  ) : (
                    <Text size="sm" c="dimmed">No CORS headers will be added to the response.</Text>
                  )}
                </Card>

                {result.middleware_config && (
                    <Card withBorder radius="lg" p="md" bg="gray.0">
                      <Title order={4} mb="sm">Middleware Configuration</Title>
                      <Stack gap="xs">
                        {Object.entries(result.middleware_config).map(([k, v]) => (
                          <Group key={k} justify="space-between" wrap="nowrap">
                            <Text size="xs" fw={700}>{k.replace(/_/g, " ").toUpperCase()}</Text>
                            <Text size="xs" ff="monospace" c="dimmed" truncate>{v || "(empty)"}</Text>
                          </Group>
                        ))}
                      </Stack>
                    </Card>
                )}
            </Stack>
          </SimpleGrid>

          {!result.is_allowed && (
             <Paper withBorder p="md" radius="md" bg="var(--mantine-color-red-0)">
                <Title order={5} c="red" mb="xs">How to fix this?</Title>
                <Text size="sm">
                  To allow this request, you need to update your CORS middleware configuration.
                  {result.message.includes("Origin") && " Add the origin to 'Allowed Origins'."}
                  {result.message.includes("Method") && " Add the method to 'Allowed Methods'."}
                  {result.message.includes("Header") && " Add the header to 'Allowed Headers'."}
                </Text>
             </Paper>
          )}
        </Stack>
      )}
    </Stack>
  );
};

export default CORSValidator;
