import React, { useState } from "react";
import {
  Card,
  Stack,
  TextInput,
  PasswordInput,
  Select,
  Button,
  Group,
  Text,
  Title,
  Alert,
  List,
  ThemeIcon,
  Badge,
  SimpleGrid,
  Fieldset,
} from "@mantine/core";
import {
  IconWorld,
  IconShieldCheck,
  IconShieldX,
  IconInfoCircle,
  IconCheck,
  IconX,
  IconLock,
  IconBolt,
  IconCopy,
  IconExternalLink,
} from "@tabler/icons-react";
import { useClipboard } from "@mantine/hooks";
import { validateCORS } from "../../hooks/api";
import type { ValidateCORSResponse } from "../../types/gateon";

const CORSValidator: React.FC = () => {
  const [url, setUrl] = useState("");
  const [origin, setOrigin] = useState("");
  const [method, setMethod] = useState("GET");
  const [headers, setHeaders] = useState("");
  const [bearerToken, setBearerToken] = useState("");
  const [acrm, setAcrm] = useState("POST");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ValidateCORSResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const clipboard = useClipboard({ timeout: 2000 });

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
        url: url.trim(),
        origin: origin.trim(),
        method,
        headers: headerMap,
        auth_bearer_token: bearerToken.trim(),
      });
      setResult(res);
    } catch (err: any) {
      setError(err.message || "Failed to validate CORS");
    } finally {
      setLoading(false);
    }
  };

  const applySuggestion = (suggestion: string) => {
    if (suggestion.startsWith("Add header: ")) {
      const header = suggestion.replace("Add header: ", "");
      if (!headers.includes(header)) {
        setHeaders(headers ? `${headers}, ${header}` : header);
      }
    } else if (suggestion.includes("Bearer Token")) {
      // Focus the token field or show a message?
      // Since it's a PasswordInput, maybe just set a dummy if they want to test?
      // But user should provide their own.
    }
  };

  const copyAsCurl = () => {
    if (!url) return;
    let curl = `curl -X ${method} "${url}" \\\n  -H "Origin: ${origin || 'http://localhost'}"`;
    
    if (bearerToken) {
      curl += ` \\\n  -H "Authorization: Bearer ${bearerToken}"`;
    }

    if (method === "OPTIONS") {
      curl += ` \\\n  -H "Access-Control-Request-Method: ${acrm}"`;
      if (headers) {
        curl += ` \\\n  -H "Access-Control-Request-Headers: ${headers}"`;
      }
    } else if (headers) {
      headers.split(",").forEach(h => {
        const trimmed = h.trim();
        if (trimmed) curl += ` \\\n  -H "${trimmed}: test-value"`;
      });
    }

    clipboard.copy(curl);
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

          <Fieldset legend="Request Parameters" variant="default" radius="md">
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
              <TextInput
                label="Target URL"
                placeholder="https://your-gateon.com/api/v1/resource"
                value={url}
                onChange={(e) => setUrl(e.currentTarget.value)}
                required
                description="Gateon will use this to match a route"
              />
              <TextInput
                label="Origin"
                placeholder="https://your-frontend.com"
                value={origin}
                onChange={(e) => setOrigin(e.currentTarget.value)}
                required
                description="The Origin header sent by the browser"
              />
              <Select
                label="HTTP Method"
                data={["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}
                value={method}
                onChange={(val) => setMethod(val || "GET")}
              />
              <PasswordInput
                label="Auth Bearer Token (Optional)"
                placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6..."
                value={bearerToken}
                onChange={(e) => setBearerToken(e.currentTarget.value)}
                leftSection={<IconLock size={16} />}
                description="Automatically adds Authorization: Bearer <token>"
              />
              {method === "OPTIONS" ? (
                <Select
                  label="Preflight Method (ACRM)"
                  data={["GET", "POST", "PUT", "PATCH", "DELETE"]}
                  value={acrm}
                  onChange={(val) => setAcrm(val || "POST")}
                  description="Access-Control-Request-Method"
                />
              ) : (
                <TextInput
                  label="Custom Request Headers (Optional)"
                  placeholder="X-Custom-Header, X-Other"
                  value={headers}
                  onChange={(e) => setHeaders(e.currentTarget.value)}
                  description="Comma-separated list of headers to simulate"
                />
              )}
              {method === "OPTIONS" && (
                <TextInput
                  label="Preflight Headers (ACRH)"
                  placeholder="Content-Type, Authorization, X-Custom"
                  value={headers}
                  onChange={(e) => setHeaders(e.currentTarget.value)}
                  description="Access-Control-Request-Headers"
                />
              )}
            </SimpleGrid>
          </Fieldset>

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
            <Stack gap="sm">
               <Text fw={700} size="lg" style={{ whiteSpace: 'pre-wrap' }}>{result.message}</Text>
               <Group gap="xs">
                 <Button 
                   variant="subtle" 
                   color={result.is_allowed ? "teal" : "red"} 
                   size="compact-xs" 
                   leftSection={clipboard.copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
                   onClick={copyAsCurl}
                 >
                   {clipboard.copied ? "Copied!" : "Copy as cURL"}
                 </Button>
                 {result.route_id && (
                    <Badge variant="light" color="gray" size="sm" leftSection={<IconExternalLink size={10} />}>
                      Route ID: {result.route_id}
                    </Badge>
                 )}
               </Group>
            </Stack>
          </Alert>

          {result.suggestions && result.suggestions.length > 0 && (
            <Alert
              icon={<IconBolt size={20} />}
              title="Gateon Smart Analysis"
              color="blue"
              radius="lg"
              variant="light"
            >
              <Text size="sm" mb="xs" fw={500}>
                Based on the matched route and its middlewares, Gateon suggests the following for your test:
              </Text>
              <List size="sm" spacing="xs">
                {result.suggestions.map((s, i) => (
                  <List.Item key={i}>
                    <Group gap="xs">
                      <Text size="sm">{s}</Text>
                      {s.startsWith("Add header: ") && (
                        <Button 
                          variant="subtle" 
                          size="compact-xs" 
                          p={0} 
                          onClick={() => applySuggestion(s)}
                        >
                          [Apply]
                        </Button>
                      )}
                    </Group>
                  </List.Item>
                ))}
              </List>
            </Alert>
          )}

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
                    <Card withBorder radius="lg" p="md">
                      <Title order={4} mb="sm">Middleware Configuration</Title>
                      <Stack gap="xs">
                        {Object.entries(result.middleware_config).map(([k, v]) => (
                          <Group key={k} justify="space-between" wrap="nowrap">
                            <Text size="xs" fw={700}>{k.replace(/_/g, " ").toUpperCase()}</Text>
                            <Text size="xs" ff="monospace" truncate>{v || "(empty)"}</Text>
                          </Group>
                        ))}
                      </Stack>
                    </Card>
                )}
            </Stack>
          </SimpleGrid>

          {!result.is_allowed && (
             <Alert 
               variant="light" 
               color="red" 
               title="How to fix this?" 
               icon={<IconInfoCircle size={18} />}
               radius="md"
             >
                <Stack gap="xs" mt="sm">
                    {result.message.includes("No route matched") && (
                        <Text size="sm">
                            Make sure the <b>URL</b> and <b>Host</b> match one of your defined routes. 
                            Check your route <b>Rules</b> (Host, Path, PathPrefix) and <b>Entrypoints</b>.
                        </Text>
                    )}
                    {result.message.includes("Origin") && (
                        <Text size="sm">
                            Add <b>{origin || "the origin"}</b> to the <b>Allowed Origins</b> list in your CORS middleware.
                        </Text>
                    )}
                    {result.message.includes("Method") && (
                        <Text size="sm">
                            Add the requested method to the <b>Allowed Methods</b> list in your CORS middleware.
                        </Text>
                    )}
                    {result.message.includes("Header") && (
                        <Text size="sm">
                            Add the requested header to the <b>Allowed Headers</b> list in your CORS middleware.
                        </Text>
                    )}
                    {result.message.includes("entrypoint context") && (
                        <Text size="sm">
                            This route is restricted to specific entrypoints. Ensure you are accessing it through the correct port/protocol.
                        </Text>
                    )}
                </Stack>
             </Alert>
          )}
        </Stack>
      )}
    </Stack>
  );
};

export default CORSValidator;
