import React from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  Group,
  Switch,
  NumberInput,
  TextInput,
  Divider,
  ThemeIcon,
  TagsInput,
  SimpleGrid,
  Paper,
  ActionIcon,
  PasswordInput,
  Select,
  Checkbox,
  Button,
} from "@mantine/core";
import {
  IconShieldLock,
  IconGhost,
  IconHourglassLow,
  IconActivity,
  IconBrain,
  IconLockSearch,
  IconDatabase,
  IconTrash,
  IconPlus,
} from "@tabler/icons-react";
import type { GlobalConfig, SecurityAdvancedConfig, IPReputationIntegration } from "../../types/gateon";

interface SecurityAdvancedSettingsCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

export const SecurityAdvancedSettingsCard: React.FC<SecurityAdvancedSettingsCardProps> = ({
  config,
  onChange,
  disabled,
}) => {
  const security = config.securityAdvanced || ({} as SecurityAdvancedConfig);

  const updateSection = (section: keyof SecurityAdvancedConfig, value: any) => {
    onChange({
      ...config,
      securityAdvanced: {
        ...security,
        [section]: {
          ...(security[section] || {}),
          ...value,
        },
      },
    });
  };

  const updateIntegration = (index: number, val: Partial<IPReputationIntegration>) => {
    const integrations = [...(security.ipReputation?.integrations || [])];
    integrations[index] = { ...integrations[index], ...val };
    updateSection("ipReputation", { integrations });
  };

  const addIntegration = () => {
    const integrations = [...(security.ipReputation?.integrations || [])];
    integrations.push({
      id: Math.random().toString(36).substring(7),
      name: "AbuseIPDB",
      type: "abuseipdb",
      apiKey: "",
      enabled: true,
      confidenceThreshold: 80,
    });
    updateSection("ipReputation", { integrations });
  };

  const removeIntegration = (index: number) => {
    const integrations = [...(security.ipReputation?.integrations || [])];
    integrations.splice(index, 1);
    updateSection("ipReputation", { integrations });
  };

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="xl">
        <Group justify="space-between">
          <Group>
            <ThemeIcon size="xl" radius="md" variant="light" color="blue">
              <IconShieldLock size={24} />
            </ThemeIcon>
            <Stack gap={0}>
              <Title order={3}>Advanced Security</Title>
              <Text size="sm" c="dimmed">
                Configure active defense, deception, and behavioral analysis.
              </Text>
            </Stack>
          </Group>
        </Group>

        <Divider label="Deception Technology" labelPosition="left" />
        <Paper withBorder p="md" radius="md">
          <Stack gap="md">
            <Group justify="space-between">
              <Stack gap={0} flex={1}>
                <Group>
                  <IconGhost size={20} color="var(--mantine-color-blue-filled)" />
                  <Text fw={500}>Honey-Potting & Deception</Text>
                </Group>
                <Text size="xs" c="dimmed">
                  Deploy deceptive traps and honeypots to identify and block attackers early in their reconnaissance phase.
                </Text>
              </Stack>
              <Switch
                id="deception-enabled-switch"
                label="Honey-Potting & Deception"
                checked={security.deception?.enabled}
                onChange={(e) => updateSection("deception", { enabled: e.currentTarget.checked })}
                disabled={disabled}
              />
            </Group>
            {security.deception?.enabled && (
              <Stack gap="sm" pl="lg">
                <TagsInput
                  id="deception-honeypot-paths"
                  label="Honeypot Paths"
                  description="Accessing these paths triggers an immediate block. Recommended: /.env, /wp-admin, /config.php"
                  placeholder="/.env, /wp-admin, /_backup"
                  value={security.deception?.honeypotPaths || []}
                  onChange={(val) => updateSection("deception", { honeypotPaths: val })}
                  disabled={disabled}
                />
                <Group justify="space-between" mt="xs">
                  <Stack gap={0}>
                    <Text size="sm" fw={500}>Inject Invisible Links</Text>
                    <Text size="xs" c="dimmed">Inject hidden links into HTML responses to trap automated crawlers.</Text>
                  </Stack>
                  <Switch
                    checked={security.deception?.injectInvisibleLinks}
                    onChange={(e) => updateSection("deception", { injectInvisibleLinks: e.currentTarget.checked })}
                    disabled={disabled}
                  />
                </Group>
                {security.deception?.injectInvisibleLinks && (
                  <>
                    <TagsInput
                      label="Invisible Link Paths"
                      placeholder="/system-config, /hidden-admin"
                      value={security.deception?.invisibleLinkPaths || []}
                      onChange={(val) => updateSection("deception", { invisibleLinkPaths: val })}
                      disabled={disabled}
                    />
                    <TagsInput
                      label="Honey Forms (POST Targets)"
                      description="Injected hidden forms that block clients if submitted."
                      placeholder="/v1/admin/login, /debug/leak"
                      value={security.deception?.honeyForms || []}
                      onChange={(val) => updateSection("deception", { honeyForms: val })}
                      disabled={disabled}
                    />
                    <SimpleGrid cols={2}>
                      <TextInput
                        label="Canary Header"
                        description="Attractive-looking header injected into response."
                        placeholder="X-Gateon-Internal-Debug"
                        value={security.deception?.canaryHeader || ""}
                        onChange={(e) => updateSection("deception", { canaryHeader: e.currentTarget.value })}
                        disabled={disabled}
                      />
                      <TextInput
                        label="Canary Token"
                        description="The token to watch for in subsequent requests."
                        placeholder="debug-mode-admin-true"
                        value={security.deception?.canaryToken || ""}
                        onChange={(e) => updateSection("deception", { canaryToken: e.currentTarget.value })}
                        disabled={disabled}
                      />
                    </SimpleGrid>
                    <Group justify="space-between">
                      <Text size="sm">Enable Troll Response</Text>
                      <Switch
                        size="sm"
                        checked={security.deception?.enableTrollResponse}
                        onChange={(e) => updateSection("deception", { enableTrollResponse: e.currentTarget.checked })}
                        disabled={disabled}
                      />
                    </Group>
                  </>
                )}
              </Stack>
            )}
          </Stack>
        </Paper>

        <Divider label="Active Mitigation" labelPosition="left" />
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
          <Paper withBorder p="md" radius="md">
            <Stack gap="md">
              <Group justify="space-between">
                <Stack gap={0} flex={1}>
                  <Group>
                    <IconHourglassLow size={20} color="var(--mantine-color-orange-filled)" />
                    <Text fw={500}>Active Tarpitting</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    Slow down suspicious connections to exhaust attacker resources and disrupt automated scans.
                  </Text>
                </Stack>
                <Switch
                  id="tarpit-enabled-switch"
                  label="Active Tarpitting"
                  checked={security.tarpit?.enabled}
                  onChange={(e) => updateSection("tarpit", { enabled: e.currentTarget.checked })}
                  disabled={disabled}
                />
              </Group>
              {security.tarpit?.enabled && (
                <Stack gap="sm">
                  <NumberInput
                    id="tarpit-delay-base"
                    label="Base Delay (ms)"
                    description="Initial delay applied to the first suspicious request. Recommended: 500ms."
                    value={security.tarpit?.delayBaseMs}
                    onChange={(val) => updateSection("tarpit", { delayBaseMs: val })}
                    disabled={disabled}
                    min={0}
                  />
                  <NumberInput
                    label="Max Delay (ms)"
                    description="Maximum delay for repeated suspicious requests. Recommended: 5000ms."
                    value={security.tarpit?.delayMaxMs}
                    onChange={(val) => updateSection("tarpit", { delayMaxMs: val })}
                    disabled={disabled}
                    min={0}
                  />
                  <NumberInput
                    label="Score Threshold"
                    description="Start tarpitting when IP threat score exceeds this. Recommended: 7.0."
                    value={security.tarpit?.scoreThreshold}
                    onChange={(val) => updateSection("tarpit", { scoreThreshold: val })}
                    disabled={disabled}
                    decimalScale={1}
                  />
                </Stack>
              )}
            </Stack>
          </Paper>

          <Paper withBorder p="md" radius="md">
            <Stack gap="md">
              <Group justify="space-between">
                <Stack gap={0} flex={1}>
                  <Group>
                    <IconLockSearch size={20} color="var(--mantine-color-teal-filled)" />
                    <Text fw={500}>PoW Challenge</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    Force clients to solve a computational puzzle to mitigate Layer 7 DDoS and scraping.
                  </Text>
                </Stack>
                <Switch
                  checked={security.pow?.enabled}
                  onChange={(e) => updateSection("pow", { enabled: e.currentTarget.checked })}
                  disabled={disabled}
                />
              </Group>
              {security.pow?.enabled && (
                <Stack gap="sm">
                  <NumberInput
                    label="Difficulty"
                    description="Puzzle complexity. 3-5 is recommended (invisible to humans, expensive for bots)."
                    value={security.pow?.difficulty}
                    onChange={(val) => updateSection("pow", { difficulty: val })}
                    disabled={disabled}
                    min={1}
                    max={10}
                  />
                  <NumberInput
                    label="Score Threshold"
                    description="Serve challenge when IP threat score exceeds this. Recommended: 5.0."
                    value={security.pow?.scoreThreshold}
                    onChange={(val) => updateSection("pow", { scoreThreshold: val })}
                    disabled={disabled}
                    decimalScale={1}
                  />
                </Stack>
              )}
            </Stack>
          </Paper>
        </SimpleGrid>

        <Divider label="Advanced Analysis & Session Integrity" labelPosition="left" />
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
          <Paper withBorder p="md" radius="md">
            <Stack gap="md">
              <Group justify="space-between">
                <Stack gap={0} flex={1}>
                  <Group>
                    <IconDatabase size={20} color="var(--mantine-color-yellow-filled)" />
                    <Text fw={500}>IP Reputation</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    Sync with global threat feeds to block known malicious actors.
                  </Text>
                </Stack>
                <Switch
                  checked={security.ipReputation?.enabled}
                  onChange={(e) => updateSection("ipReputation", { enabled: e.currentTarget.checked })}
                  disabled={disabled}
                />
              </Group>
              {security.ipReputation?.enabled && (
                <Stack gap="sm">
                  <TagsInput
                    label="Feed URLs"
                    description="URLs of IP reputation feeds (text/plain). Recommended: AbuseIPDB, Emerging Threats."
                    placeholder="https://example.com/bad-ips.txt"
                    value={security.ipReputation?.feedUrls || []}
                    onChange={(val) => updateSection("ipReputation", { feedUrls: val })}
                    disabled={disabled}
                  />
                  <SimpleGrid cols={2}>
                    <NumberInput
                      label="Update Interval (h)"
                      description="How often to sync feeds. Recommended: 24h."
                      value={security.ipReputation?.updateIntervalHours}
                      onChange={(val) => updateSection("ipReputation", { updateIntervalHours: val })}
                      disabled={disabled}
                      min={1}
                    />
                    <NumberInput
                      label="Block Threshold"
                      description="Minimum score to block. Recommended: 80.0."
                      value={security.ipReputation?.blockThreshold}
                      onChange={(val) => updateSection("ipReputation", { blockThreshold: val })}
                      disabled={disabled}
                      decimalScale={1}
                    />
                  </SimpleGrid>

                  <Divider label="External Integrations" labelPosition="center" />
                  <Stack gap="xs">
                    {(security.ipReputation?.integrations || []).map((integration, index) => (
                      <Paper key={integration.id || index} withBorder p="sm" radius="sm">
                        <Stack gap="xs">
                          <Group justify="space-between">
                            <Text size="sm" fw={500}>
                              {integration.name || "New Integration"}
                            </Text>
                            <ActionIcon
                              color="red"
                              variant="subtle"
                              onClick={() => removeIntegration(index)}
                              disabled={disabled}
                            >
                              <IconTrash size={16} />
                            </ActionIcon>
                          </Group>
                          <SimpleGrid cols={2}>
                            <TextInput
                              label="Name"
                              value={integration.name}
                              onChange={(e) => updateIntegration(index, { name: e.currentTarget.value })}
                              size="xs"
                              disabled={disabled}
                            />
                            <Select
                              label="Type"
                              data={[
                                { value: "abuseipdb", label: "AbuseIPDB" },
                                { value: "virustotal", label: "VirusTotal" },
                                { value: "alienvault", label: "AlienVault OTX" },
                              ]}
                              value={integration.type}
                              onChange={(val) => updateIntegration(index, { type: val || "" })}
                              size="xs"
                              disabled={disabled}
                            />
                          </SimpleGrid>
                          <PasswordInput
                            label="API Key"
                            value={integration.apiKey}
                            onChange={(e) => updateIntegration(index, { apiKey: e.currentTarget.value })}
                            size="xs"
                            disabled={disabled}
                          />
                          <Group grow>
                            <NumberInput
                              label="Confidence Threshold"
                              description="Score above which to consider IP malicious."
                              value={integration.confidenceThreshold}
                              onChange={(val) => updateIntegration(index, { confidenceThreshold: Number(val) })}
                              size="xs"
                              min={0}
                              max={100}
                              disabled={disabled}
                            />
                            <Checkbox
                              label="Enabled"
                              mt="xl"
                              checked={integration.enabled}
                              onChange={(e) => updateIntegration(index, { enabled: e.currentTarget.checked })}
                              disabled={disabled}
                            />
                          </Group>
                        </Stack>
                      </Paper>
                    ))}
                    <Button
                      variant="light"
                      size="xs"
                      leftSection={<IconPlus size={14} />}
                      onClick={addIntegration}
                      disabled={disabled}
                    >
                      Add Reputation Integration
                    </Button>
                  </Stack>
                </Stack>
              )}
            </Stack>
          </Paper>

          <Paper withBorder p="md" radius="md">
            <Stack gap="md">
              <Group justify="space-between">
                <Stack gap={0} flex={1}>
                  <Group>
                    <IconActivity size={20} color="var(--mantine-color-violet-filled)" />
                    <Text fw={500}>Payload Entropy</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    Detect encrypted malware or data exfiltration by measuring payload randomness.
                  </Text>
                </Stack>
                <Switch
                  checked={security.entropy?.enabled}
                  onChange={(e) => updateSection("entropy", { enabled: e.currentTarget.checked })}
                  disabled={disabled}
                />
              </Group>
              {security.entropy?.enabled && (
                <NumberInput
                  label="Entropy Threshold"
                  description="Block if payload Shannon entropy exceeds this. Recommended: 5.5 - 6.0."
                  value={security.entropy?.threshold}
                  onChange={(val) => updateSection("entropy", { threshold: val })}
                  disabled={disabled}
                  decimalScale={2}
                  step={0.1}
                />
              )}
            </Stack>
          </Paper>

          <Paper withBorder p="md" radius="md">
            <Stack gap="md">
              <Group justify="space-between">
                <Stack gap={0} flex={1}>
                  <Group>
                    <IconBrain size={20} color="var(--mantine-color-cyan-filled)" />
                    <Text fw={500}>Behavioral Analysis</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    Detect anomalies like impossible travel or invalid request sequences.
                  </Text>
                </Stack>
                <Switch
                  checked={security.behavioral?.enabled}
                  onChange={(e) => updateSection("behavioral", { enabled: e.currentTarget.checked })}
                  disabled={disabled}
                />
              </Group>
              {security.behavioral?.enabled && (
                <Stack gap="xs">
                  <Group justify="space-between">
                    <Stack gap={0}>
                      <Text size="sm">Impossible Travel Detection</Text>
                      <Text size="xs" c="dimmed">Block logins from distant locations within an impossible timeframe.</Text>
                    </Stack>
                    <Switch
                      size="sm"
                      checked={security.behavioral?.enableImpossibleTravel}
                      onChange={(e) => updateSection("behavioral", { enableImpossibleTravel: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                  </Group>
                  <Group justify="space-between">
                    <Stack gap={0}>
                      <Text size="sm">Sequence Validation</Text>
                      <Text size="xs" c="dimmed">Ensure requests follow a logical order to prevent deep endpoint bypassing.</Text>
                    </Stack>
                    <Switch
                      size="sm"
                      checked={security.behavioral?.enableSequenceValidation}
                      onChange={(e) => updateSection("behavioral", { enableSequenceValidation: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                  </Group>
                </Stack>
              )}
            </Stack>
          </Paper>

          <Paper withBorder p="md" radius="md">
            <Stack gap="md">
              <Group justify="space-between">
                <Stack gap={0} flex={1}>
                  <Group>
                    <IconShieldLock size={20} color="var(--mantine-color-indigo-filled)" />
                    <Text fw={500}>TLS Session Binding</Text>
                  </Group>
                  <Text size="xs" c="dimmed">
                    Bind application sessions to TLS connections to prevent hijacking.
                  </Text>
                </Stack>
                <Switch
                  checked={security.tlsBinding?.enabled}
                  onChange={(e) => updateSection("tlsBinding", { enabled: e.currentTarget.checked })}
                  disabled={disabled}
                />
              </Group>
              {security.tlsBinding?.enabled && (
                <TextInput
                  label="Cookie Name"
                  description="The name of the session cookie to bind. Recommended: session, authToken, or your app's session ID."
                  placeholder="session"
                  value={security.tlsBinding?.cookieName || ""}
                  onChange={(e) => updateSection("tlsBinding", { cookieName: e.currentTarget.value })}
                  disabled={disabled}
                />
              )}
            </Stack>
          </Paper>
        </SimpleGrid>
      </Stack>
    </Card>
  );
};
