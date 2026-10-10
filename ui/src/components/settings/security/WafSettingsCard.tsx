// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, Textarea, NumberInput, Button, Group, Divider, Switch, Select, MultiSelect, TagsInput, Badge, Alert, Loader, SimpleGrid } from "@mantine/core";
import { IconShieldLock } from "@tabler/icons-react";
import { useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { EFFECTIVE_WAF_QUERY_KEY, useEffectiveWaf, type EffectiveWafView } from "../../../hooks/useEffectiveWaf";
import type { StatusResponse, WafConfig } from "../../../types/gateon";
import { WAF_APP_PROFILES } from "../../../types/gateon";
import { ClamAVSection } from "./ClamAVSection";
import { BotManagementSection } from "./BotManagementSection";
import { DLP_ACTION_HELP, GLOBAL_AUDIT_ONLY_HELP } from "../../MiddlewareConfig/wafCopy";
import { ADMIN_ONLY_REASON, useAdminOnlySetting } from "../../../hooks/usePermissions";
import { GLOBAL_WAF_FAMILIES, familiesOff, familySwitchOn, withFamily } from "../../../utils/wafCategories";

interface WafSettingsCardProps {
  waf: WafConfig | undefined;
  onChange: (waf: WafConfig) => void;
  disabled: boolean;
  canEdit: boolean;
  saving: boolean;
  onSave: () => void | Promise<void>;
  status: StatusResponse | undefined;
  installing: boolean;
  uninstalling: boolean;
  onInstall: (mode: number) => void;
  onUninstall: () => void;
}

// The WAF that runs on every route: the rule set, its categories, tuning for
// the applications behind the gateway, ClamAV and bot management.
export function WafSettingsCard({
  waf,
  onChange,
  disabled,
  canEdit,
  saving,
  onSave,
  status,
  installing,
  uninstalling,
  onInstall,
  onUninstall,
}: WafSettingsCardProps) {
  // Which header names the client address is administrator-only (ADR 0040).
  const clientTrust = useAdminOnlySetting(disabled);
  // What the running WAF does, from the gateway: the tier can drop a family
  // whose switch is on, so the switches alone do not say what runs.
  const effective = useEffectiveWaf();
  const queryClient = useQueryClient();
  const save = async () => {
    await onSave();
    await queryClient.invalidateQueries({ queryKey: EFFECTIVE_WAF_QUERY_KEY });
  };
  return (
    <Card withBorder shadow="sm" radius="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Group gap="xs">
            <IconShieldLock color="var(--mantine-color-blue-filled)" />
            <Title order={3}>Global WAF Settings</Title>
          </Group>
          <Switch
            label="Protect all routes"
            checked={waf?.enabled || false}
            onChange={(e) =>
              onChange({
                ...(waf || {
                  paranoiaLevel: 1,
                }),
                enabled: e.currentTarget.checked,
              })
            }
            disabled={disabled}
          />
        </Group>
        <Text size="sm" c="dimmed">
          When enabled, the Web Application Firewall (the gwaf core ruleset and
          Gateon&apos;s rules, malware and ransomware detection included) runs on{" "}
          <strong>every</strong> route that has no WAF of its own. A route WAF
          starts from what runs here and adds to or narrows it on that route
          only. Changes apply live to existing routes.
        </Text>
        {waf?.enabled && <WafModeLine effective={effective} />}

        {waf?.enabled && (
          <Stack gap="sm">
            <Group grow align="flex-end">
              <Switch
                label="Trust Cloudflare IPs/Headers"
                description={clientTrust.locked ? ADMIN_ONLY_REASON : undefined}
                checked={waf.trustCloudflareHeaders}
                onChange={(e) =>
                  onChange({
                    ...waf!,
                    trustCloudflareHeaders: e.currentTarget.checked,
                  })
                }
                disabled={clientTrust.disabled}
              />
              <Select
                label="Paranoia Level"
                data={[
                  { value: "1", label: "1 - Standard" },
                  { value: "2", label: "2 - High" },
                  { value: "3", label: "3 - Extreme" },
                  { value: "4", label: "4 - Insane" },
                ]}
                value={(waf.paranoiaLevel || 1).toString()}
                onChange={(v) =>
                  onChange({
                    ...waf!,
                    paranoiaLevel: parseInt(v || "1"),
                  })
                }
                disabled={disabled}
              />
            </Group>

            <>
                <Divider label="Attack families" labelPosition="center" />
                <GlobalWafCategories waf={waf} onChange={onChange} disabled={disabled} effective={effective} />

                <Divider label="Optional protections" labelPosition="center" />
                <Group grow align="flex-start">
                  <Stack gap="xs">
                    <Switch
                      label="WordPress Protection"
                      description="Admin lockdown for /wp-admin and /wp-login.php. Off by default: it refuses every address not listed below."
                      checked={waf.wordpress}
                      onChange={(e) => onChange({ ...waf!, wordpress: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    {waf.wordpress && (
                      <TagsInput
                        label="Allowed Admin IPs"
                        description="IPs allowed to access /wp-admin and /wp-login.php"
                        placeholder="1.2.3.4, 5.6.7.8"
                        value={waf.allowedAdminIps || []}
                        onChange={(v) => onChange({ ...waf!, allowedAdminIps: v })}
                        disabled={disabled}
                      />
                    )}
                  </Stack>
                  <Stack gap="xs">
                    <Switch
                      label="Behavioural Reputation"
                      description="Refuse a client whose own reputation here has fallen below 20. Threat-feed listings are enforced on every route by Advanced Security > IP Reputation, with or without this."
                      checked={waf.ipReputation}
                      onChange={(e) => onChange({ ...waf!, ipReputation: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                  </Stack>
                  <Stack gap="xs">
                    <Switch
                      label="Data Loss Prevention (DLP)"
                      checked={waf.dlp}
                      onChange={(e) => onChange({ ...waf!, dlp: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                  </Stack>
                </Group>

                {waf.dlp && (
                  <Select
                    label="When a leak is found"
                    description={`${DLP_ACTION_HELP} Applies to data-leak rules only.`}
                    data={[
                      { value: "block", label: "Block — refuse the whole response (default)" },
                      { value: "redact", label: "Redact — remove the finding, send the rest" },
                      { value: "audit", label: "Audit — record it, send the response untouched" },
                    ]}
                    value={waf.dlpAction || "block"}
                    onChange={(value) => onChange({ ...waf!, dlpAction: value || "block" })}
                    allowDeselect={false}
                    disabled={disabled}
                  />
                )}

                <NumberInput
                  label="Global Anomaly Threshold"
                  description="Default score required to block if not specified on route. Default: 5"
                  value={waf.anomalyThreshold || 5}
                  onChange={(v) => onChange({ ...waf!, anomalyThreshold: parseInt(v?.toString() || "5") })}
                  min={1}
                  disabled={disabled}
                />

                <Divider label="Application Tuning" labelPosition="center" />
                <TagsInput
                  label="Gateway Origins"
                  description="The hostnames this gateway answers on. Used to tell a redirect or fetch
                    destination on this site from one somewhere else. Leave empty to use the Host()
                    rules from your routes — set it when a route matches on a path alone, or when the
                    gateway is reached by a name no route mentions. Without any origin, open-redirect
                    and SSRF checks have nothing to compare against and stay silent."
                  placeholder="app.example.com"
                  value={waf.origins ?? []}
                  onChange={(v) => onChange({ ...waf!, origins: v })}
                  disabled={disabled}
                  clearable
                />
                <MultiSelect
                  label="Platform Profiles"
                  description="Platforms running behind this gateway. Each one suppresses the specific
                    false positives that platform generates against itself — a WordPress comment field
                    really does contain PHP, and an issue tracker really does quote SQL. Exceptions are
                    scoped to a named rule on a named path and field; nothing is turned off globally."
                  placeholder={
                    (waf.appProfiles?.length ?? 0) > 0 ? undefined : "None — the default ruleset, untuned"
                  }
                  data={WAF_APP_PROFILES}
                  value={waf.appProfiles ?? []}
                  onChange={(v) => onChange({ ...waf!, appProfiles: v })}
                  disabled={disabled}
                  clearable
                  searchable
                />
                <Switch
                  label="SSRF Parameter Protection"
                  description="Block an off-origin URL in a parameter the server itself fetches (url,
                    webhook, feed, callback). Leave this off if the application accepts user-supplied
                    URLs by design — registering a webhook or importing an avatar is the same request
                    shape as the attack. Redirecting a user off-origin is always blocked and needs no
                    setting."
                  checked={waf.ssrfProtection}
                  onChange={(e) => onChange({ ...waf!, ssrfProtection: e.currentTarget.checked })}
                  disabled={disabled}
                />

                <Divider label="WAF Custom Rules" labelPosition="center" />
                <Switch
                  label="ClamAV file scanning"
                  description="Turns on the ClamAV settings below. The WAF's malware and ransomware rules run whatever this says."
                  checked={waf.malwareDetection}
                  onChange={(e) => onChange({ ...waf!, malwareDetection: e.currentTarget.checked })}
                  disabled={disabled}
                />
                <Switch
                  label="Load custom rules from disk"
                  description="Use the rule files in <data_dir>/waf/rules, if that directory exists. The built-in gwaf rules are always active."
                  checked={waf.autoUpdateRules}
                  onChange={(e) => onChange({ ...waf!, autoUpdateRules: e.currentTarget.checked })}
                  disabled={disabled}
                />

                <ClamAVSection
                  waf={waf}
                  onChange={onChange}
                  disabled={disabled}
                  status={status}
                  installing={installing}
                  uninstalling={uninstalling}
                  onInstall={onInstall}
                  onUninstall={onUninstall}
                />

                <BotManagementSection waf={waf} onChange={onChange} disabled={disabled} />
              </>

            <Textarea
              label="Custom Global Directives (not executed)"
              description="Kept so an upgrade does not lose them. The current engine does not parse SecLang, so nothing here is enforced — re-author these as rules under WAF Rules."
              placeholder="SecRule ARGS 'foo' 'id:1,deny,status:403'"
              value={waf.customDirectives || ""}
              onChange={(e) =>
                onChange({
                  ...waf!,
                  customDirectives: e.currentTarget.value,
                })
              }
              disabled={disabled}
              minRows={4}
              autosize
            />
            {canEdit && (
              <Group justify="flex-end" mt="md">
                <Button onClick={save} loading={saving} size="sm">
                  Save WAF Settings
                </Button>
              </Group>
            )}
          </Stack>
        )}
      </Stack>
    </Card>
  );
}

type EffectiveQuery = UseQueryResult<EffectiveWafView>;

// One line saying what the global WAF does with a match. "Audit only" is said
// as what it is -- nothing is blocked -- because "enabled" alone reported it as
// protecting (truth T12).
function WafModeLine({ effective }: { effective: EffectiveQuery }) {
  const mode = effective.data?.global.mode;
  if (!mode) return null;
  if (mode === "audit_only") {
    return (
      <Alert color="yellow" title="Audit only: nothing is blocked">
        {GLOBAL_AUDIT_ONLY_HELP}
      </Alert>
    );
  }
  return (
    <Group gap="xs">
      <Text size="sm">Mode:</Text>
      <Badge color={mode === "enforcing" ? "green" : "gray"} variant="light">
        {mode === "enforcing" ? "Enforcing" : "Off"}
      </Badge>
    </Group>
  );
}

// The attack-family switches (ADR 0064) beside what the running WAF does with
// each. A switch nobody touched is on; switching one off removes the rules
// filed under that family and nothing else. Malware detection is not a switch
// here: the gateway-wide WAF always runs it.
function GlobalWafCategories({
  waf,
  onChange,
  disabled,
  effective,
}: {
  waf: WafConfig;
  onChange: (waf: WafConfig) => void;
  disabled: boolean;
  effective: EffectiveQuery;
}) {
  const off = familiesOff(waf);
  return (
    <Stack gap="xs">
      <Text size="sm" c="dimmed">
        Switching a family off removes the rules filed under it from the gateway-wide WAF, on every
        route without a WAF of its own. A route WAF&apos;s own switch wins over these; one it leaves
        unset follows them. Code Execution off also lets PHP, Java and Node.js code injection
        through. Malware (web shell) detection always runs.
      </Text>
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xs">
        {GLOBAL_WAF_FAMILIES.map((f) => (
          <Group key={f.key} gap={8} wrap="nowrap" justify="space-between">
            <Switch
              label={f.label}
              checked={familySwitchOn(waf, f.key)}
              onChange={(e) => onChange(withFamily(waf, f.key, e.currentTarget.checked))}
              disabled={disabled}
            />
            <RunningBadge effective={effective} effectiveKey={f.effectiveKey} />
          </Group>
        ))}
      </SimpleGrid>
      {off.length > 0 && (
        <Alert color="yellow" title="Switched off gateway-wide">
          {off.join(", ")}: requests carrying these attacks reach the backends of routes without a
          WAF of their own.
        </Alert>
      )}
      <EffectiveState effective={effective} />
    </Stack>
  );
}

// Whether the saved configuration runs the family, from the gateway.
function RunningBadge({ effective, effectiveKey }: { effective: EffectiveQuery; effectiveKey: string }) {
  const categories = effective.data?.global.categories;
  if (!categories) return null;
  const running = categories[effectiveKey] === true;
  return (
    <Badge size="sm" color={running ? "green" : "gray"} variant="light">
      {running ? "Running" : "Not running"}
    </Badge>
  );
}

// Loading and error for the running-state badges; nothing once they are shown.
function EffectiveState({ effective }: { effective: EffectiveQuery }) {
  if (effective.isLoading) {
    return (
      <Group gap="xs">
        <Loader size="xs" />
        <Text size="sm" c="dimmed">Reading what the WAF runs…</Text>
      </Group>
    );
  }
  if (effective.isError || !effective.data) {
    return (
      <Alert color="red" title="Could not read what the WAF runs">
        {effective.error instanceof Error ? effective.error.message : "The gateway did not answer."}
      </Alert>
    );
  }
  return (
    <Text size="xs" c="dimmed">
      Running and Not running are what the saved configuration does, the WAF tier included; save to
      update them.
    </Text>
  );
}
