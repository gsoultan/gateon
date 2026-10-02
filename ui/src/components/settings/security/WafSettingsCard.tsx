// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Card, Title, Text, Stack, Textarea, NumberInput, Button, Group, Divider, Switch, Select, MultiSelect, TagsInput } from "@mantine/core";
import { IconShieldLock } from "@tabler/icons-react";
import type { StatusResponse, WafConfig } from "../../../types/gateon";
import { WAF_APP_PROFILES } from "../../../types/gateon";
import { ClamAVSection } from "./ClamAVSection";
import { BotManagementSection } from "./BotManagementSection";
import { ADMIN_ONLY_REASON, useAdminOnlySetting } from "../../../hooks/usePermissions";

interface WafSettingsCardProps {
  waf: WafConfig | undefined;
  onChange: (waf: WafConfig) => void;
  disabled: boolean;
  canEdit: boolean;
  saving: boolean;
  onSave: () => void;
  onUpdateRules: () => void;
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
  onUpdateRules,
  status,
  installing,
  uninstalling,
  onInstall,
  onUninstall,
}: WafSettingsCardProps) {
  // Which header names the client address is administrator-only (ADR 0040).
  const clientTrust = useAdminOnlySetting(disabled);
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
                  useCrs: true,
                  paranoiaLevel: 1,
                }),
                enabled: e.currentTarget.checked,
              })
            }
            disabled={disabled}
          />
        </Group>
        <Text size="sm" c="dimmed">
          When enabled, the Web Application Firewall (OWASP Core Rule Set plus
          malware &amp; ransomware detection) runs on <strong>every</strong>{" "}
          route automatically — no per-route WAF middleware required. Changes
          apply live to existing routes.
        </Text>

        {waf?.enabled && (
          <Stack gap="sm">
            <Group grow>
              <Switch
                label="Use OWASP Core Rule Set (CRS)"
                checked={waf.useCrs}
                onChange={(e) =>
                  onChange({
                    ...waf!,
                    useCrs: e.currentTarget.checked,
                  })
                }
                disabled={disabled}
              />
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
                value={waf.paranoiaLevel.toString()}
                onChange={(v) =>
                  onChange({
                    ...waf!,
                    paranoiaLevel: parseInt(v || "1"),
                  })
                }
                disabled={disabled || !waf.useCrs}
              />
            </Group>

            {waf.useCrs && (
              <>
                <Divider label="Global Protection Categories" labelPosition="center" />
                <Group grow align="flex-start">
                  <Stack gap="xs">
                    <Switch
                      label="SQL Injection"
                      checked={waf.sqli !== false}
                      onChange={(e) => onChange({ ...waf!, sqli: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    <Switch
                      label="Cross-Site Scripting"
                      checked={waf.xss !== false}
                      onChange={(e) => onChange({ ...waf!, xss: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    <Switch
                      label="File Inclusion"
                      checked={waf.lfi !== false}
                      onChange={(e) => onChange({ ...waf!, lfi: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    <Switch
                      label="Code Execution"
                      checked={waf.rce !== false}
                      onChange={(e) => onChange({ ...waf!, rce: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                  </Stack>
                  <Stack gap="xs">
                    <Switch
                      label="Scanner Detection"
                      checked={waf.scanner !== false}
                      onChange={(e) => onChange({ ...waf!, scanner: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    <Switch
                      label="Protocol Enforcement"
                      checked={waf.protocol !== false}
                      onChange={(e) => onChange({ ...waf!, protocol: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    <Switch
                      label="PHP Protection"
                      checked={waf.php !== false}
                      onChange={(e) => onChange({ ...waf!, php: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    <Switch
                      label="NodeJS Protection"
                      checked={waf.nodejs}
                      onChange={(e) => onChange({ ...waf!, nodejs: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                  </Stack>
                  <Stack gap="xs">
                    <Switch
                      label="Java Protection"
                      checked={waf.java !== false}
                      onChange={(e) => onChange({ ...waf!, java: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    <Switch
                      label="WordPress Protection"
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
                    <Switch
                      label="IP Reputation"
                      checked={waf.ipReputation}
                      onChange={(e) => onChange({ ...waf!, ipReputation: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    <Switch
                      label="DOS Protection"
                      checked={waf.dosProtection}
                      onChange={(e) => onChange({ ...waf!, dosProtection: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                  </Stack>
                  <Stack gap="xs">
                    <Switch
                      label="Malware Detection"
                      checked={waf.malwareDetection}
                      onChange={(e) => onChange({ ...waf!, malwareDetection: e.currentTarget.checked })}
                      disabled={disabled}
                    />
                    <Switch
                      label="Ransomware Detection"
                      checked={waf.ransomwareDetection}
                      onChange={(e) => onChange({ ...waf!, ransomwareDetection: e.currentTarget.checked })}
                      disabled={disabled}
                    />
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
                    description="Roll out in stages: watch first, then redact, then block once the false-positive rate is known. Applies to data-leak rules only."
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

                <Button
                  variant="light"
                  color="blue"
                  onClick={onUpdateRules}
                  loading={saving}
                  disabled={disabled}
                  mt="xs"
                >
                  Update WAF Rules Now
                </Button>

                <BotManagementSection waf={waf} onChange={onChange} disabled={disabled} />
              </>
            )}

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
                <Button onClick={onSave} loading={saving} size="sm">
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
