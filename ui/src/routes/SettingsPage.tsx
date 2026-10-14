// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { lazy, Suspense, useEffect } from "react";
import { Text, Stack, Button, Group, Alert, Skeleton, Tabs } from "@mantine/core";
import {
  IconAdjustments,
  IconAlertTriangle,
  IconNetwork,
  IconServer,
  IconShieldLock,
} from "@tabler/icons-react";
import { useUrlFilters } from "../hooks/useUrlFilters";
import { PageHeader } from "../components/layout";
import { SettingsSaveBar } from "../components/settings/tabs/SettingsSaveBar";
import { useSettingsState } from "../components/settings/tabs/settingsState";
import { asSettingsTab, type SettingsTab } from "../components/settings/tabs/settingsTab";

// Each tab is its own chunk, fetched the first time the tab is opened.
const GeneralTab = lazy(() => import("../components/settings/tabs/GeneralTab"));
const GatewayTab = lazy(() => import("../components/settings/tabs/GatewayTab"));
const SecurityTab = lazy(() => import("../components/settings/tabs/SecurityTab"));
const NetworkTab = lazy(() => import("../components/settings/tabs/NetworkTab"));

const tabFallback = <Skeleton height={320} radius="md" />;

export default function SettingsPage() {
  // The gateway's configuration, and every edit to it, lives here rather than
  // in a tab: keepMounted is off, so a tab that is not showing is unmounted,
  // and its chunk is not fetched until it is first opened.
  const settings = useSettingsState();
  const { configLoad, configLoadError, canEditGlobal, saving, error, savedOk, hasChanges } = settings;

  // Leaving the page drops every unsaved edit, so the browser asks first.
  useEffect(() => {
    if (!hasChanges) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [hasChanges]);
  const [filters, setFilters] = useUrlFilters<{ tab: string }>();
  const tab = asSettingsTab(filters.tab);
  const showTab = (next: string | null) => {
    const value: SettingsTab = asSettingsTab(next ?? undefined);
    setFilters({ tab: value === "general" ? undefined : value });
  };

  return (
    <Stack gap="xl">
      <PageHeader title="Settings" description="Manage your gateway preferences and UI appearance." />

      {configLoad === "failed" && (
        <Alert color="red" variant="light" icon={<IconAlertTriangle size="1rem" />} title="Gateway settings could not be loaded">
          <Stack gap="xs">
            <Text size="sm">
              {configLoadError || "The gateway did not answer."} Editing and saving are disabled until they load,
              so the defaults shown here cannot be written over the gateway's settings.
            </Text>
            <Group>
              <Button size="xs" variant="light" color="red" onClick={settings.retryLoad}>
                Retry
              </Button>
            </Group>
          </Stack>
        </Alert>
      )}

      <Tabs value={tab} onChange={showTab} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="general" leftSection={<IconAdjustments size={16} />}>General</Tabs.Tab>
          <Tabs.Tab value="gateway" leftSection={<IconServer size={16} />}>Gateway</Tabs.Tab>
          <Tabs.Tab value="security" leftSection={<IconShieldLock size={16} />}>Security</Tabs.Tab>
          <Tabs.Tab value="network" leftSection={<IconNetwork size={16} />}>Network &amp; HA</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="general" pt="xl">
          <Suspense fallback={tabFallback}>
            <GeneralTab settings={settings} />
          </Suspense>
        </Tabs.Panel>
        <Tabs.Panel value="gateway" pt="xl">
          <Suspense fallback={tabFallback}>
            <GatewayTab settings={settings} />
          </Suspense>
        </Tabs.Panel>
        <Tabs.Panel value="security" pt="xl">
          <Suspense fallback={tabFallback}>
            <SecurityTab settings={settings} />
          </Suspense>
        </Tabs.Panel>
        <Tabs.Panel value="network" pt="xl">
          <Suspense fallback={tabFallback}>
            <NetworkTab settings={settings} />
          </Suspense>
        </Tabs.Panel>
      </Tabs>

      {/* Outside the tabs, so every tab can save and every save reports here,
          whichever tab's button made it. It appears only when there is
          something to save, or a save to report. */}
      {canEditGlobal && (
        <SettingsSaveBar
          hasChanges={hasChanges}
          saving={saving}
          canSave={configLoad === "loaded"}
          error={error}
          savedOk={savedOk}
          onSave={settings.saveGatewayConfig}
          onDiscard={settings.discardChanges}
        />
      )}
    </Stack>
  );
}
