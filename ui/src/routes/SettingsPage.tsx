// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { lazy, Suspense, useEffect, useMemo, type ComponentType, type LazyExoticComponent } from "react";
import { Alert, Box, Button, Grid, Group, NavLink, Paper, Select, Skeleton, Stack, Text, TextInput } from "@mantine/core";
import { IconAlertTriangle, IconSearch, IconX } from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import { useUrlFilters } from "../hooks/useUrlFilters";
import { PageHeader, linkSearch } from "../components/layout";
import { SettingsSaveBar } from "../components/settings/tabs/SettingsSaveBar";
import { useSettingsState, type SettingsState } from "../components/settings/tabs/settingsState";
import { asSettingsTab, SETTINGS_SECTIONS, type SettingsTab } from "../components/settings/tabs/settingsTab";
import { searchSettings } from "../components/settings/settingsIndex";

// Each section is its own chunk, fetched the first time it is opened.
const SECTION_COMPONENTS: Record<SettingsTab, LazyExoticComponent<ComponentType<{ settings: SettingsState }>>> = {
  general: lazy(() => import("../components/settings/tabs/GeneralTab")),
  gateway: lazy(() => import("../components/settings/tabs/GatewayTab")),
  security: lazy(() => import("../components/settings/tabs/SecurityTab")),
  network: lazy(() => import("../components/settings/tabs/NetworkTab")),
  storage: lazy(() => import("../components/settings/tabs/StorageTab")),
  integrations: lazy(() => import("../components/settings/tabs/IntegrationsTab")),
};

const sectionFallback = <Skeleton height={320} radius="md" />;

type SettingsSearch = {
  tab: string;
  /** The card a link or a search result opens the section at. */
  section: string;
  q: string;
};

/**
 * The cards a search matches, each a link to its section at that card. The
 * list replaces the section while a query is typed, so the answer to "where
 * is the ClamAV switch" is one keystroke away rather than six tabs.
 */
function SearchResults({ query, onPick }: { query: string; onPick: (tab: SettingsTab, section: string) => void }) {
  const results = useMemo(() => searchSettings(query), [query]);
  if (results.length === 0) {
    return (
      <Paper withBorder p="lg" radius="md">
        <Text size="sm" c="dimmed">
          No setting matches “{query}”. Try the name of the feature, such as “retention” or “clamav”.
        </Text>
      </Paper>
    );
  }
  return (
    <Paper withBorder radius="md" p={0}>
      {results.map((r) => {
        const section = SETTINGS_SECTIONS.find((s) => s.id === r.section);
        return (
          <NavLink
            key={r.id}
            label={r.title}
            description={section?.label}
            onClick={() => onPick(r.section, r.id)}
            style={{ borderBottom: "1px solid var(--mantine-color-default-border)" }}
          />
        );
      })}
    </Paper>
  );
}

export default function SettingsPage() {
  // The gateway's configuration, and every edit to it, lives here rather than
  // in a section: a section that is not showing is unmounted, and its chunk is
  // not fetched until it is first opened.
  const settings = useSettingsState();
  const { configLoad, configLoadError, canEditGlobal, saving, error, savedOk, hasChanges } = settings;

  // Leaving the page drops every unsaved edit, so the browser asks first.
  useEffect(() => {
    if (!hasChanges) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [hasChanges]);

  const [filters, setFilters] = useUrlFilters<SettingsSearch>();
  const tab = asSettingsTab(filters.tab);
  const query = filters.q ?? "";
  const Section = SECTION_COMPONENTS[tab];

  const showSection = (next: SettingsTab, card?: string) =>
    setFilters({ tab: next === "general" ? undefined : next, section: card, q: undefined });

  // A link, a redirect or a search result names a card: scroll to it once the
  // section has rendered it, then drop the name so a reload stays put.
  useEffect(() => {
    if (!filters.section) return;
    const id = filters.section;
    let tries = 0;
    const timer = window.setInterval(() => {
      const el = document.getElementById(id);
      tries += 1;
      if (el) el.scrollIntoView({ block: "start", behavior: "smooth" });
      if (el || tries > 20) {
        window.clearInterval(timer);
        setFilters({ section: undefined });
      }
    }, 100);
    return () => window.clearInterval(timer);
  }, [filters.section, setFilters]);

  return (
    <Stack gap="xl">
      <PageHeader
        title="Settings"
        description="The gateway's configuration in six sections. Every change is saved once, from the bar at the foot of the page."
        actions={
          <TextInput
            placeholder="Search settings"
            aria-label="Search settings"
            leftSection={<IconSearch size={16} />}
            rightSection={
              query ? (
                <Button variant="subtle" color="gray" size="compact-xs" onClick={() => setFilters({ q: undefined })} aria-label="Clear search">
                  <IconX size={14} />
                </Button>
              ) : null
            }
            value={query}
            onChange={(e) => setFilters({ q: e.currentTarget.value || undefined })}
            w={{ base: "100%", sm: 280 }}
          />
        }
      />

      {configLoad === "failed" && (
        <Alert color="red" variant="light" icon={<IconAlertTriangle size="1rem" />} title="Gateway settings could not be loaded">
          <Stack gap="xs">
            <Text size="sm">
              {configLoadError || "The gateway did not answer."} Editing and saving are disabled until they load, so the defaults
              shown here cannot be written over the gateway's settings.
            </Text>
            <Group>
              <Button size="xs" variant="light" color="red" onClick={settings.retryLoad}>
                Retry
              </Button>
            </Group>
          </Stack>
        </Alert>
      )}

      <Grid gap="xl">
        <Grid.Col span={{ base: 12, md: 3 }}>
          <Box visibleFrom="md" style={{ position: "sticky", top: 80 }}>
            <Stack gap={2} component="nav" aria-label="Settings sections">
              {SETTINGS_SECTIONS.map((s) => (
                <NavLink
                  key={s.id}
                  component={Link}
                  to="/settings"
                  search={linkSearch(s.id === "general" ? {} : { tab: s.id })}
                  label={s.label}
                  description={s.description}
                  active={s.id === tab && !query}
                  variant="light"
                  style={{ borderRadius: "var(--mantine-radius-md)" }}
                />
              ))}
            </Stack>
          </Box>
          <Box hiddenFrom="md">
            <Select
              aria-label="Settings section"
              value={tab}
              onChange={(v) => showSection(asSettingsTab(v ?? undefined))}
              data={SETTINGS_SECTIONS.map((s) => ({ value: s.id, label: s.label }))}
              allowDeselect={false}
            />
          </Box>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 9 }}>
          {query ? (
            <SearchResults query={query} onPick={showSection} />
          ) : (
            <Suspense fallback={sectionFallback}>
              <Section settings={settings} />
            </Suspense>
          )}
        </Grid.Col>
      </Grid>

      {/* Outside the sections, so every section saves here. It floats only
          while there are unsaved edits. */}
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
