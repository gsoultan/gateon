// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useState } from "react";
import { notifications } from "@mantine/notifications";
import { IconShieldCheck, IconX } from "@tabler/icons-react";
import { usePermissions } from "../../../hooks/usePermissions";
import { useGateonStatus } from "../../../hooks/useGateonStatus";
import { useApiConfigStore } from "../../../store/useApiConfigStore";
import { apiFetch, getApiErrorMessage } from "../../../hooks/useGateon";
import type { GlobalConfig, StatusResponse } from "../../../types/gateon";

export type ConfigLoad = "loading" | "loaded" | "failed";
export type SettingsPreset = "development" | "production" | "high-throughput";

/**
 * Everything the Settings tabs share. It lives in SettingsPage, not in a tab:
 * a tab that is not showing is unmounted, and the gateway's configuration,
 * the unsaved edits to it and the dashboard's own drafts have to outlive a
 * switch between tabs. It is fetched once for the page, never per tab.
 */
export interface SettingsState {
  config: GlobalConfig;
  setConfig: (config: GlobalConfig) => void;
  configLoad: ConfigLoad;
  configLoadError: string | null;
  retryLoad: () => void;
  /** True until the gateway's settings have loaded, and for a role that cannot edit them. */
  formDisabled: boolean;
  canEditGlobal: boolean;
  canImportConfig: boolean;
  canExportConfig: boolean;
  status: StatusResponse | undefined;

  saving: boolean;
  error: string | null;
  savedOk: boolean;
  saveGatewayConfig: () => Promise<void>;
  triggerWafUpdate: () => Promise<void>;
  applyPreset: (preset: SettingsPreset) => void;

  installing: boolean;
  uninstalling: boolean;
  installClamav: (mode: number) => Promise<void>;
  uninstallClamav: () => Promise<void>;

  apiUrlDraft: string;
  setApiUrlDraft: (value: string) => void;
  refreshIntervalDraft: number;
  setRefreshIntervalDraft: (value: number) => void;
  generalSavedOk: boolean;
  saveGeneral: () => void;
}

/** Props every lazily loaded Settings tab takes. */
export interface SettingsTabProps {
  settings: SettingsState;
}

const errorMessage = (err: unknown): string | undefined =>
  err instanceof Error ? err.message : undefined;

function useClamavLifecycle() {
  const [installing, setInstalling] = useState(false);
  const [uninstalling, setUninstalling] = useState(false);

  const uninstallClamav = async () => {
    setUninstalling(true);
    try {
      const res = await apiFetch("/v1/security/clamav/uninstall", {
        method: "POST",
      });
      const data = await res.json();
      if (res.ok && data.success) {
        notifications.show({
          title: 'Uninstallation Started',
          message: 'ClamAV removal has been initiated. This might take a few minutes.',
          color: 'blue',
          icon: <IconShieldCheck size={16} />
        });
      } else {
        throw new Error(data.message || 'Failed to start uninstallation');
      }
    } catch (err: unknown) {
      notifications.show({
        title: 'Uninstallation Failed',
        message: errorMessage(err) || 'Failed to start ClamAV uninstallation',
        color: 'red',
        icon: <IconX size={16} />
      });
    } finally {
      setUninstalling(false);
    }
  };

  const installClamav = async (mode: number) => {
    setInstalling(true);
    try {
      const res = await apiFetch("/v1/security/clamav/install", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        notifications.show({
          title: 'Installation Started',
          message: 'ClamAV installation has been initiated. This might take a few minutes.',
          color: 'blue',
          icon: <IconShieldCheck size={16} />
        });
      } else {
        throw new Error(data.message || 'Failed to start installation');
      }
    } catch (err: unknown) {
      notifications.show({
        title: 'Installation Failed',
        message: errorMessage(err) || 'Failed to start ClamAV installation',
        color: 'red',
        icon: <IconX size={16} />
      });
    } finally {
      setInstalling(false);
    }
  };

  return { installing, uninstalling, installClamav, uninstallClamav };
}

// A preset sets the fields it names and keeps the rest of each section. It
// used to replace log and transport outright, so applying one and saving
// reset every retention period, the trace archive settings and the
// transport timeouts it never mentioned to their defaults.
function withPreset(config: GlobalConfig, preset: SettingsPreset): GlobalConfig {
  const tls = config.tls || { enabled: false };
  const redis = config.redis || { enabled: false };
  const otel = config.otel || { enabled: false };
  const base = { ...config };
  const log = config.log || {};
  if (preset === "development") {
    return {
      ...base,
      log: { ...log, level: "debug", development: true, format: "text", pathStatsRetentionDays: 7 },
      tls: { ...tls, enabled: false },
      redis: { ...redis, enabled: false },
      otel: { ...otel, enabled: false },
    };
  }
  if (preset === "production") {
    return {
      ...base,
      log: { ...log, level: "info", development: false, format: "json", pathStatsRetentionDays: 30 },
      tls: { ...tls, enabled: true },
      redis: { ...redis, enabled: true },
      otel: { ...otel, enabled: true },
    };
  }
  return {
    ...base,
    log: { ...log, level: "warn", development: false, format: "json", pathStatsRetentionDays: 7 },
    tls: tls,
    redis: redis,
    otel: otel,
    transport: {
      ...(config.transport || {}),
      maxIdleConns: 20000,
      maxIdleConnsPerHost: 2000,
      idleConnTimeoutSeconds: 90,
    },
  };
}

export function useSettingsState(): SettingsState {
  const { canEditGlobal, canImportConfig, canExportConfig } = usePermissions();
  const { data: status } = useGateonStatus();
  // Until GET /v1/global succeeds, `config` holds the placeholders set below,
  // and saving would write them over the gateway's real settings: the server
  // keeps only the sections a save leaves out, and every one of these is sent.
  // A failed load used to be swallowed, and a Save after it reset TLS,
  // Redis, OTel, logging and the management allowlist to these defaults.
  const [configLoad, setConfigLoad] = useState<ConfigLoad>("loading");
  const [configLoadError, setConfigLoadError] = useState<string | null>(null);
  const [configReload, setConfigReload] = useState(0);
  const formDisabled = !canEditGlobal || configLoad !== "loaded";
  const apiUrl = useApiConfigStore((s) => s.apiUrl);
  const refreshInterval = useApiConfigStore((s) => s.refreshInterval);
  const setApiConfig = useApiConfigStore((s) => s.setApiConfig);

  // Local edits for General Settings (committed on Save)
  const [apiUrlDraft, setApiUrlDraft] = useState(apiUrl);
  const [refreshIntervalDraft, setRefreshIntervalDraft] = useState(refreshInterval);

  useEffect(() => {
    setApiUrlDraft(apiUrl);
    setRefreshIntervalDraft(refreshInterval);
  }, [apiUrl, refreshInterval]);

  // Global config state
  const [config, setConfig] = useState<GlobalConfig>({
    tls: { enabled: false, acme: { enabled: false } },
    redis: { enabled: false },
    otel: { enabled: false },
    log: { level: "info", development: true, format: "text" },
    management: { bind: "0.0.0.0", port: "8080", allowedIps: ["0.0.0.0/0", "::/0"] },
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedOk, setSavedOk] = useState(false);
  const [generalSavedOk, setGeneralSavedOk] = useState(false);
  const clamav = useClamavLifecycle();

  useEffect(() => {
    // Fetch current global config
    const controller = new AbortController();
    setConfigLoad("loading");
    apiFetch("/v1/global", {
      signal: controller.signal,
    })
      .then(async (r) => {
        if (!r.ok) throw new Error(await r.text());
        return r.json();
      })
      .then((cfg: GlobalConfig) => {
        setConfig(cfg || ({} as GlobalConfig));
        setConfigLoad("loaded");
        setConfigLoadError(null);
      })
      .catch((e) => {
        if (controller.signal.aborted) return;
        setConfigLoad("failed");
        setConfigLoadError(getApiErrorMessage(e));
      });
    return () => controller.abort();
  }, [apiUrl, configReload]);

  const saveGeneral = () => {
    setApiConfig(apiUrlDraft, refreshIntervalDraft);
    setGeneralSavedOk(true);
    setTimeout(() => setGeneralSavedOk(false), 2000);
  };

  const saveGatewayConfig = async () => {
    if (configLoad !== "loaded") {
      setError("The gateway's settings have not loaded, so saving would overwrite them with defaults.");
      return;
    }
    setSaving(true);
    setError(null);
    setSavedOk(false);
    try {
      const res = await apiFetch("/v1/global", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(config),
      });
      // The gateway's refusal, not its JSON envelope: a refused country list
      // or WAF setting explains itself, and the raw body buried that in
      // escapes and a request id.
      if (!res.ok) throw new Error(getApiErrorMessage(new Error(await res.text())) || `HTTP ${res.status}`);
      setSavedOk(true);
    } catch (e: unknown) {
      setError(errorMessage(e) || "Failed to save configuration");
    } finally {
      setSaving(false);
    }
  };

  const triggerWafUpdate = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await apiFetch("/v1/waf/update", {
        method: "POST",
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      if (data.success) {
        setSavedOk(true);
      } else {
        setError(data.message || "Failed to update WAF rules");
      }
    } catch (e: unknown) {
      setError(errorMessage(e) || "Failed to trigger WAF update");
    } finally {
      setSaving(false);
    }
  };

  return {
    config,
    setConfig,
    configLoad,
    configLoadError,
    retryLoad: () => setConfigReload((n) => n + 1),
    formDisabled,
    canEditGlobal,
    canImportConfig,
    canExportConfig,
    status,
    saving,
    error,
    savedOk,
    saveGatewayConfig,
    triggerWafUpdate,
    applyPreset: (preset) => setConfig(withPreset(config, preset)),
    ...clamav,
    apiUrlDraft,
    setApiUrlDraft,
    refreshIntervalDraft,
    setRefreshIntervalDraft,
    generalSavedOk,
    saveGeneral,
  };
}
