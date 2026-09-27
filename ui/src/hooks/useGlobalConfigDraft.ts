// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useState } from "react";
import { apiFetch, getApiErrorMessage } from "./api";
import type { GlobalConfig } from "../types/gateon";

export type GlobalConfigLoad = "loading" | "loaded" | "failed";

const PLACEHOLDER: GlobalConfig = { tls: { enabled: false } };

/**
 * The global configuration as a page edits it: read once, re-readable, and
 * saved back by the caller.
 *
 * `status` is "loaded" only after a successful read, and a page must not offer
 * a save before then. PUT /v1/global replaces every section it carries, and
 * the Certificates and Client Authorities pages used to swallow a failed read
 * and keep editing their placeholder: one failed load and one saved
 * certificate sent `tls: { enabled: false, certificates: [that one] }`, which
 * turned TLS off and removed every other certificate. Settings had the same
 * shape and was fixed first; this is that fix for the pages that edit TLS.
 */
export function useGlobalConfigDraft() {
  const [config, setConfig] = useState<GlobalConfig>(PLACEHOLDER);
  const [status, setStatus] = useState<GlobalConfigLoad>("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setStatus("loading");
    apiFetch("/v1/global", { signal: controller.signal })
      .then(async (r) => {
        if (!r.ok) throw new Error(await r.text());
        return (await r.json()) as GlobalConfig;
      })
      .then((cfg) => {
        setConfig(cfg || PLACEHOLDER);
        setStatus("loaded");
        setLoadError(null);
      })
      .catch((e: unknown) => {
        if (controller.signal.aborted) return;
        setStatus("failed");
        setLoadError(getApiErrorMessage(e));
      });
    return () => controller.abort();
  }, [attempt]);

  return { config, setConfig, status, loadError, retry: () => setAttempt((n) => n + 1) };
}
