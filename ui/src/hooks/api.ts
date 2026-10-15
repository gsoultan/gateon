// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// These six call RPCs that already exist on ApiService. Going through the
// Connect client instead of hand-rolled fetch drops the duplicate wire format
// that both of today's API bugs lived in.
import { api } from "../services/client";
import type {
  SetupRequest,
  SetupResponse,
  GetDiagnosticsResponse,
  GetCloudflareIPsResponse,
  TraceRouteResponse,
  ValidateCORSRequest,
  ValidateCORSResponse,
  RemoveMitigatedThreatRequest,
  RemoveMitigatedThreatResponse,
  MitigateThreatRequest,
  MitigateThreatResponse,
  InstallClamavRequest,
  InstallClamavResponse,
  UninstallClamavResponse,
  RunDeepScanResponse,
  Anomaly,
} from "../types/gateon";

export {
  apiFetch,
  buildQueryString,
  getApiUrl,
  restoreSessionFromCookie,
  type PaginationParams,
  type RouteListParams,
} from "./http";
import { apiFetch } from "./http";

export { getApiErrorMessage } from "./apiError";

export async function setupGateon(req: SetupRequest): Promise<SetupResponse> {
  const res = await api.setup(req);
  if (res.success) {
    // The root route decides "setup still required?" from this cache entry
    // with ensureQueryData, which never refetches while an entry exists. The
    // entry was written before the operator was sent to /setup, so leaving it
    // would bounce the post-setup navigation to /login straight back to /setup.
    //
    // Imported lazily: a static import here puts queryClient on the entry
    // module's static graph, which drags the realtime store out of its own
    // lazy chunk and into the initial bundle (+151 kB, measured).
    const { queryClient } = await import("../queryClient");
    queryClient.removeQueries({ queryKey: ["setup-required"] });
  }
  return res;
}

export async function testDbConnection(
  payload: Pick<SetupRequest, "databaseUrl" | "databaseConfig" | "setupToken">,
): Promise<boolean> {
  const res = await apiFetch("/v1/setup/test-db", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await res.text());
  const data = await res.json();
  return !!data?.success;
}

// Still REST. The entrypoints key mismatch is fixed, but the generated
// response types every message field as `| undefined` — proto semantics —
// while the hand-written type requires them. Reconciling that is a pass
// over the type and its readers, not a swap of the transport, and doing it
// halfway would mean a cast that hides exactly the mismatch this migration
// exists to remove.
export async function getDiagnostics(): Promise<GetDiagnosticsResponse> {
  const res = await apiFetch("/v1/diagnostics");
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function applyRecommendation(anomalyType: string, source: string, threatId?: string): Promise<{ success: boolean; message: string }> {
  return api.applyRecommendation({ anomalyType, source, threatId });
}

/**
 * Applies a finding's recommendation with everything the finding knows about
 * where it happened. An unlisted_route fix creates a route for requestUri on
 * entrypoint, so sending only the source -- the client's address -- gave it
 * nothing to create.
 */
export async function applyAnomalyFix(
  anomaly: Pick<Anomaly, "type" | "source" | "id" | "requestUri" | "entrypoint" | "host">,
): Promise<{ success: boolean; message: string }> {
  return api.applyRecommendation({
    anomalyType: anomaly.type,
    source: anomaly.source,
    threatId: anomaly.id,
    requestUri: anomaly.requestUri,
    entrypoint: anomaly.entrypoint,
    host: anomaly.host,
  });
}

export async function mitigateThreat(req: MitigateThreatRequest): Promise<MitigateThreatResponse> {
  return api.mitigateThreat(req);
}

export async function removeMitigatedThreat(req: RemoveMitigatedThreatRequest): Promise<RemoveMitigatedThreatResponse> {
  return api.removeMitigatedThreat(req);
}

export async function getCloudflareIPs(): Promise<GetCloudflareIPsResponse> {
  return api.getCloudflareIPs({});
}

export async function traceRoute(ip: string): Promise<TraceRouteResponse> {
  return api.traceRoute({ ip });
}

export async function validateCORS(req: ValidateCORSRequest): Promise<ValidateCORSResponse> {
  return api.validateCORS(req);
}

// Still REST: the request carries an enum, and the hand-written
// ClamavInstallationMode is a different type from the generated
// ClamavConfig_InstallationMode. They are almost certainly the same numbers,
// which is exactly why a cast would be the wrong fix — it would assert that
// without checking, on the one field that decides how ClamAV gets installed.
export async function installClamav(req: InstallClamavRequest): Promise<InstallClamavResponse> {
  const res = await apiFetch("/v1/security/clamav/install", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// Reverted to REST after moving it to Connect in #30 broke ClamAV uninstall in
// CI, and only in CI: "Install Now" never reappeared, so the uninstall did not
// complete. Local runs on macOS passed every time, which is how it got merged.
// The CI difference is the install path — apt-get there, brew locally — so the
// two exercise different mock branches, and something about this call over
// Connect does not survive the Linux one.
//
// Reverting rather than debugging further: this is the control that removes
// antivirus from a host, the failure is reproducible in CI and not locally,
// and the four other conversions in #30 are unaffected. It can move again
// once someone can watch it fail.
export async function uninstallClamav(req: { sudoPassword?: string }): Promise<UninstallClamavResponse> {
  const res = await apiFetch("/v1/security/clamav/uninstall", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function runDeepScan(): Promise<RunDeepScanResponse> {
  return api.runDeepScan({});
}
