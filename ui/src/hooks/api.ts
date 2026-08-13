// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// These six call RPCs that already exist on ApiService. Going through the
// Connect client instead of hand-rolled fetch drops the duplicate wire format
// that both of today's API bugs lived in.
import { api } from "../services/client";
import { useAuthStore } from "../store/useAuthStore";
import { getApiBaseUrl } from "../store/useApiConfigStore";
import type {
  SetupRequest,
  SetupResponse,
  DatabaseConfig,
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
} from "../types/gateon";

export type PaginationParams = {
  page?: number;
  pageSize?: number;
  search?: string;
};

export type RouteListParams = PaginationParams & {
  type?: string;
  host?: string;
  path?: string;
  status?: string;
};

function buildQueryStringInternal(params?: PaginationParams | RouteListParams): string {
  if (!params) return "";
  const q = new URLSearchParams();
  if (params.page !== undefined) q.set("page", params.page.toString());
  if (params.pageSize !== undefined)
    q.set("pageSize", params.pageSize.toString());
  if (params.search) q.set("search", params.search);
  const rp = params as RouteListParams;
  if (rp.type) q.set("type", rp.type);
  if (rp.host) q.set("host", rp.host);
  if (rp.path) q.set("path", rp.path);
  if (rp.status) q.set("status", rp.status);
  const s = q.toString();
  return s ? `?${s}` : "";
}

export { buildQueryStringInternal as buildQueryString };

export function getApiUrl(path: string): string {
  const base = getApiBaseUrl();
  const token = useAuthStore.getState().token;
  const url = new URL(`${base}${path}`, window.location.origin);
  if (token && token !== "__cookie__") {
    url.searchParams.set("token", token);
  }
  return url.toString();
}

export async function apiFetch(path: string, options: RequestInit = {}) {
  const base = getApiBaseUrl();
  const token = useAuthStore.getState().token;
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  };
  if (token && token !== "__cookie__") {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${base}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });
  if (res.status === 401 && path !== "/v1/setup/required") {
    useAuthStore.getState().logout();
  }
  return res;
}

/** Returns a user-friendly message for API errors (e.g. 403 insufficient permissions). */
export function getApiErrorMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err ?? "");
  try {
    const data = JSON.parse(raw);
    if (
      data?.error === "insufficient permissions" ||
      data?.error === "permission denied"
    ) {
      return "Insufficient permissions. You do not have access to perform this action.";
    }
    return data?.error || raw;
  } catch {
    return raw || "Request failed";
  }
}

/** Attempt to restore session from HttpOnly cookie (e.g. after refresh). */
export async function restoreSessionFromCookie(): Promise<boolean> {
  const res = await apiFetch("/v1/me");
  if (!res.ok) return false;
  const data = await res.json();
  const user = data?.user;
  if (user?.id && user?.username) {
    useAuthStore.getState().setAuth("__cookie__", user);
    return true;
  }
  return false;
}

export async function setupGateon(req: SetupRequest): Promise<SetupResponse> {
  return api.setup(req);
}

export async function testDbConnection(payload: {
  databaseUrl?: string;
  databaseConfig?: DatabaseConfig;
}): Promise<boolean> {
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

export async function uninstallClamav(req: { sudoPassword?: string }): Promise<UninstallClamavResponse> {
  return api.uninstallClamav(req);
}

export async function runDeepScan(): Promise<RunDeepScanResponse> {
  return api.runDeepScan({});
}
