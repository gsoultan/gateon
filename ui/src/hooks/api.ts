import { useAuthStore } from "../store/useAuthStore";
import { getApiBaseUrl } from "../store/useApiConfigStore";
import type { SetupRequest, SetupResponse, DatabaseConfig, GetDiagnosticsResponse } from "../types/gateon";

export type PaginationParams = {
  page?: number;
  page_size?: number;
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
  if (params.page_size !== undefined)
    q.set("page_size", params.page_size.toString());
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
  const res = await apiFetch("/v1/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function testDbConnection(payload: {
  database_url?: string;
  database_config?: DatabaseConfig;
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

export async function getDiagnostics(): Promise<GetDiagnosticsResponse> {
  const res = await apiFetch("/v1/diagnostics");
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
