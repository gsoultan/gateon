// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// The plain-fetch half of the API client. It imports nothing from Connect or
// the generated protobuf code, so the router, the sign-in page and the session
// check can use it without the ~45 KB (gzip) RPC client in the first load.
// hooks/api.ts re-exports all of it.
import { useAuthStore } from "../store/useAuthStore";
import { getApiBaseUrl } from "../store/useApiConfigStore";

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

/**
 * Whether a request body needs a Content-Type the caller did not give. A
 * string body is JSON everywhere this client sends one, but fetch labels a
 * string text/plain -- the type a page on any other site can also send, which
 * the gateway refuses on a write (ADR 0041). FormData and Blob bodies carry
 * their own type, and a request with no body needs none.
 */
function needsJsonContentType(options: RequestInit, headers: Record<string, string>): boolean {
  if (typeof options.body !== "string") return false;
  return !Object.keys(headers).some((h) => h.toLowerCase() === "content-type");
}

export async function apiFetch(path: string, options: RequestInit = {}) {
  const base = getApiBaseUrl();
  const token = useAuthStore.getState().token;
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  };
  if (needsJsonContentType(options, headers)) {
    headers["Content-Type"] = "application/json";
  }
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
