import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAuthStore } from "../store/useAuthStore";
import type {
  StatusResponse,
  Route,
  Service,
  TargetStats,
  EntryPoint,
  GlobalConfig,
  Middleware,
  TLSOption,
  Certificate,
  PathStats,
  LimitStats,
  MiddlewarePreset,
  User,
  IsSetupRequiredResponse,
  SetupRequest,
  SetupResponse,
  ListRoutesResponse,
  ListServicesResponse,
  ListMiddlewaresResponse,
  ListEntryPointsResponse,
  ListTLSOptionsResponse,
  ListUsersResponse,
} from "../types/gateon";

export type PaginationParams = {
  page?: number;
  page_size?: number;
  search?: string;
};

function buildQueryString(params?: PaginationParams) {
  if (!params) return "";
  const q = new URLSearchParams();
  if (params.page !== undefined) q.set("page", params.page.toString());
  if (params.page_size !== undefined)
    q.set("page_size", params.page_size.toString());
  if (params.search) q.set("search", params.search);
  const s = q.toString();
  return s ? `?${s}` : "";
}

const API_BASE_URL = import.meta.env.VITE_API_URL || "";

export async function apiFetch(path: string, options: RequestInit = {}) {
  const token = useAuthStore.getState().token;
  const headers: Record<string, string> = { ...(options.headers as Record<string, string>) };
  if (token && token !== "__cookie__") {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
    credentials: "include", // send HttpOnly session cookie when present
  });
  if (res.status === 401 && path !== "/v1/setup/required") {
    useAuthStore.getState().logout();
  }
  return res;
}

export function useGateonStatus() {
  return useQuery<StatusResponse>({
    queryKey: ["status"],
    queryFn: async () => {
      const res = await apiFetch("/v1/status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: 10000,
  });
}

export function useRoutes(params?: PaginationParams) {
  return useQuery<ListRoutesResponse>({
    queryKey: ["routes", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/routes${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}

export function useServices(params?: PaginationParams) {
  return useQuery<ListServicesResponse>({
    queryKey: ["services", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/services${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}

export function useRouteStats(routeId: string) {
  return useQuery<TargetStats[]>({
    queryKey: ["stats", routeId],
    queryFn: async () => {
      const res = await apiFetch(
        `/v1/routes/${encodeURIComponent(routeId)}/stats`,
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: 5000,
  });
}

export function useLimitStats() {
  return useQuery<LimitStats>({
    queryKey: ["limit-stats"],
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/limit-stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: 5000,
  });
}

function sumLimitStats(stats: LimitStats | undefined): number {
  if (!stats) return 0;
  const r = (stats.rate_limit_rejected && typeof stats.rate_limit_rejected === "object")
    ? Object.values(stats.rate_limit_rejected).reduce((a, b) => a + Number(b), 0) : 0;
  const i = (stats.inflight_rejected && typeof stats.inflight_rejected === "object")
    ? Object.values(stats.inflight_rejected).reduce((a, b) => a + Number(b), 0) : 0;
  const b = (stats.buffering_rejected && typeof stats.buffering_rejected === "object")
    ? Object.values(stats.buffering_rejected).reduce((a, v) => a + Number(v), 0) : 0;
  return r + i + b;
}

const LIMIT_HISTORY_LEN = 24;

/** Rolling delta history of limit rejections per poll interval (e.g. 5s). */
export function useLimitStatsHistory() {
  const { data, ...rest } = useLimitStats();
  const [history, setHistory] = useState<number[]>([]);
  const prevTotal = useRef<number | null>(null);

  useEffect(() => {
    if (data == null) return;
    const total = sumLimitStats(data);
    if (prevTotal.current !== null) {
      const delta = Math.max(0, total - prevTotal.current);
      setHistory((h) => [...h.slice(-(LIMIT_HISTORY_LEN - 1)), delta]);
    }
    prevTotal.current = total;
  }, [data]);

  return { data, history, ...rest };
}

/** Attempt to restore session from HttpOnly cookie (e.g. after refresh). */
export async function restoreSessionFromCookie(): Promise<boolean> {
  const res = await apiFetch("/v1/me");
  if (!res.ok) return false;
  const data = await res.json();
  const user = data?.user;
  if (user?.id && user?.username) {
    // Use sentinel so beforeLoad passes; API uses cookie via credentials: 'include'
    useAuthStore.getState().setAuth("__cookie__", user);
    return true;
  }
  return false;
}

export function useMiddlewarePresets() {
  return useQuery<MiddlewarePreset[]>({
    queryKey: ["middleware-presets"],
    queryFn: async () => {
      const res = await apiFetch("/v1/middlewares/presets");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}

export function usePathStats() {
  return useQuery<PathStats[]>({
    queryKey: ["path-stats"],
    queryFn: async () => {
      const res = await apiFetch("/v1/diag/path-stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    refetchInterval: 5000,
  });
}

export function useEntryPoints(params?: PaginationParams) {
  return useQuery<ListEntryPointsResponse>({
    queryKey: ["entrypoints", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/entrypoints${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}

export function useGateonConfig() {
  return useQuery<GlobalConfig>({
    queryKey: ["config"],
    queryFn: async () => {
      const res = await apiFetch("/v1/global");
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
  });
}

export function useMiddlewares(params?: PaginationParams) {
  return useQuery<ListMiddlewaresResponse>({
    queryKey: ["middlewares", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/middlewares${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}

export function useTLSOptions(params?: PaginationParams) {
  return useQuery<ListTLSOptionsResponse>({
    queryKey: ["tlsoptions", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/tlsoptions${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}

export function useCertificates() {
  return useQuery<{ certificates: Certificate[] }>({
    queryKey: ["certificates"],
    queryFn: async () => {
      const res = await apiFetch("/v1/global");
      if (!res.ok) throw new Error(await res.text());
      const config: GlobalConfig = await res.json();
      return { certificates: config.tls?.certificates || [] };
    },
  });
}

export function useUsers(params?: PaginationParams) {
  return useQuery<ListUsersResponse>({
    queryKey: ["users", params],
    queryFn: async () => {
      const res = await apiFetch(`/v1/users${buildQueryString(params)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
  });
}

export function useIsSetupRequired() {
  return useQuery<IsSetupRequiredResponse>({
    queryKey: ["setup-required"],
    queryFn: async () => {
      const res = await apiFetch("/v1/setup/required");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    retry: false,
  });
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
