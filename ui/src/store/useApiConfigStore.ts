import { create } from "zustand";

const DEFAULT_API_URL =
  import.meta.env.VITE_API_URL || "http://localhost:8080";
const DEFAULT_REFRESH_INTERVAL = 10;

function loadFromStorage() {
  if (typeof localStorage === "undefined") {
    return { apiUrl: DEFAULT_API_URL, refreshInterval: DEFAULT_REFRESH_INTERVAL };
  }
  const savedUrl = localStorage.getItem("gateon_api_url");
  const savedInterval = localStorage.getItem("gateon_refresh_interval");
  const apiUrl = savedUrl || DEFAULT_API_URL;
  const parsed = savedInterval ? parseInt(savedInterval, 10) : DEFAULT_REFRESH_INTERVAL;
  const refreshInterval = Number.isFinite(parsed)
    ? Math.min(60, Math.max(1, parsed))
    : DEFAULT_REFRESH_INTERVAL;
  return { apiUrl, refreshInterval };
}

interface ApiConfigState {
  apiUrl: string;
  refreshInterval: number;
  setApiConfig: (apiUrl: string, refreshInterval: number) => void;
}

export const useApiConfigStore = create<ApiConfigState>((set) => ({
  ...loadFromStorage(),
  setApiConfig: (apiUrl, refreshInterval) => {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem("gateon_api_url", apiUrl);
      localStorage.setItem(
        "gateon_refresh_interval",
        String(Math.min(60, Math.max(1, refreshInterval)))
      );
    }
    set({
      apiUrl,
      refreshInterval: Math.min(60, Math.max(1, refreshInterval)),
    });
  },
}));

/** Returns the API base URL for fetch/WebSocket (no trailing slash). */
export function getApiBaseUrl(): string {
  const url = useApiConfigStore.getState().apiUrl || DEFAULT_API_URL;
  return url.replace(/\/$/, "");
}
