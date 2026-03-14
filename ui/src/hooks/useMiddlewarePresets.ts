import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { MiddlewarePreset } from "../types/gateon";

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
