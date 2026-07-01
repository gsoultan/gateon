import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./api";
import type { ListAuditArchivesResponse, GetAuditArchiveResponse, AuditLog } from "../types/gateon";

export function useAuditArchives() {
  return useQuery<ListAuditArchivesResponse>({
    queryKey: ["audit-archives"],
    queryFn: async () => {
      const res = await apiFetch("/v1/audit/archives");
      if (!res.ok) {
        throw new Error("Failed to fetch audit archives");
      }
      return res.json();
    },
  });
}

export async function getAuditArchive(filename: string): Promise<AuditLog[]> {
  const res = await apiFetch(`/v1/audit/archives/${filename}`);
  if (!res.ok) {
    throw new Error("Failed to fetch audit archive content");
  }
  const data: GetAuditArchiveResponse = await res.json();
  return data.logs;
}
