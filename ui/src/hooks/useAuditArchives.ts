// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { api } from "../services/client";
import type { ListAuditArchivesResponse, AuditLog } from "../types/gateon";

// Both calls go through the generated client, whose RPCs answer in the shapes
// this page reads. The REST routes did not: the list encoded the archives'
// proto structs with encoding/json, so every createdAt arrived as created_at
// and rendered blank, and an archive came back as the bare array it holds,
// which has no `logs` -- opening or downloading one showed nothing.

// fetchAuditArchives lists the archives with size as a number: it is an int64,
// which arrives as bigint, and the page divides it.
export async function fetchAuditArchives(): Promise<ListAuditArchivesResponse> {
  const res = await api.listAuditArchives({});
  return {
    archives: res.archives.map((a) => ({ filename: a.filename, size: Number(a.size), createdAt: a.createdAt })),
  };
}

export function useAuditArchives() {
  return useQuery<ListAuditArchivesResponse>({
    queryKey: ["audit-archives"],
    queryFn: fetchAuditArchives,
  });
}

// getAuditArchive returns plain entries: the page downloads them through
// JSON.stringify, which would write a generated message's $typeName into the
// file.
export async function getAuditArchive(filename: string): Promise<AuditLog[]> {
  const res = await api.getAuditArchive({ filename });
  return res.logs.map(({ id, userId, action, resource, details, timestamp, ipAddress, signature }) => ({
    id,
    userId,
    action,
    resource,
    details,
    timestamp,
    ipAddress,
    signature,
  }));
}
