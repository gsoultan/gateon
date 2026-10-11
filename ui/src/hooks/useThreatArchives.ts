// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "../services/client";
import type { Anomaly } from "../services/gen/gateon/v1/diagnostics_pb";

// Archived security threats live in files on the gateway, not in the
// database: both calls read those files, so browsing the archive costs the
// database nothing.

export interface ThreatArchiveFile {
  filename: string;
  size: number;
  createdAt: string;
  firstAt: string;
  lastAt: string;
}

export interface ThreatArchivePage<T> {
  items: T[];
  totalCount: number;
}

// The size is an int64, which arrives as bigint; the page divides it.
export async function fetchThreatArchives(limit: number, offset: number): Promise<ThreatArchivePage<ThreatArchiveFile>> {
  const res = await api.listSecurityThreatArchives({ limit, offset });
  return {
    items: res.archives.map((a) => ({
      filename: a.filename,
      size: Number(a.size),
      createdAt: a.createdAt,
      firstAt: a.firstAt,
      lastAt: a.lastAt,
    })),
    totalCount: res.totalCount,
  };
}

export function useThreatArchives(limit: number, offset: number) {
  return useQuery({
    queryKey: ["threat-archives", limit, offset],
    queryFn: () => fetchThreatArchives(limit, offset),
    placeholderData: keepPreviousData,
  });
}

export function useThreatArchive(filename: string | null, search: string, limit: number, offset: number) {
  return useQuery<ThreatArchivePage<Anomaly>>({
    queryKey: ["threat-archive", filename, search, limit, offset],
    queryFn: async () => {
      const res = await api.getSecurityThreatArchive({ filename: filename ?? "", search, limit, offset });
      return { items: res.threats, totalCount: res.totalCount };
    },
    enabled: !!filename,
    placeholderData: keepPreviousData,
  });
}
