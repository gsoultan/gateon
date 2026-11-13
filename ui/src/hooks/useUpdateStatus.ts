// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/client";
import type { UpdateStatus } from "../services/gen/gateon/v1/status_pb";

const queryKey = ["update-status"];

// The gateway asks its release source once a day, so the answer changes about
// that often. Half an hour keeps a dashboard left open from showing a stale
// "up to date" all day without asking on every page.
const REFRESH_MS = 30 * 60 * 1000;

/** What the gateway's last release check found (ADR 0085). */
export function useUpdateStatus() {
  return useQuery<UpdateStatus | undefined>({
    queryKey,
    queryFn: async () => (await api.getUpdateStatus({})).status,
    staleTime: REFRESH_MS,
    refetchInterval: REFRESH_MS,
  });
}

/** Asks the release source now; the status everyone reads becomes the answer. */
export function useCheckForUpdate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => (await api.checkForUpdate({})).status,
    onSuccess: (status) => queryClient.setQueryData(queryKey, status),
  });
}
