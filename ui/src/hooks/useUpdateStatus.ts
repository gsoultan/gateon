// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/client";
import type { UpdateStatus } from "../services/gen/gateon/v1/status_pb";
import { upgradeInProgress } from "../components/settings/update/upgradeView";

const queryKey = ["update-status"];

// The gateway asks its release source once a day, so the answer changes about
// that often. Half an hour keeps a dashboard left open from showing a stale
// "up to date" all day without asking on every page.
const REFRESH_MS = 30 * 60 * 1000;

// While an install runs the answer changes every few seconds, and for part of
// that time the gateway is restarting and does not answer at all.
const INSTALLING_MS = 2000;

/**
 * What the gateway's last release check found (ADR 0085), and how an install
 * stands (ADR 0087). While one is running it asks every two seconds and keeps
 * asking through the restart; the last answer stays on screen meanwhile.
 */
export function useUpdateStatus() {
  return useQuery<UpdateStatus | undefined>({
    queryKey,
    queryFn: async () => (await api.getUpdateStatus({})).status,
    staleTime: (query) => (upgradeInProgress(query.state.data?.upgrade?.current?.phase) ? 0 : REFRESH_MS),
    refetchInterval: (query) => (upgradeInProgress(query.state.data?.upgrade?.current?.phase) ? INSTALLING_MS : REFRESH_MS),
  });
}

/** Starts installing a release; the status everyone reads becomes the answer. */
export function useInstallUpdate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (version: string) => (await api.installUpdate({ version })).status,
    onSuccess: (status) => queryClient.setQueryData(queryKey, status),
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
