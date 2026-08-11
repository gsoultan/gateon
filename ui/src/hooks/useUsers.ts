// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { apiFetch, buildQueryString } from "./api";
import type { PaginationParams } from "./api";
import type { ListUsersResponse } from "../types/gateon";

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
