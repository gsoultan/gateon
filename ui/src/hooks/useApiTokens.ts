// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { api } from "../services/client";
import type { TokenRow } from "../components/apiTokens";

/** The gateway keeps at most 50 tokens, so one page holds them all. */
const PAGE_SIZE = 50;

export const API_TOKENS_KEY = ["api-tokens"] as const;

/** The scrape credentials, newest first, without their secrets (ADR 0050). */
export function useApiTokens() {
  return useQuery<TokenRow[]>({
    queryKey: API_TOKENS_KEY,
    queryFn: async () => {
      const res = await api.listApiTokens({ page: 0, pageSize: PAGE_SIZE });
      return res.tokens.map(({ id, name, scopes, hint, createdBy, createdAt, lastUsedAt, expiresAt }) => ({
        id,
        name,
        scopes: [...scopes],
        hint,
        createdBy,
        createdAt,
        lastUsedAt,
        expiresAt,
      }));
    },
  });
}

/** Issues a token; the secret in the answer is the only copy there is. */
export async function createApiToken(name: string, scopes: string[], ttlDays: number) {
  const res = await api.createApiToken({ name, scopes, ttlDays });
  return { name: res.token?.name ?? name, secret: res.secret };
}

/** Revokes a token; the next request with it is refused. */
export async function revokeApiToken(id: string) {
  await api.revokeApiToken({ id });
}
