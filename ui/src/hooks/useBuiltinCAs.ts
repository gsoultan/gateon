// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from "@tanstack/react-query";
import { api } from "../services/client";
import type { BuiltinCertificateAuthority } from "../services/gen/gateon/v1/tls_pb";

/** The catalog is a handful of entries compiled into the binary; one page holds it. */
const PAGE_SIZE = 50;

export const BUILTIN_CAS_KEY = ["builtin-cas"] as const;

/**
 * The CA certificates compiled into the gateway, for naming in a ca_file
 * instead of uploading one. They change only with a release, so the answer is
 * kept for the session rather than refetched.
 */
export function useBuiltinCAs(enabled: boolean) {
  return useQuery<BuiltinCertificateAuthority[]>({
    queryKey: BUILTIN_CAS_KEY,
    queryFn: async () => {
      const res = await api.listBuiltinCertificateAuthorities({ page: 0, pageSize: PAGE_SIZE });
      return res.authorities;
    },
    enabled,
    staleTime: Infinity,
  });
}
