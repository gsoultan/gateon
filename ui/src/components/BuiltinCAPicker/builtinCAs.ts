// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  BuiltinCertificateAuthorityUse,
  type BuiltinCertificateAuthority,
} from "../../services/gen/gateon/v1/tls_pb";

export type BuiltinCAUse = "server-chain" | "client-ca";

const wantedUse: Record<BuiltinCAUse, BuiltinCertificateAuthorityUse> = {
  "server-chain": BuiltinCertificateAuthorityUse.SERVER_CHAIN,
  "client-ca": BuiltinCertificateAuthorityUse.CLIENT_CA,
};

type ExpiryFields = Pick<BuiltinCertificateAuthority, "notAfter" | "expired" | "expiringSoon" | "keyAlgorithm">;

/** The line under a CA's name: red once expired, orange inside the warning window. */
export function expiryLine(ca: ExpiryFields): { text: string; color: string } {
  const date = ca.notAfter.slice(0, 10);
  if (ca.expired) return { text: `Expired ${date}`, color: "red" };
  if (ca.expiringSoon) return { text: `Expires ${date}`, color: "orange" };
  return { text: `${ca.keyAlgorithm} · expires ${date}`, color: "dimmed" };
}

/** The CAs meant for the field come first; the rest keep the gateway's order. */
export function orderForUse<T extends Pick<BuiltinCertificateAuthority, "use">>(cas: readonly T[], use: BuiltinCAUse): T[] {
  const want = wantedUse[use];
  return [...cas].sort((a, b) => Number(b.use === want) - Number(a.use === want));
}

/** The prefix a ca_file value carries when it names a built-in CA. */
export const BUILTIN_PREFIX = "builtin:";

export function isBuiltinRef(caFile: string): boolean {
  return caFile.startsWith(BUILTIN_PREFIX);
}

/** The caveat of the built-in CA caFile names, or "" when it has none or names none. */
export function caveatFor(cas: readonly Pick<BuiltinCertificateAuthority, "ref" | "caveat">[], caFile: string): string {
  return cas.find((ca) => ca.ref === caFile)?.caveat ?? "";
}
