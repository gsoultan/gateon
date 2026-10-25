// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { TlsClientCertSelectionStrategy, type TlsClientConfig, type TlsClientIdentity } from "../types/gateon";

/**
 * The backend TLS settings a service form starts from.
 *
 * skipVerify is false. It used to default to true, so switching backend TLS on
 * in the form also switched certificate verification off: an operator who only
 * wanted TLS to the backend got a connection any interceptor could answer. The
 * gateway itself verifies unless told otherwise; the form must not tell it
 * otherwise by default.
 */
export function defaultTlsClientConfig(): TlsClientConfig {
  return {
    enabled: false,
    certFile: "",
    keyFile: "",
    caFile: "",
    skipVerify: false,
    serverName: "",
    certSelectionStrategy: TlsClientCertSelectionStrategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC,
    certIdentities: [],
  };
}

export function emptyClientIdentity(): TlsClientIdentity {
  return { id: "", certFile: "", keyFile: "", matchHosts: [], matchHeader: "", matchHeaderValue: "" };
}

/**
 * backendTlsProblem mirrors the gateway's save-time refusal of identities it
 * would never present, so the form can say so before the request. Whether the
 * files load is only known on the gateway, which answers that itself.
 */
export function backendTlsProblem(cfg: TlsClientConfig | undefined): string | null {
  if (!cfg?.enabled) return null;
  if (!cfg.certFile !== !cfg.keyFile) {
    return "Backend TLS needs both a client certificate and its key, or neither.";
  }
  const identities = cfg.certIdentities ?? [];
  if (identities.length === 0) return null;
  const strategy = cfg.certSelectionStrategy ?? TlsClientCertSelectionStrategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC;
  if (strategy === TlsClientCertSelectionStrategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC) {
    return "Per-request certificates are chosen by host or by header. Choose a selection strategy or remove them.";
  }
  for (const [i, item] of identities.entries()) {
    const name = item.id || `#${i + 1}`;
    if (!item.certFile || !item.keyFile) return `Certificate ${name} needs both a certificate and a key.`;
    if (strategy === TlsClientCertSelectionStrategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST && !item.matchHosts?.length) {
      return `Certificate ${name} matches no host, so it would never be presented.`;
    }
    if (strategy === TlsClientCertSelectionStrategy.TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER && !item.matchHeader) {
      return `Certificate ${name} matches no header, so it would never be presented.`;
    }
  }
  return null;
}
