// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { TlsClientConfig } from "../types/gateon";

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
  };
}
