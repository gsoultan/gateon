// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { expect, test } from "bun:test";
import { TlsClientCertSelectionStrategy as S } from "../types/gateon";
import { backendTlsProblem, defaultTlsClientConfig } from "./serviceTlsDefaults";

// Turning backend TLS on in the service form must not also turn certificate
// verification off, which the old default did.
test("backend TLS starts with certificate verification on", () => {
  expect(defaultTlsClientConfig().skipVerify).toBe(false);
});

const id = { id: "a", certFile: "/a.crt", keyFile: "/a.key" };

test("the form refuses what the gateway refuses", () => {
  const on = { ...defaultTlsClientConfig(), enabled: true };
  expect(backendTlsProblem({ ...on, certFile: "/c.crt" })).toContain("both");
  expect(backendTlsProblem({ ...on, certIdentities: [{ ...id, matchHeader: "X-T" }] })).toContain("strategy");
  expect(backendTlsProblem({ ...on, certSelectionStrategy: S.TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST, certIdentities: [id] }))
    .toContain("matches no host");
  expect(backendTlsProblem({ ...on, certSelectionStrategy: S.TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER, certIdentities: [id] }))
    .toContain("matches no header");
});

test("the form keeps what the gateway presents", () => {
  const on = { ...defaultTlsClientConfig(), enabled: true };
  expect(backendTlsProblem(on)).toBeNull();
  expect(backendTlsProblem({ ...defaultTlsClientConfig(), certFile: "/c.crt" })).toBeNull();
  expect(backendTlsProblem({ ...on, certSelectionStrategy: S.TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST,
    certIdentities: [{ ...id, matchHosts: ["a.test"] }] })).toBeNull();
});
