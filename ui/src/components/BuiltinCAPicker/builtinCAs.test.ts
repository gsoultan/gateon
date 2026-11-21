// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { caveatFor, expiryLine, isBuiltinRef, orderForUse } from "./builtinCAs";
import { BuiltinCertificateAuthorityUse } from "../../services/gen/gateon/v1/tls_pb";

const base = { notAfter: "2029-08-15T17:00:00Z", keyAlgorithm: "ECDSA", expired: false, expiringSoon: false };

describe("expiryLine", () => {
  // A built-in CA can only be replaced by a release, so a stale one has to be
  // visible where it is chosen, not discovered in a failed handshake.
  test("an expired CA says so in red", () => {
    expect(expiryLine({ ...base, expired: true, expiringSoon: true })).toEqual({ text: "Expired 2029-08-15", color: "red" });
  });
  test("a CA inside the warning window is orange", () => {
    expect(expiryLine({ ...base, expiringSoon: true })).toEqual({ text: "Expires 2029-08-15", color: "orange" });
  });
  test("a current CA shows its key type and date", () => {
    expect(expiryLine(base)).toEqual({ text: "ECDSA · expires 2029-08-15", color: "dimmed" });
  });
});

describe("orderForUse", () => {
  const cas = [
    { ref: "rsa", use: BuiltinCertificateAuthorityUse.SERVER_CHAIN },
    { ref: "ecc", use: BuiltinCertificateAuthorityUse.SERVER_CHAIN },
    { ref: "aop", use: BuiltinCertificateAuthorityUse.CLIENT_CA },
  ];
  test("a client-CA field lists the client CA first and keeps the rest in order", () => {
    expect(orderForUse(cas, "client-ca").map((c) => c.ref)).toEqual(["aop", "rsa", "ecc"]);
  });
  test("a chain field keeps the origin CAs first", () => {
    expect(orderForUse(cas, "server-chain").map((c) => c.ref)).toEqual(["rsa", "ecc", "aop"]);
  });
});

describe("caveatFor", () => {
  const cas = [
    { ref: "builtin:cloudflare-origin-pull-ca", caveat: "Shared by every Cloudflare account" },
    { ref: "builtin:cloudflare-origin-ca-ecc", caveat: "" },
  ];

  test("names the chosen built-in CA's caveat", () => {
    expect(caveatFor(cas, "builtin:cloudflare-origin-pull-ca")).toContain("every Cloudflare account");
  });

  test("says nothing for a CA without one, an unknown ref, or a path", () => {
    expect(caveatFor(cas, "builtin:cloudflare-origin-ca-ecc")).toBe("");
    expect(caveatFor(cas, "builtin:nope")).toBe("");
    expect(caveatFor(cas, "certs/ca.pem")).toBe("");
    expect(isBuiltinRef("certs/ca.pem")).toBe(false);
    expect(isBuiltinRef("builtin:cloudflare-origin-pull-ca")).toBe(true);
  });
});
