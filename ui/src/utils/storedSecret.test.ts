// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import {
  STORED_SECRET_SENTINEL,
  hasStoredSecret,
  isSecretReference,
  isStoredSecret,
  replacementValue,
} from "./storedSecret";

describe("stored secrets", () => {
  test("the placeholder is recognised, and nothing else is", () => {
    expect(isStoredSecret(STORED_SECRET_SENTINEL)).toBe(true);
    expect(isStoredSecret("")).toBe(false);
    expect(isStoredSecret(undefined)).toBe(false);
    expect(isStoredSecret("a-real-password")).toBe(false);
  });

  test("a connection URL with its password stored is recognised", () => {
    expect(hasStoredSecret(`postgres://gateon:${STORED_SECRET_SENTINEL}@db/gateon`)).toBe(true);
    expect(hasStoredSecret("postgres://db/gateon")).toBe(false);
  });

  test("references are told apart from values", () => {
    expect(isSecretReference("$env:GATEON_REDIS_PASSWORD")).toBe(true);
    expect(isSecretReference("$vault:secret/data/x#y")).toBe(true);
    expect(isSecretReference("$aws-sm:name#key")).toBe(true);
    expect(isSecretReference("env:NOT_A_REFERENCE")).toBe(false);
  });

  // Starting a replacement and saving without typing must keep the stored
  // secret: for an optional credential "" would clear it.
  test("an empty replacement keeps the stored secret", () => {
    expect(replacementValue("")).toBe(STORED_SECRET_SENTINEL);
    expect(replacementValue("new-value")).toBe("new-value");
  });
});
