// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import type { SetupRequest } from "../types/gateon";
import { configuredDatabaseLabel, configuredLoggingLabel, keepConfigured, type SetupStatus } from "./setupWizard";

const wizard: SetupRequest = {
  adminUsername: "admin",
  adminPassword: "a-long-passphrase",
  pasetoSecret: "k".repeat(32),
  managementBind: "0.0.0.0",
  managementPort: "8080",
  setupToken: "tok",
  databaseConfig: { driver: "sqlite", sqlitePath: "gateon.db" },
  loggingDatabaseUrl: "logs.db",
};

const nothingKept: SetupStatus = {
  databaseConfigured: false,
  databaseDriver: "",
  databaseDescription: "",
  loggingDatabaseDescription: "",
  sessionKeyFromEnvironment: false,
};

describe("keepConfigured", () => {
  test("a configured database is not replaced by the wizard's default (ADR 0057)", () => {
    const sent = keepConfigured(wizard, { ...nothingKept, databaseConfigured: true, databaseDriver: "postgres" });
    expect(sent.databaseConfig).toBeUndefined();
    expect(sent.databaseUrl).toBeUndefined();
    expect(sent.loggingDatabaseUrl).toBeUndefined();
    expect(sent.loggingDatabaseConfig).toBeUndefined();
    expect(sent.adminUsername).toBe("admin");
  });

  test("a session key from the environment is not overwritten by a generated one", () => {
    const sent = keepConfigured(wizard, { ...nothingKept, sessionKeyFromEnvironment: true });
    expect(sent.pasetoSecret).toBe("");
    expect(sent.databaseConfig).toEqual({ driver: "sqlite", sqlitePath: "gateon.db" });
  });

  test("a first run sends what the wizard chose", () => {
    expect(keepConfigured(wizard, nothingKept)).toEqual(wizard);
    expect(keepConfigured(wizard, null)).toEqual(wizard);
  });
});

describe("configuredDatabaseLabel", () => {
  test("names the engine and, with the token, where it is", () => {
    expect(configuredDatabaseLabel({ databaseDriver: "postgres", databaseDescription: "db.internal:5432/gateon" })).toBe(
      "PostgreSQL db.internal:5432/gateon",
    );
    expect(configuredDatabaseLabel({ databaseDriver: "sqlite", databaseDescription: "" })).toBe("SQLite");
  });

  test("the logging database defaults to the management one", () => {
    expect(configuredLoggingLabel(nothingKept)).toBe("the same database as management");
    expect(configuredLoggingLabel({ ...nothingKept, loggingDatabaseDescription: "logs.db" })).toBe("logs.db");
  });
});
