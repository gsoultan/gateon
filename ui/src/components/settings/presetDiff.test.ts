// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { presetChanges } from "./presetDiff";
import { withPreset } from "./tabs/settingsState";
import type { GlobalConfig } from "../../types/gateon";

describe("presetChanges", () => {
  test("lists only the leaves that differ, with their paths", () => {
    const changes = presetChanges({ log: { level: "info", format: "json" }, tls: { enabled: true } }, { log: { level: "debug", format: "json" }, tls: { enabled: true } });
    expect(changes).toEqual([{ path: "log.level", from: "info", to: "debug" }]);
  });

  test("a field the preset adds reads as unset before", () => {
    expect(presetChanges({}, { redis: { enabled: false } })).toEqual([{ path: "redis.enabled", from: "unset", to: "false" }]);
  });

  test("the development preset leaves retention and transport alone", () => {
    const config: GlobalConfig = {
      log: { level: "info", format: "json", accessLogRetentionDays: 90 },
      transport: { maxIdleConns: 500 },
      tls: { enabled: true },
      redis: { enabled: true },
      otel: { enabled: true },
    } as GlobalConfig;
    const paths = presetChanges(config, withPreset(config, "development")).map((c) => c.path);
    expect(paths).not.toContain("log.accessLogRetentionDays");
    expect(paths).not.toContain("transport.maxIdleConns");
    expect(paths).toContain("tls.enabled");
    expect(paths).toContain("log.level");
  });
});
