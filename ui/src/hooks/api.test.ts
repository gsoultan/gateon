// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import { Code, ConnectError } from "@connectrpc/connect";
import type {
  DatabaseConfig,
  DeepScanStatus,
  GetCloudflareIPsResponse,
  MitigateThreatRequest,
  MitigateThreatResponse,
  RemoveMitigatedThreatRequest,
  RemoveMitigatedThreatResponse,
  RunDeepScanResponse,
  SetupRequest,
  SetupResponse,
  TraceHop,
  TraceRouteResponse,
  ValidateCORSRequest,
  ValidateCORSResponse,
} from "../types/gateon";
import type {
  SetupRequest as WireSetupRequest,
  SetupResponse as WireSetupResponse,
} from "../services/gen/gateon/v1/auth_pb";
import type { DatabaseConfig as WireDatabaseConfig } from "../services/gen/gateon/v1/common_pb";
import type {
  MitigateThreatRequest as WireMitigateThreatRequest,
  MitigateThreatResponse as WireMitigateThreatResponse,
  RemoveMitigatedThreatRequest as WireRemoveMitigatedThreatRequest,
  RemoveMitigatedThreatResponse as WireRemoveMitigatedThreatResponse,
  TraceHop as WireTraceHop,
  TraceRouteResponse as WireTraceRouteResponse,
  ValidateCORSRequest as WireValidateCORSRequest,
  ValidateCORSResponse as WireValidateCORSResponse,
} from "../services/gen/gateon/v1/diagnostics_pb";
import type { GetCloudflareIPsResponse as WireGetCloudflareIPsResponse } from "../services/gen/gateon/v1/middleware_pb";
import type {
  DeepScanStatus as WireDeepScanStatus,
  RunDeepScanResponse as WireRunDeepScanResponse,
} from "../services/gen/gateon/v1/api_pb";
import type { Trace as WireTrace } from "../services/gen/gateon/v1/trace_pb";
import type { Trace } from "./useTraces";

// Compiles only when T is never; otherwise the type checker names what T is.
function assertNone<T extends never>(): T[] {
  return [];
}

// The client reads window.location when it is imported; there is no window
// under bun:test, and the setup RPC itself is not what is under test.
mock.module("../services/client", () => ({
  api: { setup: async () => ({ success: true, error: "" }) },
}));

const { setupGateon, getApiErrorMessage } = await import("./api");
const { queryClient } = await import("../queryClient");

describe("setupGateon", () => {
  test("forgets the cached 'setup required' answer once setup has succeeded", async () => {
    // What the root route cached before it sent the operator to /setup. The
    // route answers every later navigation from this entry without refetching,
    // so a stale `true` here bounces the post-setup navigation back to /setup.
    queryClient.setQueryData(["setup-required"], { required: true });

    await setupGateon({} as SetupRequest);

    expect(queryClient.getQueryData(["setup-required"])).toBeUndefined();
  });

  test("sends no key the proto message lacks", () => {
    // setupGateon hands this hand-written type to the generated client, which
    // serialises through the proto schema and drops a key the schema lacks --
    // as protojson does on the server -- without an error. The setup wizard's
    // logging database was sent that way and went nowhere. The check is the
    // type checker's, which `bun run build` runs first: a key missing from the
    // proto fails the build with `Type '"<key>"' does not satisfy the
    // constraint 'never'`.
    expect(assertNone<Exclude<keyof SetupRequest, keyof WireSetupRequest>>()).toEqual([]);
    expect(assertNone<Exclude<keyof DatabaseConfig, keyof WireDatabaseConfig>>()).toEqual([]);
  });
});

// The same hand-off for every hand-written type that crosses the generated
// client in this file. A request built elsewhere and passed through is not an
// object literal, so TypeScript does not check it for extra keys; a response
// read through a hand-written type is read under names nothing may send.
describe("hand-written types at the generated client", () => {
  test("carry no key the proto message lacks", () => {
    expect(assertNone<Exclude<keyof MitigateThreatRequest, keyof WireMitigateThreatRequest>>()).toEqual([]);
    expect(assertNone<Exclude<keyof RemoveMitigatedThreatRequest, keyof WireRemoveMitigatedThreatRequest>>()).toEqual([]);
    expect(assertNone<Exclude<keyof ValidateCORSRequest, keyof WireValidateCORSRequest>>()).toEqual([]);
    expect(assertNone<Exclude<keyof SetupResponse, keyof WireSetupResponse>>()).toEqual([]);
    expect(assertNone<Exclude<keyof MitigateThreatResponse, keyof WireMitigateThreatResponse>>()).toEqual([]);
    expect(assertNone<Exclude<keyof RemoveMitigatedThreatResponse, keyof WireRemoveMitigatedThreatResponse>>()).toEqual([]);
    expect(assertNone<Exclude<keyof ValidateCORSResponse, keyof WireValidateCORSResponse>>()).toEqual([]);
    expect(assertNone<Exclude<keyof GetCloudflareIPsResponse, keyof WireGetCloudflareIPsResponse>>()).toEqual([]);
    expect(assertNone<Exclude<keyof TraceRouteResponse, keyof WireTraceRouteResponse>>()).toEqual([]);
    expect(assertNone<Exclude<keyof RunDeepScanResponse, keyof WireRunDeepScanResponse>>()).toEqual([]);
    // And the messages those responses carry.
    expect(assertNone<Exclude<keyof TraceHop, keyof WireTraceHop>>()).toEqual([]);
    expect(assertNone<Exclude<keyof DeepScanStatus, keyof WireDeepScanStatus>>()).toEqual([]);
    // The traces page reads traces from the generated client as this type.
    expect(assertNone<Exclude<keyof Trace, keyof WireTrace>>()).toEqual([]);
  });
});

// A Connect call's error message is prefixed with its code, "[permission_denied]"
// and the like; the helper every page shows errors through reads the error
// itself instead.
describe("getApiErrorMessage", () => {
  test("says what a Connect error means, not its wire code", () => {
    expect(getApiErrorMessage(new ConnectError("insufficient permissions", Code.PermissionDenied))).toBe(
      "Insufficient permissions. You do not have access to perform this action.",
    );
    expect(getApiErrorMessage(new ConnectError("trace not found", Code.NotFound))).toBe("trace not found");
  });

  test("still reads the JSON error body a REST call answers with", () => {
    expect(getApiErrorMessage(new Error('{"error":"missing database configuration"}'))).toBe(
      "missing database configuration",
    );
  });
});
