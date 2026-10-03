// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { isValidElement, type ReactElement, type ReactNode } from "react";
import { renderToString } from "react-dom/server";

// The editors import the API client, which reads window.location on import.
mock.module("../../services/client", () => ({ api: {} }));

const { AuthConfigEditor } = await import("./AuthConfigEditor");
const { RatelimitConfigEditor } = await import("./RatelimitConfigEditor");
const { IPFilterConfigEditor, GeoIPConfigEditor, XFCCConfigEditor, TLSBindingConfigEditor } = await import(
  "./SecurityConfigEditors"
);
const { CORS_PRESETS } = await import("./MiscConfigEditors");
const {
  corsProblem,
  middlewareConfigProblem,
  withoutRetiredKeys,
  xfccProblem,
  tlsBindingProblem,
  WILDCARD_CREDENTIALS,
} = await import("./middlewareConfigProblems");

type Props = Record<string, unknown>;

// The editors are hook-free function components: calling one returns the tree
// it renders, whose props can be read without a DOM.
function find(node: ReactNode, label: string): ReactElement<Props> | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = find(child, label);
      if (found) return found;
    }
    return null;
  }
  if (!isValidElement<Props>(node)) return null;
  if (node.props.label === label) return node;
  return find(node.props.children as ReactNode, label);
}

const html = (el: ReactElement) => renderToString(<MantineProvider>{el}</MantineProvider>);

// Each setting does what its label says, or the form will not save it (ADR
// 0046); these pin the dashboard half against the gateway's refusals.

describe("CORS", () => {
  test("no preset pairs origin * with credentials", () => {
    for (const [name, preset] of Object.entries(CORS_PRESETS)) {
      const wildcard = preset.allowed_origins.split(",").map((s) => s.trim()).includes("*");
      expect({ name, pair: wildcard && preset.allow_credentials === "true" }).toEqual({ name, pair: false });
    }
  });

  test("credentials with * are refused; with named origins, or for the backend preset, they are not", () => {
    expect(corsProblem({ allowed_origins: "*", allow_credentials: "true" })).toBe(WILDCARD_CREDENTIALS);
    expect(corsProblem({ allowed_origins: "https://a.example, *", allow_credentials: "true" })).toBe(WILDCARD_CREDENTIALS);
    expect(middlewareConfigProblem("grpcweb", { allowed_origins: "*", allow_credentials: "true" })).toBe(WILDCARD_CREDENTIALS);
    expect(corsProblem({ allowed_origins: "https://a.example", allow_credentials: "true" })).toBeUndefined();
    expect(corsProblem({ allowed_origins: "*", allow_credentials: "false" })).toBeUndefined();
    expect(corsProblem({ preset: "backend", allowed_origins: "*", allow_credentials: "true" })).toBeUndefined();
  });
});

describe("auth", () => {
  test("the revocation switch says it needs Redis and what it checks", () => {
    for (const type of ["jwt", "paseto", "oidc"]) {
      const page = html(<AuthConfigEditor config={{ type }} onChange={() => {}} />);
      expect(page).toContain("Enable Revocation");
      expect(page).toContain("Needs Redis");
    }
    expect(html(<AuthConfigEditor config={{ type: "apikey" }} onChange={() => {}} />)).not.toContain("Enable Revocation");
  });

  test("the scope placeholder is a list the gateway reads as two scopes", () => {
    const field = find(AuthConfigEditor({ config: { type: "jwt" }, onChange: () => {} }), "Required Scopes");
    const placeholder = String(field?.props.placeholder ?? "");
    // internal/middleware/auth_factory.go parseRequiredScopes: commas and spaces.
    expect(placeholder.split(/[\s,]+/).filter(Boolean)).toEqual(["read", "write"]);
  });

  test("the token type hint names the RFC 7662 values", () => {
    const page = html(<AuthConfigEditor config={{ type: "oauth2" }} onChange={() => {}} />);
    expect(page).toContain("access_token or refresh_token");
    expect(page).not.toContain("accessToken");
  });
});

describe("client address", () => {
  test("no middleware offers its own Trust Cloudflare Headers switch", () => {
    const pages = [
      html(<RatelimitConfigEditor config={{ trust_cloudflare_headers: "true" }} onChange={() => {}} />),
      html(<IPFilterConfigEditor config={{}} updateConfig={() => {}} />),
      html(<GeoIPConfigEditor config={{}} updateConfig={() => {}} />),
    ];
    for (const page of pages) {
      expect(page).not.toContain("Use CF-Connecting-IP");
      expect(page).toContain("cannot be set per middleware");
    }
  });

  test("a save drops the retired key, and keeps everything else", () => {
    expect(withoutRetiredKeys("ratelimit", { storage: "local", trust_cloudflare_headers: "true" })).toEqual({
      storage: "local",
    });
    expect(withoutRetiredKeys("ipfilter", { trust_cloudflare_headers: "false" })).toEqual({});
    expect(withoutRetiredKeys("cors", { trust_cloudflare_headers: "true" })).toEqual({ trust_cloudflare_headers: "true" });
  });

  test("the rate limit says Redis storage needs Redis", () => {
    expect(html(<RatelimitConfigEditor config={{ storage: "redis" }} onChange={() => {}} />)).toContain(
      "Needs Redis configured",
    );
  });
});

describe("xfcc", () => {
  test("Forward By asks for the URI it forwards, and will not save without one", () => {
    expect(html(<XFCCConfigEditor config={{ forward_by: "true" }} updateConfig={() => {}} />)).toContain(
      "spiffe://example.org/gateway",
    );
    expect(xfccProblem({ forward_by: "true" })).toBeDefined();
    expect(xfccProblem({ forward_by: "true", by: "not a uri" })).toBeDefined();
    expect(xfccProblem({ forward_by: "true", by: "spiffe://rv/gateon" })).toBeUndefined();
    expect(xfccProblem({ forward_by: "false" })).toBeUndefined();
  });
});

describe("tls_binding", () => {
  test("needs a 32-character secret; a stored one is kept", () => {
    expect(tlsBindingProblem({})).toBeDefined();
    expect(tlsBindingProblem({ secret: "short" })).toBeDefined();
    expect(tlsBindingProblem({ secret: "x".repeat(32) })).toBeUndefined();
    expect(tlsBindingProblem({ secret: "__gateon_redacted__" })).toBeUndefined();
    const page = html(<TLSBindingConfigEditor config={{}} updateConfig={() => {}} />);
    expect(page).toContain("client certificate");
  });
});
