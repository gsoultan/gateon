// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { isValidElement, type ReactElement, type ReactNode } from "react";
import { renderToString } from "react-dom/server";

// The security editors import the API client, and the client reads
// window.location when it is imported. There is no window under bun:test, so
// the client is replaced before the editors are loaded.
mock.module("../../services/client", () => ({ api: {} }));

const { MiddlewareConfigEditor } = await import("./MiddlewareConfigEditor");
const { HeadersConfigEditor } = await import("./HeadersConfigEditor");
const { AuthConfigEditor } = await import("./AuthConfigEditor");
const {
  BotManagementConfigEditor,
  FileSecurityConfigEditor,
  PolicyConfigEditor,
  SecurityHeadersConfigEditor,
  WAFConfigEditor,
} = await import("./SecurityConfigEditors");
const { CORSConfigEditor, CORS_PRESETS, StripPrefixConfigEditor } =
  await import("./MiscConfigEditors");
const { BufferingConfigEditor } = await import("./TrafficConfigEditors");

type Props = Record<string, unknown>;
type Element = ReactElement<Props>;

// The editors under test are hook-free function components, so calling them
// returns the element tree they would render. Walking that tree reaches the
// props — labels, checked state, change handlers — without a DOM.
function findElement(node: ReactNode, matches: (el: Element) => boolean): Element | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = findElement(child, matches);
      if (found) return found;
    }
    return null;
  }
  if (!isValidElement<Props>(node)) return null;
  if (matches(node)) return node;
  return findElement(node.props.children as ReactNode, matches);
}

function byLabel(label: string) {
  return (el: Element) => el.props.label === label;
}

function byTitle(title: string) {
  return (el: Element) => el.props.title === title;
}

// Mantine's Switch hands its handler a change event; the editors read
// currentTarget.checked from it.
function flip(el: Element | null, checked: boolean) {
  expect(el).not.toBeNull();
  (el!.props.onChange as (e: unknown) => void)({ currentTarget: { checked } });
}

function capture() {
  let last: Record<string, string> = {};
  return {
    onChange: (next: Record<string, string>) => {
      last = next;
    },
    updateConfig: (key: string, value: string) => {
      last = { [key]: value };
    },
    get last() {
      return last;
    },
  };
}

// Every key below is the spelling internal/middleware reads. The editor and
// the gateway share nothing but these strings, so the editor writing any other
// spelling is a control wired to nothing.

describe("headers editor", () => {
  test("custom header lists use the add_/set_ request/response prefixes the gateway reads", () => {
    const tree = HeadersConfigEditor({ config: {}, onChange: () => {} });
    expect(findElement(tree, byTitle("Add Request Headers"))?.props.prefix).toBe("add_request_");
    expect(findElement(tree, byTitle("Set Request Headers"))?.props.prefix).toBe("set_request_");
    expect(findElement(tree, byTitle("Add Response Headers"))?.props.prefix).toBe("add_response_");
    expect(findElement(tree, byTitle("Set Response Headers"))?.props.prefix).toBe("set_response_");
  });
});

describe("auth editor", () => {
  test("revocation toggle is bound to enable_revocation", () => {
    const c = capture();
    const tree = AuthConfigEditor({
      config: { type: "jwt", enable_revocation: "true" },
      onChange: c.onChange,
    });
    const toggle = findElement(tree, byLabel("Enable Revocation"));
    expect(toggle?.props.checked).toBe(true);
    flip(toggle, false);
    expect(c.last).toMatchObject({ enable_revocation: "false" });
  });

  test("hashed-keys toggle is bound to hashed", () => {
    const c = capture();
    const tree = AuthConfigEditor({
      config: { type: "apikey", hashed: "true" },
      onChange: c.onChange,
    });
    const toggle = findElement(tree, byLabel("Hashed Keys"));
    expect(toggle?.props.checked).toBe(true);
    flip(toggle, false);
    expect(c.last).toMatchObject({ hashed: "false" });
  });

  test("claim-to-header mapping uses the map_claim_ prefix", () => {
    const tree = AuthConfigEditor({ config: { type: "jwt" }, onChange: () => {} });
    expect(findElement(tree, byTitle("Claim-to-Header Mapping"))?.props.prefix).toBe("map_claim_");
  });
});

describe("bot management editor", () => {
  test("challenge toggles are bound to enable_js_challenge and enable_browser_integrity", () => {
    const c = capture();
    const tree = BotManagementConfigEditor({
      config: { enable_js_challenge: "true", enable_browser_integrity: "true" },
      updateConfig: c.updateConfig,
    });
    const js = findElement(tree, byLabel("JS Challenge"));
    const integrity = findElement(tree, byLabel("Browser Integrity Check"));
    expect(js?.props.checked).toBe(true);
    expect(integrity?.props.checked).toBe(true);
    flip(js, false);
    expect(c.last).toEqual({ enable_js_challenge: "false" });
    flip(integrity, false);
    expect(c.last).toEqual({ enable_browser_integrity: "false" });
  });
});

// A control the gateway does not read is worse than a missing one: an operator
// reads a switch labelled with a protection as "this protection is on". The
// keys below have no reader in internal/, cmd/ or pkg/ under either spelling,
// so the controls that wrote them are gone.

describe("waf editor", () => {
  test("a route saved with useCrs=false still shows every control the gateway reads", () => {
    // useCrs was never read by createWAF or parseWAFConfig; it only hid the
    // rest of this editor. A route carrying the key from an older dashboard was
    // fully protected while showing none of the controls that said so.
    const tree = WAFConfigEditor({ config: { useCrs: "false" }, updateConfig: () => {} });
    for (const label of [
      "SQL Injection",
      "Cross-Site Scripting (XSS)",
      "IP Reputation",
      "Data Loss Prevention (DLP)",
      "Paranoia Level",
      "Anomaly Threshold",
      "SSRF Parameter Protection",
      "Request Body Limit",
      "Response Body Limit",
      "Audit Log Path (optional)",
    ]) {
      expect(findElement(tree, byLabel(label))).not.toBeNull();
    }
  });

  test("the switches no Go code reads are gone", () => {
    const tree = WAFConfigEditor({ config: {}, updateConfig: () => {} });
    for (const label of [
      "Use OWASP CRS",
      "Behavioral Profiling",
      "Impossible Travel",
      "Device Posture Check",
      "Custom Directives",
    ]) {
      expect(findElement(tree, byLabel(label))).toBeNull();
    }
  });

  test("renders the tuning controls and none of the dead ones", () => {
    const html = renderToString(
      <MantineProvider>
        <WAFConfigEditor config={{ useCrs: "false" }} updateConfig={() => {}} />
      </MantineProvider>,
    );
    expect(html).toContain("SQL Injection");
    expect(html).toContain("Paranoia Level");
    expect(html).not.toContain("Use OWASP CRS");
    expect(html).not.toContain("Behavioral Profiling");
    expect(html).not.toContain("Device Posture Check");
    expect(html).not.toContain("Custom Directives");
  });
});

describe("buffering editor", () => {
  test("offers only the request limit, the one key createBuffering reads", () => {
    const tree = BufferingConfigEditor({ config: {}, updateConfig: () => {} });
    expect(findElement(tree, byLabel("Max Request Body (Bytes)"))).not.toBeNull();
    expect(findElement(tree, byLabel("Max Response Body (Bytes)"))).toBeNull();
  });
});

describe("file security editor", () => {
  test("the magic-number check is stated, not offered, because it cannot be turned off", () => {
    const tree = FileSecurityConfigEditor({ config: {}, updateConfig: () => {} });
    expect(findElement(tree, byLabel("Strict Magic Number Check"))).toBeNull();
  });

  test("ClamAV toggle is bound to enable_clamav", () => {
    const c = capture();
    const tree = FileSecurityConfigEditor({
      config: { enable_clamav: "true" },
      updateConfig: c.updateConfig,
    });
    const toggle = findElement(tree, byLabel("Enable ClamAV Scanning"));
    expect(toggle?.props.checked).toBe(true);
    expect(findElement(tree, byLabel("ClamAV Address"))).not.toBeNull();
    flip(toggle, false);
    expect(c.last).toEqual({ enable_clamav: "false" });
  });
});

describe("policy editor", () => {
  test("Add Rule creates a rule_/message_ pair that the editor lists and the gateway reads", () => {
    const c = capture();
    const tree = PolicyConfigEditor({ config: {}, onChange: c.onChange });
    const add = findElement(
      tree,
      (el) => typeof el.props.children === "string" && el.props.children.trim() === "Add Rule",
    );
    expect(add).not.toBeNull();
    (add!.props.onClick as () => void)();
    const keys = Object.keys(c.last);
    expect(keys.some((k) => k.startsWith("rule_"))).toBe(true);
    expect(keys.some((k) => k.startsWith("message_"))).toBe(true);

    const listed = PolicyConfigEditor({ config: c.last, onChange: c.onChange });
    expect(findElement(listed, byLabel("CEL Expression"))).not.toBeNull();
  });
});

describe("strip prefix editor", () => {
  test("prefixes are joined without spaces because the gateway does not trim them", () => {
    const c = capture();
    const tree = StripPrefixConfigEditor({ config: {}, updateConfig: c.updateConfig });
    (tree.props.onChange as (value: string[]) => void)(["/api", "/v1"]);
    expect(c.last).toEqual({ prefixes: "/api,/v1" });
  });
});

describe("CORS presets", () => {
  test("preset values are keyed the way the editor and the gateway read them", () => {
    for (const preset of Object.values(CORS_PRESETS)) {
      expect(Object.keys(preset).sort()).toEqual([
        "allow_credentials",
        "allowed_headers",
        "allowed_methods",
        "allowed_origins",
        "exposed_headers",
        "max_age",
      ]);
    }
  });

  test("choosing a preset fills the origin list the editor displays", () => {
    const c = capture();
    const tree = CORSConfigEditor({
      config: {},
      updateConfig: c.updateConfig,
      onChange: c.onChange,
    });
    const select = findElement(tree, byLabel("CORS Preset"));
    expect(select).not.toBeNull();
    (select!.props.onChange as (value: string | null) => void)("standard");
    expect(c.last.allowed_origins).toBe("*");
    expect(c.last.preset).toBe("standard");
  });
});

describe("middleware kind names", () => {
  test.each([
    "file_security",
    "security_headers",
    "bot_management",
    "schema_validation",
    "request_id",
  ])("%s, as the gateway spells it, gets its editor", (kind) => {
    const html = renderToString(
      <MantineProvider>
        <MiddlewareConfigEditor type={kind} config={{}} onChange={() => {}} />
      </MantineProvider>,
    );
    expect(html).not.toContain("Unknown middleware type");
  });
});

describe("security headers preset", () => {
  // An unset preset is the gateway's legacy set -- nosniff, SAMEORIGIN framing
  // and a referrer policy, no CSP. The editor showed it as Recommended, which
  // adds a CSP and HSTS the route did not have.
  test("an unset preset shows what the gateway applies", () => {
    const tree = SecurityHeadersConfigEditor({ config: {}, updateConfig: () => {} });
    const select = findElement(tree, byLabel("Security Headers Preset"));
    expect(select).not.toBeNull();
    expect(select!.props.value).toBe("legacy");
    const values = (select!.props.data as { value: string }[]).map((d) => d.value);
    expect(values).toEqual(["legacy", "recommended", "strict", "none"]);
  });
});

describe("custom error pages", () => {
  // The gateway serves each page value verbatim as the response body. The form
  // asked for a "Page Path" with /path/to/404.html as its example, so an
  // operator following it published a page reading "/path/to/404.html".
  test("asks for the page's HTML, which is what the gateway serves", () => {
    const html = renderToString(
      <MantineProvider>
        <MiddlewareConfigEditor
          type="errors"
          config={{ status_codes: "404", page_404: "<h1>Gone</h1>" }}
          onChange={() => {}}
        />
      </MantineProvider>,
    );
    expect(html).toContain("Page HTML");
    expect(html).not.toContain("Page Path");
    expect(html).not.toContain("/path/to/404.html");
  });
});

describe("policy help", () => {
  // The gateway hands CEL `auth` as the claims map itself; the help text said
  // `auth.claims`, so a rule written from it read a key that does not exist
  // and refused every request.
  test("documents the variables the gateway provides", () => {
    const html = renderToString(
      <MantineProvider>
        <PolicyConfigEditor config={{}} onChange={() => {}} />
      </MantineProvider>,
    );
    expect(html).not.toContain("auth.claims");
    for (const v of ["request.host", "request.query", "auth.role", "has(auth.role)"]) {
      expect(html).toContain(v);
    }
  });
});
