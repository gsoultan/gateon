// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { isValidElement, type ReactElement, type ReactNode } from "react";
import { renderToString } from "react-dom/server";

// The editors import the API client, which reads window.location on import.
mock.module("../../services/client", () => ({ api: {} }));

const { AuthConfigEditor } = await import("./AuthConfigEditor");
const { authConfigProblem } = await import("./authConfigProblems");

type Props = Record<string, unknown>;
const P = "__gateon_redacted__";
const html = (config: Record<string, string>) =>
  renderToString(
    <MantineProvider>
      <AuthConfigEditor config={config} onChange={() => {}} />
    </MantineProvider>,
  );

function find(node: ReactNode, matches: (el: ReactElement<Props>) => boolean): ReactElement<Props> | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = find(child, matches);
      if (found) return found;
    }
    return null;
  }
  if (!isValidElement<Props>(node)) return null;
  if (matches(node)) return node;
  return find(node.props.children as ReactNode, matches);
}

// "Add user" appends a row with no password, and the gateway used to store it
// and let anyone in under that name (ADR 0043). The row now says so, and the
// form will not save until a password is entered; a user whose password is
// stored keeps it through the placeholder (ADR 0033) and is not flagged.
describe("basic auth users", () => {
  test("a user added with no password is flagged and blocks the save", () => {
    let last: Record<string, string> = {};
    const tree = AuthConfigEditor({ config: { type: "basic", users: `alice:${P}` }, onChange: (c) => (last = c) });
    const users = find(tree, (el) => typeof el.type === "function" && el.type.name === "BasicUsersEditor");
    const add = find((users!.type as (p: Props) => ReactNode)(users!.props), (el) => el.props.children === "Add user");
    (add!.props.onClick as () => void)();
    expect(last.users).toBe(`alice:${P},user2:`);

    expect(authConfigProblem(last)).toContain('User "user2"');
    expect(html(last)).toContain("A user with no password lets anyone in under this name.");
  });

  test("users whose passwords are stored, or newly typed, are not flagged", () => {
    for (const users of [`alice:${P},bob:${P}`, `alice:${P},user2:s3cret`]) {
      expect(authConfigProblem({ type: "basic", users })).toBeUndefined();
      expect(html({ type: "basic", users })).not.toContain("lets anyone in");
    }
  });
});

// A provider's published keys sign tokens for every application it serves, so
// with no audience a route accepted a token issued to any of them (ADR 0043).
describe("audience", () => {
  test("OIDC, and JWT verified with a JWKS URL, require one and say why", () => {
    const configs: Record<string, string>[] = [
      { type: "oidc", issuer: "https://idp.example" },
      { type: "jwt", jwks_url: "https://idp.example/jwks" },
    ];
    for (const config of configs) {
      expect(authConfigProblem(config)).toContain("accepts a token issued to any of them");
      const page = html(config);
      expect(page).toContain("accepts a token issued to any of them");
      expect(page).not.toContain("Audience (optional)");
    }
  });

  test("an audience, or the named opt-out, satisfies it; a shared-secret JWT does not need one", () => {
    expect(authConfigProblem({ type: "oidc", issuer: "https://idp.example", audience: "my-api" })).toBeUndefined();
    expect(authConfigProblem({ type: "oidc", issuer: "https://idp.example", allow_any_audience: "true" })).toBeUndefined();
    expect(authConfigProblem({ type: "jwt", secret: P })).toBeUndefined();
  });

  test("the opt-out is a named switch bound to allow_any_audience", () => {
    let last: Record<string, string> = {};
    const tree = AuthConfigEditor({ config: { type: "oidc" }, onChange: (c) => (last = c) });
    const fields = find(tree, (el) => typeof el.type === "function" && el.type.name === "AudienceFields");
    const toggle = find((fields!.type as (p: Props) => ReactNode)(fields!.props), (el) =>
      el.props.label === "Accept a token issued for any audience");
    expect(toggle?.props.checked).toBe(false);
    (toggle!.props.onChange as (e: unknown) => void)({ currentTarget: { checked: true } });
    expect(last).toMatchObject({ allow_any_audience: "true" });
  });
});
