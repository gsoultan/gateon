// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { GUIDES, guideIdForHref, isExternalHref } from "./guides";

describe("guide links", () => {
  test("every guide the Introduction lists has a tab", () => {
    const intro = GUIDES.find((g) => g.id === "intro")!;
    const listed = [...intro.content.matchAll(/\]\(\.\/([^)#]+\.md)\)/g)].map((m) => m[1]);
    expect(listed.length).toBeGreaterThan(0);
    for (const file of listed) {
      expect(GUIDES.some((g) => g.file === file)).toBe(true);
    }
  });

  test("a link to another guide names its tab, with or without ./ and a fragment", () => {
    expect(guideIdForHref("./services.md")).toBe("running-service");
    expect(guideIdForHref("services.md")).toBe("running-service");
    expect(guideIdForHref("./proxy-protocol.md#versions-v1-vs-v2")).toBe("proxy-protocol");
    expect(guideIdForHref("./websockets-sse.md")).toBe("websockets-sse");
  });

  test("anything else is not a guide", () => {
    expect(guideIdForHref(undefined)).toBeUndefined();
    expect(guideIdForHref("./missing.md")).toBeUndefined();
    expect(guideIdForHref("https://example.com/services.md")).toBeUndefined();
  });

  test("only http(s) links leave the dashboard", () => {
    expect(isExternalHref("https://www.rfc-editor.org/")).toBe(true);
    expect(isExternalHref("HTTP://example.com")).toBe(true);
    expect(isExternalHref("./services.md")).toBe(false);
    expect(isExternalHref("javascript:alert(1)")).toBe(false);
  });
});
