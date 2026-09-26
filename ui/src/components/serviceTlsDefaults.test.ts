// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { expect, test } from "bun:test";
import { defaultTlsClientConfig } from "./serviceTlsDefaults";

// Turning backend TLS on in the service form must not also turn certificate
// verification off, which the old default did.
test("backend TLS starts with certificate verification on", () => {
  expect(defaultTlsClientConfig().skipVerify).toBe(false);
});
