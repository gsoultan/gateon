// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Tooltip } from "@mantine/core";
import { TERMS, type TermKey } from "./terms";

/**
 * A dashboard word with its API name on hover. The dashboard says Listener and
 * Policy; the API, the proto and the config files keep entryPoint and
 * middleware, so the first use of a term on a page carries the API name and
 * the docs and curl examples still line up.
 */
export function Term({ of, plural = false }: { of: TermKey; plural?: boolean }) {
  const term = TERMS[of];
  return (
    <Tooltip label={`${term.api} in the API and config`} withArrow openDelay={300}>
      <span style={{ textDecoration: "underline dotted", textDecorationColor: "var(--mantine-color-dimmed)", cursor: "help" }}>
        {plural ? term.plural : term.word}
      </span>
    </Tooltip>
  );
}
