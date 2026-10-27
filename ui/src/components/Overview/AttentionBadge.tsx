// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { ActionIcon, Indicator, Tooltip } from "@mantine/core";
import { Link } from "@tanstack/react-router";
import { IconBell } from "@tabler/icons-react";
import { useAttention } from "./useAttention";

/**
 * How many rows the Overview's Needs attention list holds, on a bell in the
 * header. It reuses the queries the Overview already runs, so it costs no
 * request of its own; it links to the list rather than repeating it.
 */
export function AttentionBadge() {
  const { items } = useAttention();
  const count = items.length;
  const label = count === 0 ? "Nothing needs attention" : `${count} ${count === 1 ? "item needs" : "items need"} attention`;
  return (
    <Tooltip label={label}>
      <Indicator
        inline
        disabled={count === 0}
        label={count > 99 ? "99+" : count}
        size={16}
        color={items.some((i) => i.state === "down") ? "red" : "yellow"}
        offset={4}
      >
        <ActionIcon component={Link} to="/" hash="attention" variant="subtle" color="gray" size="lg" aria-label={label}>
          <IconBell size={19} stroke={1.6} />
        </ActionIcon>
      </Indicator>
    </Tooltip>
  );
}
