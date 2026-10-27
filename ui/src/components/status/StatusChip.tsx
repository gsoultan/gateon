// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Badge, Tooltip, type BadgeProps } from "@mantine/core";
import { STATUS_CHIP, type StatusState } from "./statusState";

interface StatusChipProps extends Omit<BadgeProps, "color" | "variant" | "children"> {
  state: StatusState;
  /** Replaces the state's word, for a chip that carries a number ("12 of 13"). */
  label?: string;
  /** Why the chip reads as it does; shown on hover and to screen readers. */
  reason?: string;
}

/**
 * The one status vocabulary. Every page used to coin its own (HEALTHY,
 * RUNNING, CLOSED, Active, Live, Detecting only...), and CLOSED was good for a
 * circuit and bad for everything else. Five states, one colour map, text next
 * to colour so the state is never colour alone. Unknown is for a value the
 * gateway did not compute: it is shown instead of a zero (ADR 0048).
 */
export function StatusChip({ state, label, reason, size = "sm", ...rest }: StatusChipProps) {
  const chip = STATUS_CHIP[state];
  const text = label ?? chip.label;
  const badge = (
    <Badge
      size={size}
      radius="sm"
      color={chip.color}
      variant={chip.variant}
      aria-label={reason ? `${text}: ${reason}` : text}
      styles={{ root: { textTransform: "none", fontWeight: 600, letterSpacing: 0 } }}
      leftSection={
        <span
          aria-hidden="true"
          style={{
            display: "inline-block",
            width: 6,
            height: 6,
            borderRadius: "50%",
            backgroundColor: "currentColor",
          }}
        />
      }
      {...rest}
    >
      {text}
    </Badge>
  );
  if (!reason) return badge;
  return (
    <Tooltip label={reason} withArrow multiline maw={320}>
      {badge}
    </Tooltip>
  );
}
