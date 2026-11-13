// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Badge } from "@mantine/core";
import { Link } from "@tanstack/react-router";
import { IconArrowUpCircle } from "@tabler/icons-react";
import { useUpdateStatus } from "../../hooks/useUpdateStatus";
import { linkSearch } from "./createLink";

/**
 * A pill in the header while a newer release is known (ADR 0085), linking to
 * the card that says how to take it. It renders nothing otherwise: loading,
 * up to date, switched off and failed are all "no notice".
 */
export function UpdateNotice() {
  const { data: status } = useUpdateStatus();
  if (!status?.updateAvailable || !status.latestVersion) return null;
  const label = `Update available: v${status.latestVersion}`;
  return (
    <Badge
      component={Link}
      to="/settings"
      search={linkSearch({ tab: "updates" })}
      variant="light"
      color="blue"
      size="lg"
      radius="xl"
      tt="none"
      leftSection={<IconArrowUpCircle size={14} aria-hidden />}
      aria-label={label}
      style={{ cursor: "pointer", flexShrink: 0 }}
      visibleFrom="sm"
    >
      {label}
    </Badge>
  );
}
