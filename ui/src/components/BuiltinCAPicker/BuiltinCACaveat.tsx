// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";
import { useBuiltinCAs } from "../../hooks/useBuiltinCAs";
import { caveatFor, isBuiltinRef } from "./builtinCAs";

export interface BuiltinCACaveatProps {
  /** The ca_file value the field holds. */
  caFile: string;
}

/**
 * What a chosen built-in CA does not prove, shown under the field that names
 * it. Nothing renders for a path, or for a built-in CA with nothing to say.
 */
export function BuiltinCACaveat({ caFile }: BuiltinCACaveatProps) {
  const builtin = isBuiltinRef(caFile);
  const { data } = useBuiltinCAs(builtin);
  const caveat = builtin ? caveatFor(data ?? [], caFile) : "";
  if (!caveat) return null;
  return (
    <Alert color="orange" variant="light" icon={<IconAlertTriangle size={16} />} title="This CA is shared">
      {caveat}
    </Alert>
  );
}
