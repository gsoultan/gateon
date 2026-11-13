// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useState } from "react";
import { ActionIcon, Loader, Menu, Text, Tooltip } from "@mantine/core";
import { IconCertificate } from "@tabler/icons-react";
import { useBuiltinCAs } from "../../hooks/useBuiltinCAs";
import { expiryLine, orderForUse, type BuiltinCAUse } from "./builtinCAs";

export interface BuiltinCAPickerProps {
  /** Which kind of CA the field wants; matching ones are listed first. */
  use: BuiltinCAUse;
  onSelect: (ref: string) => void;
}

/**
 * A menu of the CA certificates built into the gateway. Choosing one puts its
 * reference (builtin:…) in the field, so the certificate never has to be
 * downloaded and pasted in.
 */
export function BuiltinCAPicker({ use, onSelect }: BuiltinCAPickerProps) {
  const [opened, setOpened] = useState(false);
  const { data, isLoading, isError } = useBuiltinCAs(opened);
  const sorted = orderForUse(data ?? [], use);

  return (
    <Menu opened={opened} onChange={setOpened} width={300} position="bottom-end" withinPortal>
      <Menu.Target>
        <Tooltip label="Use a built-in CA" disabled={opened}>
          <ActionIcon variant="subtle" color="blue" aria-label="Use a built-in CA certificate">
            <IconCertificate size={16} />
          </ActionIcon>
        </Tooltip>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Built into Gateon</Menu.Label>
        {isLoading && (
          <Menu.Item disabled leftSection={<Loader size={12} />}>
            Loading…
          </Menu.Item>
        )}
        {isError && (
          <Menu.Item disabled>
            <Text size="xs" c="red">Couldn't load the built-in CAs. Close and reopen to try again.</Text>
          </Menu.Item>
        )}
        {!isLoading && !isError && sorted.length === 0 && (
          <Menu.Item disabled>No built-in CAs in this build.</Menu.Item>
        )}
        {sorted.map((ca) => {
          const expiry = expiryLine(ca);
          return (
            <Menu.Item key={ca.ref} onClick={() => onSelect(ca.ref)}>
              <Text size="sm">{ca.name}</Text>
              <Text size="xs" c={expiry.color}>{expiry.text}</Text>
            </Menu.Item>
          );
        })}
      </Menu.Dropdown>
    </Menu>
  );
}
