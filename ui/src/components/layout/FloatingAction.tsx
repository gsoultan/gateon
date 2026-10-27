// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Affix, Button } from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";

interface FloatingActionProps {
  label: string;
  onClick: () => void;
}

/**
 * A page's one create action, as a button floating above the phone's bottom
 * bar. On a wide screen the same action is in the page header and this is
 * not rendered.
 */
export function FloatingAction({ label, onClick }: FloatingActionProps) {
  return (
    <Affix position={{ bottom: 72, right: 16 }} hiddenFrom="sm" zIndex={150}>
      <Button size="md" radius="xl" leftSection={<IconPlus size={18} />} onClick={onClick} aria-label={label}>
        {label}
      </Button>
    </Affix>
  );
}
