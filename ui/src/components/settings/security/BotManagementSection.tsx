// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Group, Divider, Switch } from "@mantine/core";
import type { WafConfig } from "../../../types/gateon";

interface BotManagementSectionProps {
  waf: WafConfig;
  onChange: (waf: WafConfig) => void;
  disabled: boolean;
}

// Bot management applied on every route the global WAF protects.
export function BotManagementSection({ waf, onChange, disabled }: BotManagementSectionProps) {
  return (
    <>
      <Divider label="Global Bot Management" labelPosition="center" />
      <Group grow>
        <Switch
          label="Enable Bot Management"
          checked={waf.botManagement?.enabled}
          onChange={(e) => onChange({
            ...waf,
            botManagement: {
              ...(waf.botManagement || {}),
              enabled: e.currentTarget.checked
            }
          })}
          disabled={disabled}
        />
        <Switch
          label="Browser Integrity"
          checked={waf.botManagement?.enableBrowserIntegrity}
          onChange={(e) => onChange({
            ...waf,
            botManagement: {
              ...(waf.botManagement || {}),
              enableBrowserIntegrity: e.currentTarget.checked
            }
          })}
          disabled={disabled || !waf.botManagement?.enabled}
        />
        <Switch
          label="JS Challenge"
          checked={waf.botManagement?.enableJsChallenge}
          onChange={(e) => onChange({
            ...waf,
            botManagement: {
              ...(waf.botManagement || {}),
              enableJsChallenge: e.currentTarget.checked
            }
          })}
          disabled={disabled || !waf.botManagement?.enabled}
        />
      </Group>
    </>
  );
}
