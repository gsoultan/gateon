// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Group, Divider, Switch, Text } from "@mantine/core";
import type { WafConfig } from "../../../types/gateon";
import { BROWSER_HEADER_CHECK_HELP, JS_CHALLENGE_HELP } from "../../MiddlewareConfig/botManagementCopy";

interface BotManagementSectionProps {
  waf: WafConfig;
  onChange: (waf: WafConfig) => void;
  disabled: boolean;
}

// The defaults a route's Bot Management middleware falls back to for any
// setting the route leaves unset. They are not applied to routes without one:
// the gateway reads them only inside that middleware (ADR 0045).
export function BotManagementSection({ waf, onChange, disabled }: BotManagementSectionProps) {
  return (
    <>
      <Divider label="Bot Management Defaults" labelPosition="center" />
      <Text size="xs" c="dimmed">
        Defaults for routes that use a Bot Management middleware, for any setting the route leaves unset. Routes
        without that middleware are not affected.
      </Text>
      <Group grow align="flex-start">
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
          label="Browser Header Check"
          description={BROWSER_HEADER_CHECK_HELP}
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
          label="JavaScript Challenge"
          description={JS_CHALLENGE_HELP}
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
