// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

export const SETTINGS_TABS = ["general", "gateway", "security", "network"] as const;
export type SettingsTab = (typeof SETTINGS_TABS)[number];

// asSettingsTab reads the ?tab= search param. Anything it does not name,
// including nothing, is the General tab, so an old bookmark still lands.
export function asSettingsTab(value: string | undefined): SettingsTab {
  return SETTINGS_TABS.find((t) => t === value) ?? "general";
}
