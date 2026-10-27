// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { lazy, Suspense } from "react";
import { Skeleton, Stack, Tabs } from "@mantine/core";
import { IconKey, IconUsers } from "@tabler/icons-react";
import { PageHeader } from "../components/layout";
import { useUrlFilters } from "../hooks/useUrlFilters";

const UsersPage = lazy(() => import("./UsersPage"));
const ApiTokensPage = lazy(() => import("./ApiTokensPage"));

const ACCESS_TABS = ["users", "tokens"] as const;
type AccessTab = (typeof ACCESS_TABS)[number];

function asAccessTab(value: string | undefined): AccessTab {
  return ACCESS_TABS.find((t) => t === value) ?? "users";
}

const fallback = <Skeleton height={320} radius="md" />;

/** Who and what may sign in: people on the Users tab, machines on API tokens. */
export default function AccessPage() {
  const [filters, setFilters] = useUrlFilters<{ tab: string }>();
  const tab = asAccessTab(filters.tab);
  const showTab = (next: string | null) => {
    const value = asAccessTab(next ?? undefined);
    setFilters({ tab: value === "users" ? undefined : value });
  };

  return (
    <Stack gap="xl">
      <PageHeader
        title="Access"
        description="Who can sign in to this dashboard and what each role may do, and the tokens machines use to read it."
      />
      <Tabs value={tab} onChange={showTab} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="users" leftSection={<IconUsers size={16} />}>
            Users
          </Tabs.Tab>
          <Tabs.Tab value="tokens" leftSection={<IconKey size={16} />}>
            API tokens
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="users" pt="xl">
          <Suspense fallback={fallback}>
            <UsersPage embedded />
          </Suspense>
        </Tabs.Panel>
        <Tabs.Panel value="tokens" pt="xl">
          <Suspense fallback={fallback}>
            <ApiTokensPage embedded />
          </Suspense>
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
