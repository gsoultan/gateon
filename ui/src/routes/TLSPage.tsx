// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { lazy, Suspense } from "react";
import { Skeleton, Stack, Tabs } from "@mantine/core";
import { IconCertificate, IconLockAccess, IconShieldLock } from "@tabler/icons-react";
import { PageHeader } from "../components/layout";
import { Term } from "../components/status";
import { useUrlFilters } from "../hooks/useUrlFilters";

// Each tab is its own chunk, fetched when first opened.
const CertificatesPage = lazy(() => import("./CertificatesPage"));
const ClientAuthoritiesPage = lazy(() => import("./ClientAuthoritiesPage"));
const TLSOptionsPage = lazy(() => import("./TLSOptionsPage"));

const TLS_TABS = ["certificates", "client-cas", "profiles"] as const;
type TlsTab = (typeof TLS_TABS)[number];

// Anything the search does not name, including nothing, is Certificates.
function asTlsTab(value: string | undefined): TlsTab {
  return TLS_TABS.find((t) => t === value) ?? "certificates";
}

const fallback = <Skeleton height={320} radius="md" />;

/**
 * Certificates, client CAs and TLS profiles: the three pages that used to sit
 * under Security beside the WAF, as three tabs of one page. Each tab keeps
 * its form.
 */
export default function TLSPage() {
  const [filters, setFilters] = useUrlFilters<{ tab: string }>();
  const tab = asTlsTab(filters.tab);
  const showTab = (next: string | null) => {
    const value = asTlsTab(next ?? undefined);
    setFilters({ tab: value === "certificates" ? undefined : value });
  };

  return (
    <Stack gap="xl">
      <PageHeader
        title="TLS"
        description={
          <>
            Certificates the gateway serves, the <Term of="clientCa" plural /> it trusts for client certificates, and the{" "}
            <Term of="tlsProfile" plural /> that routes reuse.
          </>
        }
      />
      <Tabs value={tab} onChange={showTab} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="certificates" leftSection={<IconCertificate size={16} />}>
            Certificates
          </Tabs.Tab>
          <Tabs.Tab value="client-cas" leftSection={<IconShieldLock size={16} />}>
            Client CAs
          </Tabs.Tab>
          <Tabs.Tab value="profiles" leftSection={<IconLockAccess size={16} />}>
            Profiles
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="certificates" pt="xl">
          <Suspense fallback={fallback}>
            <CertificatesPage embedded />
          </Suspense>
        </Tabs.Panel>
        <Tabs.Panel value="client-cas" pt="xl">
          <Suspense fallback={fallback}>
            <ClientAuthoritiesPage embedded />
          </Suspense>
        </Tabs.Panel>
        <Tabs.Panel value="profiles" pt="xl">
          <Suspense fallback={fallback}>
            <TLSOptionsPage embedded />
          </Suspense>
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
