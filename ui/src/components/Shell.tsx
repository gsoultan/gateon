// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useMemo } from "react";
import { Alert, AppShell } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Outlet, useLocation } from "@tanstack/react-router";
import { IconEye } from "@tabler/icons-react";
import { useGateonStatus } from "../hooks/useGateon";
import { useSignOut } from "../hooks/useSignOut";
import { usePermissions } from "../hooks/usePermissions";
import { useIsMobile } from "../hooks/useMobile";
import { useAuthStore } from "../store/useAuthStore";
import { usePreferencesStore } from "../store/usePreferencesStore";
import { CommandPaletteProvider } from "./CommandPalette";
import { AppHeader, AppNavbar, MobileTabBar, layoutClasses as classes, navSections } from "./layout";

const NAVBAR_WIDTH = 248;
const NAVBAR_COLLAPSED_WIDTH = 72;

export function Shell() {
  const [mobileOpened, { toggle: toggleMobile, close: closeMobile }] = useDisclosure();
  const sidebarCollapsed = usePreferencesStore((state) => state.sidebarCollapsed);
  const toggleSidebar = usePreferencesStore((state) => state.toggleSidebar);
  const { pathname } = useLocation();
  const { data: status, refetch, isFetching } = useGateonStatus();
  const signOut = useSignOut();
  const user = useAuthStore((state) => state.user);
  const isViewer = usePermissions().isViewer;
  const isMobile = useIsMobile();
  // On a phone the sidebar is a drawer, and it always shows its labels.
  const expanded = isMobile || !sidebarCollapsed;

  const isAdmin = user?.role === "admin";
  const sections = useMemo(() => navSections({ isAdmin }), [isAdmin]);

  // The mobile drawer stayed open over the page it had just opened, so every
  // navigation on a phone took a second tap to see the result.
  useEffect(() => {
    closeMobile();
  }, [pathname, closeMobile]);

  return (
    <CommandPaletteProvider>
      <AppShell
        header={{ height: 60 }}
        navbar={{
          width: expanded ? NAVBAR_WIDTH : NAVBAR_COLLAPSED_WIDTH,
          breakpoint: "sm",
          collapsed: { mobile: !mobileOpened },
        }}
        footer={{ height: 60, collapsed: !isMobile }}
        padding={{ base: "md", md: "xl" }}
        classNames={{ header: classes.header, navbar: classes.navbar, main: classes.main }}
      >
        <a href="#main-content" className="skip-to-content">
          Skip to main content
        </a>
        <AppShell.Header>
          <AppHeader
            mobileOpened={mobileOpened}
            onToggleMobile={toggleMobile}
            sidebarExpanded={!sidebarCollapsed}
            onToggleSidebar={toggleSidebar}
            username={user?.username}
            role={user?.role}
            version={status?.version}
            refreshing={isFetching}
            onRefresh={() => void refetch()}
            onSignOut={() => void signOut()}
          />
        </AppShell.Header>

        <AppShell.Navbar>
          <AppNavbar sections={sections} expanded={expanded} isMobile={isMobile} version={status?.version} />
        </AppShell.Navbar>

        {isMobile && (
          <AppShell.Footer className={classes.mobileBar}>
            <MobileTabBar onMore={toggleMobile} />
          </AppShell.Footer>
        )}

        <AppShell.Main id="main-content">
          <div className={classes.content}>
            {isViewer && (
              <Alert mb="lg" color="blue" variant="light" icon={<IconEye size={18} />} title="View only">
                You have read-only access. Create, edit, and delete actions are restricted.
              </Alert>
            )}
            <Outlet />
          </div>
        </AppShell.Main>
      </AppShell>
    </CommandPaletteProvider>
  );
}
