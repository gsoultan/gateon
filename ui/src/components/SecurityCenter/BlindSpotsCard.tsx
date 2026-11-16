// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Anchor, Badge, Card, Group, Skeleton, Stack, Text, Title } from "@mantine/core";
import { Link } from "@tanstack/react-router";
import type { SecurityPosture } from "../../hooks/useSecurityPosture";
import { blindSpotGroups } from "./postureView";

/** Route names shown per group before the rest are counted. */
const ROUTES_SHOWN = 12;

/**
 * What the WAF cannot see, or sees and does not stop: the routes a posture
 * percentage hides. From the posture report, computed from configuration
 * only. Route names are operator-set and rendered as text.
 */
export function BlindSpotsCard({ posture, isLoading, error }: {
  posture: SecurityPosture | undefined;
  isLoading: boolean;
  error: unknown;
}) {
  const groups = blindSpotGroups(posture?.blindSpots);
  const omitted = posture?.blindSpots?.omitted ?? 0;
  return (
    <Card withBorder radius="md">
      <Title order={4}>What the WAF cannot see</Title>
      <Text size="sm" c="dimmed" mb="md">
        Traffic that reaches a backend without the WAF refusing it. Read from the current configuration.
      </Text>
      {isLoading ? (
        <Stack gap="xs" aria-busy="true">
          <Skeleton height={18} />
          <Skeleton height={18} width="70%" />
        </Stack>
      ) : error ? (
        <Alert color="red" title="The blind-spot list could not be loaded">
          The security posture report did not arrive. Reload the page to try again.
        </Alert>
      ) : !posture?.blindSpots ? (
        <Text size="sm" c="dimmed">This gateway does not report blind spots yet. Upgrade it to see them here.</Text>
      ) : groups.length === 0 ? (
        <Text size="sm" c="dimmed">Nothing to show: every route is inspected by a blocking WAF.</Text>
      ) : (
        <Stack gap="md">
          {groups.map((g) => (
            <Stack key={g.kind} gap={4}>
              <Group gap="xs">
                <Badge color={g.color} variant="light">
                  {g.routes.length > 0 ? g.routes.length : "All routes"}
                </Badge>
                <Text fw={600} size="sm">{g.title}</Text>
              </Group>
              <Text size="sm">{g.why}</Text>
              {g.fix !== "" && (
                <Text size="sm" c="dimmed">
                  {g.fix}{" "}
                  {g.fixPath && (
                    <Anchor component={Link} to={g.fixPath} size="sm">
                      {g.fixPath === "/routes" ? "Open Routes" : "Open Security"}
                    </Anchor>
                  )}
                </Text>
              )}
              {g.routes.length > 0 && (
                <Group gap={6}>
                  {g.routes.slice(0, ROUTES_SHOWN).map((name) => (
                    <Badge key={name} variant="outline" color="gray" tt="none">{name}</Badge>
                  ))}
                  {g.routes.length > ROUTES_SHOWN && (
                    <Text size="xs" c="dimmed">{`and ${g.routes.length - ROUTES_SHOWN} more`}</Text>
                  )}
                </Group>
              )}
            </Stack>
          ))}
          {omitted > 0 && (
            <Text size="xs" c="dimmed">{`${omitted} more are not listed here.`}</Text>
          )}
        </Stack>
      )}
    </Card>
  );
}
