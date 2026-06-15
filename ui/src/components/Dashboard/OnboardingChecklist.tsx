import { memo, useMemo } from "react";
import {
  Paper,
  Group,
  Stack,
  Title,
  Text,
  ThemeIcon,
  Progress,
  Button,
  ActionIcon,
  Tooltip,
  Badge,
} from "@mantine/core";
import {
  IconCheck,
  IconArrowRight,
  IconX,
  IconRocket,
  IconRoute,
  IconServer,
  IconPlugConnected,
  IconShieldLock,
} from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import type { Icon } from "@tabler/icons-react";
import {
  useEntryPoints,
  useServices,
  useRoutes,
  useMiddlewares,
} from "../../hooks/useGateon";
import { usePermissions } from "../../hooks/usePermissions";
import { usePreferencesStore } from "../../store/usePreferencesStore";

/** Middleware `type` values that count as protective/security middleware. */
const SECURITY_MIDDLEWARE_TYPES = ["waf", "filesecurity", "ratelimit", "ipallowlist", "ipblocklist"];

interface ChecklistStep {
  key: string;
  title: string;
  description: string;
  done: boolean;
  to: string;
  icon: Icon;
  color: string;
}

/**
 * OnboardingChecklist guides a freshly-installed Gateon through its first
 * configuration milestones (entry point → service → route → protection),
 * deriving completion purely from live config counts. It auto-hides once every
 * step is complete and can be dismissed permanently (persisted preference).
 */
export const OnboardingChecklist = memo(function OnboardingChecklist() {
  const { canWrite } = usePermissions();
  const dismissed = usePreferencesStore((s) => s.onboardingDismissed);
  const setDismissed = usePreferencesStore((s) => s.setOnboardingDismissed);

  const entryPoints = useEntryPoints({ page: 0, page_size: 1 });
  const services = useServices({ page: 0, page_size: 1 });
  const routes = useRoutes({ page: 0, page_size: 1 });
  // Fetch a generous page so we can inspect middleware types for protection.
  const middlewares = useMiddlewares({ page: 0, page_size: 100 });

  const isLoading =
    entryPoints.isLoading ||
    services.isLoading ||
    routes.isLoading ||
    middlewares.isLoading;

  const hasProtection = useMemo(() => {
    const list = middlewares.data?.middlewares ?? [];
    return list.some((m) =>
      SECURITY_MIDDLEWARE_TYPES.includes(m.type.toLowerCase()),
    );
  }, [middlewares.data]);

  const steps: ChecklistStep[] = useMemo(
    () => [
      {
        key: "entrypoint",
        title: "Create an entry point",
        description: "Define the address and port Gateon listens on.",
        done: (entryPoints.data?.total_count ?? 0) > 0,
        to: "/entrypoints",
        icon: IconPlugConnected,
        color: "grape",
      },
      {
        key: "service",
        title: "Register a service",
        description: "Point Gateon at one or more upstream backends.",
        done: (services.data?.total_count ?? 0) > 0,
        to: "/services",
        icon: IconServer,
        color: "teal",
      },
      {
        key: "route",
        title: "Add a route",
        description: "Match incoming traffic and forward it to a service.",
        done: (routes.data?.total_count ?? 0) > 0,
        to: "/routes",
        icon: IconRoute,
        color: "blue",
      },
      {
        key: "protection",
        title: "Enable protection",
        description: "Attach a WAF or security middleware to harden traffic.",
        done: hasProtection,
        to: "/middlewares",
        icon: IconShieldLock,
        color: "red",
      },
    ],
    [
      entryPoints.data,
      services.data,
      routes.data,
      hasProtection,
    ],
  );

  const completed = steps.filter((s) => s.done).length;
  const allDone = completed === steps.length;
  const nextStep = steps.find((s) => !s.done);

  // Hide while loading (avoid flashing a misleading empty checklist), once the
  // user dismissed it, or once every milestone is complete.
  if (isLoading || dismissed || allDone) {
    return null;
  }

  return (
    <Paper
      withBorder
      radius="lg"
      p="lg"
      shadow="xs"
      style={{
        background:
          "linear-gradient(135deg, var(--mantine-color-indigo-light), var(--mantine-color-body))",
      }}
    >
      <Group justify="space-between" align="flex-start" mb="md" wrap="nowrap">
        <Group gap="sm" wrap="nowrap">
          <ThemeIcon size={42} radius="md" variant="light" color="indigo">
            <IconRocket size={24} stroke={1.5} />
          </ThemeIcon>
          <div>
            <Title order={5} fw={800} style={{ letterSpacing: -0.2 }}>
              Get started with Gateon
            </Title>
            <Text size="xs" c="dimmed">
              Complete these steps to start routing and securing traffic.
            </Text>
          </div>
        </Group>
        <Tooltip label="Dismiss" withArrow>
          <ActionIcon
            variant="subtle"
            color="gray"
            aria-label="Dismiss onboarding checklist"
            onClick={() => setDismissed(true)}
          >
            <IconX size={18} />
          </ActionIcon>
        </Tooltip>
      </Group>

      <Group gap="xs" mb="md" wrap="nowrap">
        <Progress
          value={(completed / steps.length) * 100}
          color="indigo"
          radius="xl"
          size="md"
          style={{ flex: 1 }}
          aria-label="Onboarding progress"
        />
        <Badge variant="light" color="indigo">
          {completed}/{steps.length}
        </Badge>
      </Group>

      <Stack gap="xs">
        {steps.map((step) => (
          <Group
            key={step.key}
            justify="space-between"
            wrap="nowrap"
            gap="sm"
            style={{
              opacity: step.done ? 0.7 : 1,
            }}
          >
            <Group gap="sm" wrap="nowrap" style={{ minWidth: 0 }}>
              <ThemeIcon
                size={28}
                radius="xl"
                variant={step.done ? "filled" : "light"}
                color={step.done ? "teal" : step.color}
              >
                {step.done ? <IconCheck size={16} /> : <step.icon size={16} />}
              </ThemeIcon>
              <div style={{ minWidth: 0 }}>
                <Text
                  size="sm"
                  fw={700}
                  td={step.done ? "line-through" : undefined}
                  truncate
                >
                  {step.title}
                </Text>
                <Text size="xs" c="dimmed" truncate>
                  {step.description}
                </Text>
              </div>
            </Group>
            {!step.done && canWrite && (
              <Button
                component={Link}
                to={step.to}
                size="xs"
                variant={step.key === nextStep?.key ? "filled" : "light"}
                color={step.color}
                rightSection={<IconArrowRight size={14} />}
                style={{ flexShrink: 0 }}
              >
                Go
              </Button>
            )}
          </Group>
        ))}
      </Stack>

      {!canWrite && (
        <Text size="xs" c="dimmed" mt="md">
          Your role has read-only access; ask an administrator to complete setup.
        </Text>
      )}
    </Paper>
  );
});
