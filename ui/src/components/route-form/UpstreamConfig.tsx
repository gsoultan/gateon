import { Stack, Select, Text } from "@mantine/core";
import type { RouteFormApi } from "./RoutingConfig";

interface UpstreamConfigProps {
  form: RouteFormApi;
  serviceOptions: { value: string; label: string }[];
}

export function UpstreamConfig({ form, serviceOptions }: UpstreamConfigProps) {
  const routeType = form.state.values.type;
  const typeLabel =
    routeType === "grpc"
      ? "gRPC"
      : routeType === "graphql"
        ? "GraphQL"
        : routeType === "tcp"
          ? "TCP (L4)"
          : routeType === "udp"
            ? "UDP (L4)"
            : "HTTP";

  return (
    <Stack gap="md" mt="xl">
      <form.Field
        name="service_id"
        children={(field) => (
          <Select
            label="Upstream Service"
            description={
              routeType === "tcp" || routeType === "udp"
                ? `Select a ${typeLabel} backend service`
                : "Select the backend service (HTTP, GraphQL, or gRPC targets)"
            }
            data={serviceOptions}
            value={field.state.value}
            onBlur={field.handleBlur}
            onChange={(v) => field.handleChange(v || "")}
            required
            placeholder="Choose a service"
            searchable
          />
        )}
      />
      <Text size="xs" c="dimmed">
        Route type: {typeLabel} (set in previous step)
      </Text>
    </Stack>
  );
}
