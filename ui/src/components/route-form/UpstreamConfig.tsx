import { Stack, Select } from "@mantine/core";
import type { RouteFormApi } from "./RoutingConfig";

export function UpstreamConfig({
  form,
  serviceOptions,
}: {
  form: RouteFormApi;
  serviceOptions: { value: string; label: string }[];
}) {
  return (
    <Stack gap="md" mt="xl">
      <form.Field
        name="service_id"
        children={(field) => (
          <Select
            label="Upstream Service"
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

      <form.Field
        name="type"
        children={(field) => (
          <Select
            label="Protocol Type"
            data={["http", "grpc"]}
            value={field.state.value}
            onBlur={field.handleBlur}
            onChange={(v) => field.handleChange(v as "http" | "grpc")}
            required
          />
        )}
      />
    </Stack>
  );
}
