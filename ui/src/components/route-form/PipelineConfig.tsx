import { Stack, MultiSelect, Select, Divider } from "@mantine/core";
import type { RouteFormApi } from "./RoutingConfig";

export function PipelineConfig({
  form,
  middlewareOptions,
  tlsOptOptions,
  certOptions,
}: {
  form: RouteFormApi;
  middlewareOptions: { value: string; label: string }[];
  tlsOptOptions: { value: string; label: string }[];
  certOptions: { value: string; label: string }[];
}) {
  return (
    <Stack gap="md" mt="xl">
      <form.Field
        name="middlewares"
        children={(field) => (
          <MultiSelect
            label="Middlewares"
            data={middlewareOptions}
            value={field.state.value}
            onBlur={field.handleBlur}
            onChange={(v) => field.handleChange(v)}
            placeholder="Select middlewares"
            searchable
          />
        )}
      />

      <Divider label="TLS Settings" labelPosition="center" my="sm" />

      <form.Field
        name="tls.option_id"
        children={(field) => (
          <Select
            label="TLS Option"
            data={tlsOptOptions}
            value={field.state.value || ""}
            onBlur={field.handleBlur}
            onChange={(v) => field.handleChange(v || "")}
            placeholder="Default policy"
            clearable
          />
        )}
      />

      <form.Field
        name="tls.certificate_ids"
        children={(field) => (
          <MultiSelect
            label="Certificates"
            data={certOptions}
            value={field.state.value || []}
            onBlur={field.handleBlur}
            onChange={(v) => field.handleChange(v)}
            placeholder="Select certificates"
            clearable
          />
        )}
      />
    </Stack>
  );
}
