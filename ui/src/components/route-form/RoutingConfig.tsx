import { Stack, Group, TextInput, MultiSelect, NumberInput } from "@mantine/core";
import type { Route } from "../../types/gateon";
import type { useForm } from "@tanstack/react-form";

export type RouteFormApi = ReturnType<typeof useForm<Route>>;

export function RoutingConfig({
  form,
  entryPointOptions,
}: {
  form: RouteFormApi;
  entryPointOptions: { value: string; label: string }[];
}) {
  return (
    <Stack gap="md" mt="xl">
      <form.Field
        name="name"
        children={(field) => (
          <TextInput
            label="Friendly Name"
            placeholder="My Application Route"
            required
            value={field.state.value || ""}
            onBlur={field.handleBlur}
            onChange={(e) => field.handleChange(e.target.value)}
            size="md"
            radius="md"
          />
        )}
      />

      <form.Field
        name="entrypoints"
        children={(field) => (
          <MultiSelect
            label="EntryPoints"
            description="Restrict this route to specific addresses"
            data={entryPointOptions}
            value={field.state.value}
            onBlur={field.handleBlur}
            onChange={(v) => field.handleChange(v)}
            placeholder="Select EntryPoints"
            searchable
            clearable
          />
        )}
      />

      <Group align="flex-end" grow>
        <form.Field
          name="rule"
          children={(field) => (
            <TextInput
              label="Rule"
              placeholder="Host(`example.com`)"
              required
              description="Matching expression"
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(e) => field.handleChange(e.target.value)}
            />
          )}
        />
        <form.Field
          name="priority"
          children={(field) => (
            <NumberInput
              label="Priority"
              description="Higher matches first"
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(v) => field.handleChange(Number(v))}
              w={120}
            />
          )}
        />
      </Group>
    </Stack>
  );
}
