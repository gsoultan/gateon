import { useState } from "react";
import { Stack, MultiSelect, Select, Divider } from "@mantine/core";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { apiFetch, getApiErrorMessage } from "../../hooks/useGateon";
import { useMiddlewarePresets } from "../../hooks/useGateon";
import type { RouteFormApi } from "./RoutingConfig";
import type { Middleware } from "../../types/gateon";

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
  const queryClient = useQueryClient();
  const { data: presets } = useMiddlewarePresets();
  const [presetValue, setPresetValue] = useState<string | null>(null);

  const applyPresetMutation = useMutation({
    mutationFn: async (presetId: string) => {
      const preset = presets?.find((p) => p.id === presetId);
      if (!preset) throw new Error("Preset not found");

      const ids: string[] = [];
      for (let i = 0; i < preset.middlewares.length; i++) {
        const item = preset.middlewares[i];
        const mw: Middleware = {
          id: "",
          name: `${preset.name} - ${item.name} ${Date.now()}`,
          type: item.type,
          config: item.config,
        };
        const res = await apiFetch("/v1/middlewares", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(mw),
        });
        if (!res.ok) throw new Error(await res.text());
        const saved = await res.json();
        ids.push(saved.id);
      }
      return ids;
    },
    onSuccess: (ids) => {
      const current = form.state.values.middlewares || [];
      form.setFieldValue("middlewares", [...current, ...ids]);
      queryClient.invalidateQueries({ queryKey: ["middlewares"] });
      setPresetValue(null); // reset so user can apply same preset again
      notifications.show({
        title: "Preset Applied",
        message: `Added ${ids.length} middlewares to this route.`,
        color: "green",
      });
    },
    onError: (err: unknown) => {
      notifications.show({
        title: "Preset Failed",
        message: getApiErrorMessage(err),
        color: "red",
      });
    },
  });

  return (
    <Stack gap="md" mt="xl">
      {presets && presets.length > 0 && (
        <Select
          label="Add Protection Preset"
          description="Creates and attaches middlewares (ratelimit, inflightreq, buffering) to this route"
          placeholder="Choose a preset..."
          data={presets.map((p) => ({ value: p.id, label: p.name }))}
          value={presetValue}
          onChange={(v) => {
            setPresetValue(v);
            if (v) applyPresetMutation.mutate(v);
          }}
          clearable
          disabled={applyPresetMutation.isPending}
        />
      )}
      <form.Field
        name="middlewares"
        children={(field) => (
          <MultiSelect
            label="Middlewares"
            description="Add protection presets above or select existing middlewares"
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
