// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useMemo, useState } from "react";
import { Button, Collapse, Divider, Group, Paper, Stack, Text } from "@mantine/core";
import type { Route } from "../../types/gateon";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "@tanstack/react-form";
import { notifications } from "@mantine/notifications";
import { useEntryPoints, useMiddlewares, useTLSOptions, useCertificates, useServices, apiFetch, getApiErrorMessage } from "../../hooks/useGateon";
import { IconCheck, IconCode, IconRoute, IconServer, IconShieldLock } from "@tabler/icons-react";
import { FormSection } from "../layout";
import { RoutingConfig, UpstreamConfig, PipelineConfig, RoutePreview } from "./";
import { formValuesToRoute, routeToFormValues } from "./routePayload";
import { summarizeRoute } from "./routeSummary";

/**
 * One page: Match, Send to, Policies and TLS, in that order, with the route
 * read back as a sentence at the top and the saved form as code at the foot.
 * The four-step wizard it replaces hid the service behind a Next button and
 * put the only Save on its last step; here every field is on screen and Save
 * is enabled the moment the route is complete.
 */
export default function RouteForm({ onSuccess, initialData }: { onSuccess?: () => void; initialData?: Route | null }) {
  const queryClient = useQueryClient();
  const [showCode, setShowCode] = useState(false);

  const { data: epData } = useEntryPoints();
  const { data: mwData } = useMiddlewares();
  const { data: tlsOptData } = useTLSOptions();
  const { data: certData } = useCertificates();
  const { data: serviceData } = useServices();

  const mutation = useMutation({
    mutationFn: async (newRoute: Route) => {
      const res = await apiFetch("/v1/routes", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newRoute),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: (savedRoute: Route) => {
      queryClient.invalidateQueries({ queryKey: ["routes"] });
      notifications.show({
        title: "Route saved",
        message: `${savedRoute.name || savedRoute.id} is in force.`,
        color: "green",
        icon: <IconCheck size={18} />,
      });
      onSuccess?.();
    },
    onError: (err: unknown) => {
      notifications.show({ title: "The route was not saved", message: getApiErrorMessage(err), color: "red" });
    },
  });

  const form = useForm({
    defaultValues: {
      id: "",
      name: "",
      type: "http" as const,
      rule: "",
      priority: 0,
      entrypoints: [] as string[],
      middlewares: [] as string[],
      serviceId: "",
      tls: { certificateIds: [] as string[], optionId: "" },
      disabled: false,
      streamMode: 0,
    } as Route,
    onSubmit: async ({ value }) => {
      mutation.mutate(formValuesToRoute(value));
    },
  });

  useEffect(() => {
    if (initialData) {
      const v = routeToFormValues(initialData);
      form.setFieldValue("id", v.id);
      form.setFieldValue("name", v.name);
      form.setFieldValue("type", v.type);
      form.setFieldValue("rule", v.rule);
      form.setFieldValue("priority", v.priority);
      form.setFieldValue("entrypoints", v.entrypoints);
      form.setFieldValue("middlewares", v.middlewares);
      form.setFieldValue("serviceId", v.serviceId);
      form.setFieldValue("tls", v.tls);
      form.setFieldValue("disabled", v.disabled);
      form.setFieldValue("streamMode", v.streamMode);
    }
  }, [initialData, form]);

  const routeType = form.state.values.type;
  const epOptionsAll = (epData?.entryPoints || []).map((ep) => ({ value: ep.id, label: `${ep.name} (${ep.address})`, type: ep.type }));
  const epOptions = epOptionsAll
    .filter((ep) => {
      if (routeType === "tcp") return ep.type === 2; // EntryPointType.TCP
      if (routeType === "udp") return ep.type === 3; // EntryPointType.UDP
      return ep.type !== 2 && ep.type !== 3; // HTTP/gRPC: exclude L4 listeners
    })
    .map(({ value, label }) => ({ value, label }));

  const mwOptions = (mwData?.middlewares || []).map((mw) => ({ value: mw.id, label: `${mw.name} (${mw.type})` }));

  const tlsOptOptions = ((tlsOptData as any)?.tlsOptions || (tlsOptData as any)?.options || []).map((opt: any) => ({ value: opt.id, label: opt.name }));

  const certOptions = (certData?.certificates || []).map((c) => ({ value: c.id, label: c.name }));

  const serviceOptions = (serviceData?.services || [])
    .filter((s) => {
      if (routeType === "tcp" || routeType === "udp") return (s.backendType || "http") === routeType;
      return (s.backendType || "http") !== "tcp" && (s.backendType || "http") !== "udp";
    })
    .map((s) => ({ value: s.id, label: `${s.name} (${s.backendType || "http"})` }));

  const lookups = useMemo(
    () => ({
      listenerNames: new Map((epData?.entryPoints || []).map((ep) => [ep.id, ep.name || ep.address])),
      serviceNames: new Map((serviceData?.services || []).map((s) => [s.id, s.name])),
      policyNames: new Map((mwData?.middlewares || []).map((mw) => [mw.id, mw.name])),
    }),
    [epData?.entryPoints, serviceData?.services, mwData?.middlewares],
  );

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        form.handleSubmit();
      }}
    >
      <Stack gap="xl">
        <form.Subscribe
          selector={(state) => state.values}
          children={(values) => (
            <Paper withBorder p="md" radius="md" bg="var(--mantine-color-default-hover)">
              <Text size="sm" aria-live="polite">
                {summarizeRoute(values, lookups)}
              </Text>
            </Paper>
          )}
        />

        <FormSection title="Match" description="What this route is called, and which requests on which listeners it takes." icon={<IconRoute size={18} />}>
          <RoutingConfig form={form} entryPointOptions={epOptions} />
        </FormSection>

        <Divider />

        <FormSection title="Send to" description="The service whose targets answer the matched requests." icon={<IconServer size={18} />}>
          <UpstreamConfig form={form} serviceOptions={serviceOptions} />
        </FormSection>

        <Divider />

        <FormSection title="Policies and TLS" description="What runs on each request before the service sees it, and the certificate the route serves." icon={<IconShieldLock size={18} />}>
          <PipelineConfig form={form} middlewareOptions={mwOptions} tlsOptOptions={tlsOptOptions} certOptions={certOptions} />
        </FormSection>

        <Divider />

        <Stack gap="sm">
          <Group justify="space-between">
            <Button variant="subtle" color="gray" leftSection={<IconCode size={16} />} onClick={() => setShowCode((v) => !v)} aria-expanded={showCode}>
              {showCode ? "Hide code" : "View as code"}
            </Button>
            <form.Subscribe
              selector={(state) => [state.values.name, state.values.rule, state.values.serviceId, state.values.type]}
              children={([name, rule, serviceId, type]) => {
                const isL4 = type === "tcp" || type === "udp";
                const ruleOk = isL4 ? true : !!rule;
                return (
                  <Button type="submit" loading={mutation.isPending} disabled={!name || !ruleOk || !serviceId}>
                    {initialData?.id ? "Save route" : "Create route"}
                  </Button>
                );
              }}
            />
          </Group>
          <Collapse expanded={showCode}>
            <form.Subscribe selector={(state) => state.values} children={(values) => <RoutePreview values={values} height={320} />} />
          </Collapse>
        </Stack>
      </Stack>
    </form>
  );
}
