import { useState, useEffect } from "react";
import {
  Stack,
  Group,
  Button,
  Text,
  Stepper,
  Code,
  ScrollArea,
  Paper,
  Divider,
} from "@mantine/core";
import type { Route } from "../types/gateon";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "@tanstack/react-form";
import { notifications } from "@mantine/notifications";
import {
  useEntryPoints,
  useMiddlewares,
  useTLSOptions,
  useCertificates,
  useServices,
  apiFetch,
} from "../hooks/useGateon";
import {
  IconCheck,
  IconServer,
  IconShieldLock,
  IconRoute,
} from "@tabler/icons-react";
import { RoutingConfig, UpstreamConfig, PipelineConfig } from "./route-form";

export default function RouteForm({
  onSuccess,
  initialData,
}: {
  onSuccess?: () => void;
  initialData?: Route | null;
}) {
  const queryClient = useQueryClient();
  const [active, setActive] = useState(0);

  // Data for form selections
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
        title: "Route Saved",
        message: `Route ${savedRoute.id} has been successfully created/updated.`,
        color: "green",
        icon: <IconCheck size={18} />,
      });
      onSuccess?.();
    },
    onError: (err: any) => {
      notifications.show({
        title: "Error Saving Route",
        message: err.message,
        color: "red",
      });
    },
  });

  const form = useForm<Route>({
    defaultValues: {
      id: "",
      name: "",
      type: "http",
      rule: "",
      priority: 0,
      entrypoints: [],
      middlewares: [],
      service_id: "",
      tls: {
        certificate_ids: [],
        option_id: "",
      },
      disabled: false,
    },
    onSubmit: async ({ value }) => {
      const v = { ...value };
      if (v.type === "tcp" || v.type === "udp") {
        v.rule = "L4()";
      }
      mutation.mutate(v);
    },
  });

  useEffect(() => {
    if (initialData) {
      form.setFieldValue("id", initialData.id);
      form.setFieldValue("name", initialData.name || "");
      form.setFieldValue("type", initialData.type || "http");
      const t = initialData.type || "http";
      form.setFieldValue(
        "rule",
        t === "tcp" || t === "udp" ? "L4()" : (initialData.rule || ""),
      );
      form.setFieldValue("priority", initialData.priority || 0);
      form.setFieldValue("entrypoints", initialData.entrypoints || []);
      form.setFieldValue("middlewares", initialData.middlewares || []);
      form.setFieldValue("service_id", initialData.service_id || "");
      form.setFieldValue(
        "tls",
        initialData.tls || { certificate_ids: [], option_id: "" },
      );
      form.setFieldValue("disabled", initialData.disabled ?? false);
    }
  }, [initialData, form]);

  const nextStep = () =>
    setActive((current) => (current < 3 ? current + 1 : current));
  const prevStep = () =>
    setActive((current) => (current > 0 ? current - 1 : current));

  const routeType = form.state.values.type;
  const epOptionsAll = (epData?.entry_points || []).map((ep) => ({
    value: ep.id,
    label: `${ep.name} (${ep.address})`,
    type: ep.type,
  }));
  const epOptions = epOptionsAll.filter((ep) => {
    if (routeType === "tcp") return ep.type === 2; // EntryPointType.TCP
    if (routeType === "udp") return ep.type === 3; // EntryPointType.UDP
    return ep.type !== 2 && ep.type !== 3; // HTTP/gRPC: exclude L4 entrypoints
  }).map(({ value, label }) => ({ value, label }));

  const mwOptions = (mwData?.middlewares || []).map((mw) => ({
    value: mw.id,
    label: `${mw.name} (${mw.type})`,
  }));

  const tlsOptOptions = (tlsOptData?.tls_options || []).map((opt) => ({
    value: opt.id,
    label: opt.name,
  }));

  const certOptions = (certData?.certificates || []).map((c) => ({
    value: c.id,
    label: c.name,
  }));

  const serviceOptions = (serviceData?.services || [])
    .filter((s) => {
      if (routeType === "tcp" || routeType === "udp") {
        return (s.backend_type || "http") === routeType;
      }
      return (s.backend_type || "http") !== "tcp" && (s.backend_type || "http") !== "udp";
    })
    .map((s) => ({
      value: s.id,
      label: `${s.name} (${s.backend_type || "http"})`,
    }));

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        form.handleSubmit();
      }}
    >
      <Stack gap="lg">
        <Paper withBorder p="xl" radius="lg" shadow="xs">
          <Stack gap="xl">
            <Stepper
              active={active}
              onStepClick={setActive}
              allowNextStepsSelect={false}
              size="sm"
            >
              <Stepper.Step
                label="Routing"
                description="Entry & Matching"
                icon={<IconRoute size={18} />}
              >
                <RoutingConfig form={form} entryPointOptions={epOptions} />
              </Stepper.Step>

              <Stepper.Step
                label="Backend"
                description="Service & Type"
                icon={<IconServer size={18} />}
              >
                <UpstreamConfig form={form} serviceOptions={serviceOptions} />
              </Stepper.Step>

              <Stepper.Step
                label="Pipeline"
                description="Logic & Security"
                icon={<IconShieldLock size={18} />}
              >
                <PipelineConfig
                  form={form}
                  middlewareOptions={mwOptions}
                  tlsOptOptions={tlsOptOptions}
                  certOptions={certOptions}
                />
              </Stepper.Step>

              <Stepper.Completed>
                <Stack gap="md" mt="xl" align="center" py="xl">
                  <Paper p="md" radius="100%" bg="green.1" c="green.6">
                    <IconCheck size={40} />
                  </Paper>
                  <Text size="lg" fw={800}>
                    Configuration Ready
                  </Text>
                  <Text size="sm" c="dimmed" ta="center">
                    Review the JSON preview below.
                  </Text>
                  <form.Subscribe
                    selector={(state) => [
                      state.values.name,
                      state.values.rule,
                      state.values.service_id,
                    ]}
                    children={([name, rule, service_id]) => {
                      const type = form.state.values.type;
                      const isL4 = type === "tcp" || type === "udp";
                      const ruleOk = isL4 ? true : !!rule;
                      return (
                      <Button
                        type="submit"
                        size="md"
                        radius="md"
                        loading={mutation.isPending}
                        disabled={!name || !ruleOk || !service_id}
                        w={200}
                      >
                        Save Route
                      </Button>
                      );
                    }}
                  />
                </Stack>
              </Stepper.Completed>
            </Stepper>

            <Group justify="flex-end" mt="xl">
              {active !== 0 && active <= 3 && (
                <Button variant="subtle" color="gray" onClick={prevStep}>
                  Back
                </Button>
              )}
              {active < 3 && (
                <form.Subscribe
                  selector={(state) => [
                    state.values.name,
                    state.values.rule,
                    state.values.service_id,
                    state.values.type,
                  ]}
                  children={([name, rule, service_id, type]) => {
                    const isL4 = type === "tcp" || type === "udp";
                    const ruleOk = isL4 ? true : !!rule;
                    return (
                    <Button
                      onClick={nextStep}
                      radius="md"
                      px="xl"
                      disabled={
                        (active === 0 && (!name || !ruleOk || !type)) ||
                        (active === 1 && !service_id)
                      }
                    >
                      Next Step
                    </Button>
                    );
                  }}
                />
              )}
            </Group>
          </Stack>
        </Paper>

        <Stack gap="xs">
          <Divider
            label={
              <Text fw={800} size="xs" c="dimmed">
                Route Definition Preview
              </Text>
            }
            labelPosition="center"
          />
          <Paper
            withBorder
            p="md"
            bg="var(--mantine-color-black)"
            radius="lg"
          >
            <ScrollArea h={200} offsetScrollbars>
              <form.Subscribe
                selector={(state) => state.values}
                children={(values) => (
                  <Code block bg="transparent" c="indigo.3" style={{ fontSize: 12 }}>
                    {JSON.stringify(values, null, 2)}
                  </Code>
                )}
              />
            </ScrollArea>
          </Paper>
        </Stack>
      </Stack>
    </form>
  );
}
