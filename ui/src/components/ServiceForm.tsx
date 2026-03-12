import { useEffect } from "react";
import {
  TextInput,
  Stack,
  Group,
  Button,
  Paper,
  Text,
  ActionIcon,
  Select,
  NumberInput,
} from "@mantine/core";
import { IconPlus, IconTrash, IconCheck } from "@tabler/icons-react";
import type { Service } from "../types/gateon";
import { apiFetch } from "../hooks/useGateon";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "@tanstack/react-form";
import { notifications } from "@mantine/notifications";

export function ServiceForm({
  onSuccess,
  initialData,
}: {
  onSuccess?: () => void;
  initialData?: Service | null;
}) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async (newService: Service) => {
      const res = await apiFetch("/v1/services", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newService),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: (savedService: Service) => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      notifications.show({
        title: "Service Saved",
        message: `Service ${savedService.id} has been successfully created/updated.`,
        color: "green",
        icon: <IconCheck size={18} />,
      });
      onSuccess?.();
    },
    onError: (err: any) => {
      notifications.show({
        title: "Error Saving Service",
        message: err.message,
        color: "red",
      });
    },
  });

  const form = useForm<Service>({
    defaultValues: {
      id: "",
      name: "",
      weighted_targets: [{ url: "", weight: 1 }],
      load_balancer_policy: "round_robin",
      health_check_path: "",
    },
    onSubmit: async ({ value }) => {
      // Filter out empty targets
      const cleanValue = {
        ...value,
        weighted_targets: value.weighted_targets.filter((t) => t.url.trim() !== ""),
      };
      if (cleanValue.weighted_targets.length === 0) {
        notifications.show({
          title: "Validation Error",
          message: "At least one target URL is required.",
          color: "red",
        });
        return;
      }
      mutation.mutate(cleanValue);
    },
  });

  useEffect(() => {
    if (initialData) {
      form.setFieldValue("id", initialData.id);
      form.setFieldValue("name", initialData.name);
      form.setFieldValue(
        "weighted_targets",
        initialData.weighted_targets?.length > 0
          ? initialData.weighted_targets
          : [{ url: "", weight: 1 }],
      );
      form.setFieldValue(
        "load_balancer_policy",
        initialData.load_balancer_policy || "round_robin",
      );
      form.setFieldValue("health_check_path", initialData.health_check_path || "");
    }
  }, [initialData, form]);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        form.handleSubmit();
      }}
    >
      <Stack gap="md">
        <form.Field
          name="name"
          children={(field) => (
            <TextInput
              label="Service Name"
              required
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(e) => field.handleChange(e.target.value)}
              placeholder="Authentication Microservice"
              size="md"
              radius="md"
            />
          )}
        />

        <Paper withBorder p="md" radius="md">
          <Stack gap="sm">
            <Group justify="space-between">
              <Text fw={500} size="sm">
                Targets
              </Text>
              <Button
                variant="subtle"
                size="compact-xs"
                leftSection={<IconPlus size={14} />}
                onClick={() =>
                  form.pushFieldValue("weighted_targets", { url: "", weight: 1 })
                }
              >
                Add Target
              </Button>
            </Group>

            <form.Field
              name="weighted_targets"
              mode="array"
              children={(field) => (
                <>
                  {field.state.value.map((_, i) => (
                    <Group key={i} grow align="flex-end">
                      <form.Field
                        name={`weighted_targets[${i}].url`}
                        children={(urlField) => (
                          <TextInput
                            placeholder="http://host:port"
                            value={urlField.state.value}
                            onBlur={urlField.handleBlur}
                            onChange={(e) => urlField.handleChange(e.target.value)}
                            flex={1}
                          />
                        )}
                      />
                      <form.Field
                        name={`weighted_targets[${i}].weight`}
                        children={(weightField) => (
                          <NumberInput
                            value={weightField.state.value}
                            onBlur={weightField.handleBlur}
                            onChange={(v) => weightField.handleChange(Number(v))}
                            style={{ maxWidth: 100 }}
                            min={1}
                          />
                        )}
                      />
                      <ActionIcon
                        color="red"
                        variant="light"
                        onClick={() => form.removeFieldValue("weighted_targets", i)}
                        disabled={field.state.value.length === 1}
                      >
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Group>
                  ))}
                </>
              )}
            />
          </Stack>
        </Paper>

        <form.Field
          name="load_balancer_policy"
          children={(field) => (
            <Select
              label="Load Balancer Policy"
              data={[
                { label: "Round Robin", value: "round_robin" },
                { label: "Least Connections", value: "least_conn" },
                { label: "Weighted Round Robin", value: "weighted_round_robin" },
              ]}
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(v) => field.handleChange(v || "round_robin")}
            />
          )}
        />

        <form.Field
          name="health_check_path"
          children={(field) => (
            <TextInput
              label="Health Check Path"
              placeholder="/healthz"
              value={field.state.value}
              onBlur={field.handleBlur}
              onChange={(e) => field.handleChange(e.target.value)}
            />
          )}
        />

        <Button
          type="submit"
          loading={mutation.isPending}
          fullWidth
          mt="md"
          radius="md"
        >
          Save Service
        </Button>
      </Stack>
    </form>
  );
}
