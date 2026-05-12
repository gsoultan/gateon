import React, { useState } from "react";
import {
  Card,
  Title,
  Text,
  Stack,
  Group,
  Switch,
  NumberInput,
  TextInput,
  Divider,
  ThemeIcon,
  ActionIcon,
  SimpleGrid,
  Paper,
  Button,
  Select,
  Modal,
  Badge,
} from "@mantine/core";
import {
  IconBell,
  IconPlus,
  IconTrash,
  IconEdit,
  IconBrandSlack,
  IconBrandDiscord,
  IconWebhook,
  IconBrandTelegram,
  IconPlayerPlay,
} from "@tabler/icons-react";
import type { GlobalConfig, AlertingConfig, AlertDispatcher, AlertPlaybook } from "../../types/gateon";
import { generateRandomString } from "../../utils/random";

interface AlertingSettingsCardProps {
  config: GlobalConfig;
  onChange: (config: GlobalConfig) => void;
  disabled?: boolean;
}

export const AlertingSettingsCard: React.FC<AlertingSettingsCardProps> = ({
  config,
  onChange,
  disabled,
}) => {
  const alerting = config.alerting || { enabled: false, dispatchers: [], playbooks: [] };
  const [dispatcherModalOpen, setDispatcherModalOpen] = useState(false);
  const [editingDispatcher, setEditingDispatcher] = useState<AlertDispatcher | null>(null);

  const [playbookModalOpen, setPlaybookModalOpen] = useState(false);
  const [editingPlaybook, setEditingPlaybook] = useState<AlertPlaybook | null>(null);

  const updateAlerting = (value: Partial<AlertingConfig>) => {
    onChange({
      ...config,
      alerting: {
        ...alerting,
        ...value,
      },
    });
  };

  const saveDispatcher = (dispatcher: AlertDispatcher) => {
    const dispatchers = [...(alerting.dispatchers || [])];
    const index = dispatchers.findIndex((d) => d.id === dispatcher.id);
    if (index >= 0) {
      dispatchers[index] = dispatcher;
    } else {
      dispatchers.push(dispatcher);
    }
    updateAlerting({ dispatchers });
    setDispatcherModalOpen(false);
  };

  const deleteDispatcher = (id: string) => {
    updateAlerting({
      dispatchers: (alerting.dispatchers || []).filter((d) => d.id !== id),
      playbooks: (alerting.playbooks || []).map(pb => ({
        ...pb,
        dispatcher_ids: (pb.dispatcher_ids || []).filter(dID => dID !== id)
      }))
    });
  };

  const savePlaybook = (playbook: AlertPlaybook) => {
    const playbooks = [...(alerting.playbooks || [])];
    const index = playbooks.findIndex((p) => p.id === playbook.id);
    if (index >= 0) {
      playbooks[index] = playbook;
    } else {
      playbooks.push(playbook);
    }
    updateAlerting({ playbooks });
    setPlaybookModalOpen(false);
  };

  const deletePlaybook = (id: string) => {
    updateAlerting({
      playbooks: (alerting.playbooks || []).filter((p) => p.id !== id),
    });
  };

  return (
    <Card withBorder radius="md" p="xl" shadow="sm">
      <Stack gap="xl">
        <Group justify="space-between">
          <Group>
            <ThemeIcon size="xl" radius="md" variant="light" color="orange">
              <IconBell size={24} />
            </ThemeIcon>
            <Stack gap={0}>
              <Title order={3}>Alerting & SOAR</Title>
              <Text size="sm" c="dimmed">
                Configure security notifications and automated response playbooks.
              </Text>
            </Stack>
          </Group>
          <Switch
            checked={alerting.enabled}
            onChange={(e) => updateAlerting({ enabled: e.currentTarget.checked })}
            disabled={disabled}
            size="lg"
          />
        </Group>

        {alerting.enabled && (
          <>
            <Divider label="Notification Channels (Dispatchers)" labelPosition="left" />
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
              {(alerting.dispatchers || []).map((d) => (
                <Paper key={d.id} withBorder p="md" radius="md">
                  <Group justify="space-between" align="flex-start">
                    <Group gap="sm">
                      <DispatcherIcon type={d.type} />
                      <div>
                        <Text fw={600} size="sm">{d.name}</Text>
                        <Text size="xs" c="dimmed">{(d.type || '').toUpperCase()}</Text>
                      </div>
                    </Group>
                    <Group gap={4}>
                      <ActionIcon variant="subtle" color="blue" onClick={() => { setEditingDispatcher(d); setDispatcherModalOpen(true); }}>
                        <IconEdit size={16} />
                      </ActionIcon>
                      <ActionIcon variant="subtle" color="red" onClick={() => deleteDispatcher(d.id)}>
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Group>
                  </Group>
                </Paper>
              ))}
              <Button
                variant="light"
                leftSection={<IconPlus size={16} />}
                onClick={() => {
                  setEditingDispatcher({ id: generateRandomString(8), name: "", type: "slack" });
                  setDispatcherModalOpen(true);
                }}
              >
                Add Dispatcher
              </Button>
            </SimpleGrid>

            <Divider label="Alert Playbooks" labelPosition="left" />
            <Stack gap="sm">
              {(alerting.playbooks || []).map((pb) => (
                <Paper key={pb.id} withBorder p="md" radius="md">
                  <Group justify="space-between">
                    <Group gap="lg">
                      <ThemeIcon variant="light" color="cyan">
                        <IconPlayerPlay size={18} />
                      </ThemeIcon>
                      <div>
                        <Text fw={600}>{pb.name}</Text>
                        <Group gap="xs" mt={4}>
                          <Badge size="xs" variant="outline">{pb.event_type}</Badge>
                          <Badge size="xs" color="orange">Score ≥ {pb.threshold}</Badge>
                          <Badge size="xs" color="indigo">{pb.action}</Badge>
                        </Group>
                      </div>
                    </Group>
                    <Group gap={4}>
                      <ActionIcon variant="subtle" color="blue" onClick={() => { setEditingPlaybook(pb); setPlaybookModalOpen(true); }}>
                        <IconEdit size={16} />
                      </ActionIcon>
                      <ActionIcon variant="subtle" color="red" onClick={() => deletePlaybook(pb.id)}>
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Group>
                  </Group>
                </Paper>
              ))}
              <Button
                variant="light"
                color="cyan"
                leftSection={<IconPlus size={16} />}
                onClick={() => {
                  setEditingPlaybook({
                    id: generateRandomString(8),
                    name: "",
                    event_type: "waf_threat",
                    threshold: 0.5,
                    dispatcher_ids: [],
                    action: "notify",
                  });
                  setPlaybookModalOpen(true);
                }}
              >
                Add Playbook
              </Button>
            </Stack>
          </>
        )}
      </Stack>

      <Modal
        opened={dispatcherModalOpen}
        onClose={() => setDispatcherModalOpen(false)}
        title={editingDispatcher?.name ? "Edit Dispatcher" : "Add Dispatcher"}
        size="md"
      >
        {editingDispatcher && (
          <Stack gap="md">
            <TextInput
              label="Name"
              placeholder="e.g. Security Slack"
              value={editingDispatcher.name}
              onChange={(e) => setEditingDispatcher({ ...editingDispatcher, name: e.currentTarget.value })}
              required
            />
            <Select
              label="Type"
              data={[
                { value: "slack", label: "Slack" },
                { value: "discord", label: "Discord" },
                { value: "webhook", label: "Webhook" },
                { value: "telegram", label: "Telegram" },
              ]}
              value={editingDispatcher.type}
              onChange={(val) => setEditingDispatcher({ ...editingDispatcher, type: val || "slack" })}
            />
            {editingDispatcher.type === "slack" && (
              <>
                <TextInput
                  label="Webhook URL"
                  value={editingDispatcher.webhook_url}
                  onChange={(e) => setEditingDispatcher({ ...editingDispatcher, webhook_url: e.currentTarget.value })}
                  required
                />
                <TextInput
                  label="Channel (optional)"
                  placeholder="#alerts"
                  value={editingDispatcher.slack_channel}
                  onChange={(e) => setEditingDispatcher({ ...editingDispatcher, slack_channel: e.currentTarget.value })}
                />
              </>
            )}
            {editingDispatcher.type === "discord" && (
              <TextInput
                label="Webhook URL"
                value={editingDispatcher.webhook_url}
                onChange={(e) => setEditingDispatcher({ ...editingDispatcher, webhook_url: e.currentTarget.value })}
                required
              />
            )}
            {editingDispatcher.type === "webhook" && (
              <TextInput
                label="Webhook URL"
                value={editingDispatcher.webhook_url}
                onChange={(e) => setEditingDispatcher({ ...editingDispatcher, webhook_url: e.currentTarget.value })}
                required
              />
            )}
            {editingDispatcher.type === "telegram" && (
              <>
                <TextInput
                  label="Bot Token"
                  placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
                  value={editingDispatcher.telegram_bot_token}
                  onChange={(e) => setEditingDispatcher({ ...editingDispatcher, telegram_bot_token: e.currentTarget.value })}
                  required
                />
                <TextInput
                  label="Chat ID"
                  placeholder="-100123456789"
                  value={editingDispatcher.telegram_chat_id}
                  onChange={(e) => setEditingDispatcher({ ...editingDispatcher, telegram_chat_id: e.currentTarget.value })}
                  required
                />
              </>
            )}
            <Button onClick={() => saveDispatcher(editingDispatcher)}>Save Dispatcher</Button>
          </Stack>
        )}
      </Modal>

      <Modal
        opened={playbookModalOpen}
        onClose={() => setPlaybookModalOpen(false)}
        title={editingPlaybook?.name ? "Edit Playbook" : "Add Playbook"}
        size="lg"
      >
        {editingPlaybook && (
          <Stack gap="md">
            <TextInput
              label="Playbook Name"
              placeholder="e.g. Critical Threat Response"
              value={editingPlaybook.name}
              onChange={(e) => setEditingPlaybook({ ...editingPlaybook, name: e.currentTarget.value })}
              required
            />
            <Group grow>
              <Select
                label="Trigger Event"
                data={[
                  { value: "all", label: "All Threats" },
                  { value: "waf_threat", label: "WAF Threat" },
                  { value: "high_anomaly", label: "High Anomaly Score" },
                  { value: "impossible_travel", label: "Impossible Travel" },
                  { value: "auth_failure", label: "Auth Failures" },
                ]}
                value={editingPlaybook.event_type}
                onChange={(val) => setEditingPlaybook({ ...editingPlaybook, event_type: val || "all" })}
              />
              <NumberInput
                label="Score Threshold"
                min={0}
                max={1}
                step={0.1}
                value={editingPlaybook.threshold}
                onChange={(val) => setEditingPlaybook({ ...editingPlaybook, threshold: Number(val) })}
              />
            </Group>
            <Select
                label="Action"
                data={[
                    { value: "notify", label: "Notify Only" },
                    { value: "block", label: "Block IP (XDP Shun)" },
                    { value: "challenge", label: "Trigger JS Challenge" },
                ]}
                value={editingPlaybook.action}
                onChange={(val) => setEditingPlaybook({ ...editingPlaybook, action: val || "notify" })}
            />
            <Divider label="Dispatchers to Notify" labelPosition="left" />
            <SimpleGrid cols={2}>
              {(alerting.dispatchers || []).map(d => (
                <Switch
                  key={d.id}
                  label={d.name}
                  checked={(editingPlaybook.dispatcher_ids || []).includes(d.id)}
                  onChange={(e) => {
                    const ids = e.currentTarget.checked
                      ? [...(editingPlaybook.dispatcher_ids || []), d.id]
                      : (editingPlaybook.dispatcher_ids || []).filter(id => id !== d.id);
                    setEditingPlaybook({ ...editingPlaybook, dispatcher_ids: ids });
                  }}
                />
              ))}
            </SimpleGrid>
            {(!alerting.dispatchers || alerting.dispatchers.length === 0) && (
              <Text size="xs" c="red">No dispatchers configured. Please add a dispatcher first.</Text>
            )}
            <Button mt="md" onClick={() => savePlaybook(editingPlaybook)}>Save Playbook</Button>
          </Stack>
        )}
      </Modal>
    </Card>
  );
};

const DispatcherIcon: React.FC<{ type: string }> = ({ type }) => {
  switch (type) {
    case "slack": return <IconBrandSlack color="#4A154B" />;
    case "discord": return <IconBrandDiscord color="#5865F2" />;
    case "telegram": return <IconBrandTelegram color="#26A5E4" />;
    case "webhook": return <IconWebhook color="gray" />;
    default: return <IconBell />;
  }
};
