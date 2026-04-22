import {
  Card,
  Title,
  Text,
  Stack,
  Switch,
  TextInput,
  NumberInput,
  Group,
  Button,
  Divider,
  Badge,
  Alert,
} from "@mantine/core";
import { IconDatabase, IconDownload, IconAlertCircle, IconCheck } from "@tabler/icons-react";
import { useEffect, useState } from "react";
import { notifications } from "@mantine/notifications";
import type { GeoIPConfig } from "../../types/gateon";
import { apiFetch } from "../../hooks/useGateon";

interface GeoIPStatus {
  exists: boolean;
  path: string;
  info: string;
}

interface GeoIPSettingsCardProps {
  config: GeoIPConfig;
  onChange: (config: GeoIPConfig) => void;
}

export function GeoIPSettingsCard({ config, onChange }: GeoIPSettingsCardProps) {
  const [status, setStatus] = useState<GeoIPStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState(false);

  const fetchStatus = async () => {
    try {
      setLoading(true);
      const resp = await apiFetch("/v1/geoip/status");
      if (resp.ok) {
        const data = await resp.json();
        setStatus(data);
      }
    } catch (err) {
      console.error("Failed to fetch GeoIP status", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleUpdate = async () => {
    try {
      setUpdating(true);
      const resp = await apiFetch("/v1/geoip/update", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          maxmind_license_key: config.maxmind_license_key,
        }),
      });
      if (resp.ok) {
        notifications.show({
          title: "Success",
          message: "GeoIP database updated successfully",
          color: "green",
          icon: <IconCheck size={16} />,
        });
        fetchStatus();
      } else {
        const msg = await resp.text();
        notifications.show({
          title: "Update Failed",
          message: msg || "Failed to update GeoIP database",
          color: "red",
          icon: <IconAlertCircle size={16} />,
        });
      }
    } catch (err) {
      notifications.show({
        title: "Error",
        message: "Network error occurred during update",
        color: "red",
      });
    } finally {
      setUpdating(false);
    }
  };

  return (
    <Card withBorder padding="lg" radius="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Group>
            <IconDatabase size={24} />
            <div>
              <Title order={4}>GeoIP Configuration</Title>
              <Text size="sm" color="dimmed">
                Manage geographical intelligence database for IP resolution.
              </Text>
            </div>
          </Group>
          {status && (
            <Badge color={status.exists ? "green" : "red"} variant="light">
              {status.exists ? "Database Loaded" : "Not Loaded"}
            </Badge>
          )}
        </Group>

        <Divider />

        {status && status.exists && (
          <Alert color="blue" icon={<IconCheck size={16} />}>
            <Text size="sm"><b>Active Database:</b> {status.info}</Text>
            <Text size="xs" color="dimmed">Path: {status.path}</Text>
          </Alert>
        )}

        {!status?.exists && (
          <Alert color="orange" icon={<IconAlertCircle size={16} />}>
            GeoIP database is missing. Trace points will not be shown on the map unless a database is provided or auto-update is configured with a license key.
          </Alert>
        )}

        <Stack gap="sm">
          <Switch
            label="Enable GeoIP Resolution"
            description="Use GeoIP database to resolve IP addresses to geographical locations"
            checked={config.enabled}
            onChange={(e) => onChange({ ...config, enabled: e.currentTarget.checked })}
          />

          <TextInput
            label="Database Path"
            placeholder="e.g. geoip/GeoLite2-City.mmdb"
            description="Custom path to your MaxMind GeoLite2 City database"
            value={config.db_path || ""}
            onChange={(e) => onChange({ ...config, db_path: e.currentTarget.value })}
            disabled={!config.enabled}
          />

          <Divider label="Auto Update" labelPosition="center" />

          <Switch
            label="Enable Automatic Updates"
            description="Periodically download the latest database from MaxMind"
            checked={config.auto_update}
            onChange={(e) => onChange({ ...config, auto_update: e.currentTarget.checked })}
            disabled={!config.enabled}
          />

          <TextInput
            label="MaxMind License Key"
            placeholder="Your MaxMind license key"
            description="Required for automatic updates. Get one at maxmind.com"
            type="password"
            value={config.maxmind_license_key || ""}
            onChange={(e) => onChange({ ...config, maxmind_license_key: e.currentTarget.value })}
            disabled={!config.enabled || !config.auto_update}
          />

          <NumberInput
            label="Update Interval (Days)"
            description="How often to check for updates"
            min={1}
            max={365}
            value={config.update_interval_days || 30}
            onChange={(val) => onChange({ ...config, update_interval_days: Number(val) })}
            disabled={!config.enabled || !config.auto_update}
          />

          <Button
            leftSection={<IconDownload size={16} />}
            variant="light"
            onClick={handleUpdate}
            loading={updating}
            disabled={!config.enabled || !config.maxmind_license_key}
          >
            Update Now
          </Button>
        </Stack>
      </Stack>
    </Card>
  );
}
