import {
  Stack,
  Text,
  NumberInput,
  Switch,
  Group,
  Divider,
} from "@mantine/core";
import { KeyValueList } from "./KeyValueList";

interface HeadersConfigEditorProps {
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
}

export function HeadersConfigEditor({ config, onChange }: HeadersConfigEditorProps) {
  const updateConfig = (key: string, value: string) => {
    onChange({ ...config, [key]: value });
  };

  return (
    <Stack gap="md">
      <Text size="sm" fw={600} c="dimmed" tt="uppercase">
        HSTS (Traefik-style)
      </Text>
      <Group grow>
        <NumberInput
          label="STS Seconds (max-age)"
          description="Set > 0 to add Strict-Transport-Security. 0 = disabled."
          value={parseInt(config.stsSeconds) || 0}
          onChange={(val) =>
            updateConfig("stsSeconds", (val ?? 0).toString())
          }
          min={0}
          placeholder="31536000"
        />
        <Switch
          label="Include Subdomains"
          description="stsIncludeSubdomains"
          checked={config.stsIncludeSubdomains === "true"}
          onChange={(e) =>
            updateConfig(
              "stsIncludeSubdomains",
              e.currentTarget.checked ? "true" : "false"
            )
          }
          mt={20}
        />
      </Group>
      <Group grow>
        <Switch
          label="Preload"
          description="Allow HSTS preload list submission"
          checked={config.stsPreload === "true"}
          onChange={(e) =>
            updateConfig(
              "stsPreload",
              e.currentTarget.checked ? "true" : "false"
            )
          }
        />
        <Switch
          label="Force STS (HTTP dev)"
          description="Add header over HTTP (for development)"
          checked={config.forceStsHeader === "true"}
          onChange={(e) =>
            updateConfig(
              "forceStsHeader",
              e.currentTarget.checked ? "true" : "false"
            )
          }
        />
      </Group>
      <Divider label="Custom Headers" labelPosition="center" />
      <KeyValueList
        config={config}
        onChange={onChange}
        title="Add Request Headers"
        prefix="addRequest_"
        placeholderKey="X-Header"
        placeholderValue="Value"
      />
      <Divider />
      <KeyValueList
        config={config}
        onChange={onChange}
        title="Set Request Headers"
        prefix="setRequest_"
        placeholderKey="X-Header"
        placeholderValue="Value"
      />
      <Divider />
      <KeyValueList
        config={config}
        onChange={onChange}
        title="Add Response Headers"
        prefix="addResponse_"
        placeholderKey="X-Header"
        placeholderValue="Value"
      />
      <KeyValueList
        config={config}
        onChange={onChange}
        title="Set Response Headers"
        prefix="setResponse_"
        placeholderKey="X-Header"
        placeholderValue="Value"
      />
    </Stack>
  );
}
