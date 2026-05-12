import {
  Stack,
  Group,
  Text,
  SegmentedControl,
  Paper,
  ScrollArea,
  Code,
} from "@mantine/core";
import { stringify as yamlStringify } from "yaml";
import type { Route } from "../../types/gateon";
import { useState } from "react";

interface RoutePreviewProps {
  values: Route;
  height?: number | string;
}

export function RoutePreview({ values, height = 300 }: RoutePreviewProps) {
  const [previewFormat, setPreviewFormat] = useState<"json" | "yaml">("json");

  return (
    <Stack gap="xs" h="100%">
      <Group justify="space-between" align="center">
        <Text fw={800} size="xs" c="dimmed" style={{ letterSpacing: 0.5 }}>
          CONFIGURATION PREVIEW
        </Text>
        <SegmentedControl
          size="xs"
          value={previewFormat}
          onChange={(v) => setPreviewFormat(v as "json" | "yaml")}
          data={[
            { value: "json", label: "JSON" },
            { value: "yaml", label: "YAML" },
          ]}
          radius="md"
        />
      </Group>
      <Paper
        withBorder
        p="md"
        bg="var(--mantine-color-black)"
        radius="lg"
        style={{ flex: 1, display: "flex", flexDirection: "column" }}
      >
        <ScrollArea h={height} offsetScrollbars type="auto">
          <Code block bg="transparent" c="indigo.3" style={{ fontSize: 11, lineHeight: 1.4 }}>
            {previewFormat === "yaml"
              ? yamlStringify(values, { indent: 2 })
              : JSON.stringify(values, null, 2)}
          </Code>
        </ScrollArea>
      </Paper>
    </Stack>
  );
}
