import React from "react";
import { Paper, Text, Badge, Stack, Group, ThemeIcon, Box } from "@mantine/core";
import { IconShieldLock, IconLock, IconBug, IconActivity } from "@tabler/icons-react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import type { Anomaly } from "../../types/gateon";
import "leaflet/dist/leaflet.css";

// Theme-aware basemaps. The component chrome (legend/empty-state) is tuned for a
// dark basemap, so in dark mode we use CARTO dark_all; in light mode CARTO light_all
// keeps labels readable. Both fall back to OSM attribution requirements.
const TILES = {
  dark: {
    url: "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    bg: "#0f172a",
  },
  light: {
    url: "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png",
    bg: "#e5e7eb",
  },
} as const;

const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>';

interface AnomalyMapProps {
  anomalies: Anomaly[];
  onTrace?: (ip: string) => void;
}

const getSeverityColor = (sev: string) => {
  switch (sev.toLowerCase()) {
    case "critical": return "#fa5252"; // red.6
    case "high": return "#fd7e14"; // orange.6
    case "medium": return "#fab005"; // yellow.6
    default: return "#228be6"; // blue.6
  }
};

const getIcon = (type: string) => {
  if (type.includes("attack") || type.includes("hacker") || type.includes("violation")) return <IconShieldLock size={14} />;
  if (type.includes("brute")) return <IconLock size={14} />;
  if (type.includes("scan") || type.includes("security")) return <IconBug size={14} />;
  return <IconActivity size={14} />;
};

const AnomalyMap: React.FC<AnomalyMapProps> = ({ anomalies, onTrace }) => {
  // Always use the light basemap so the geography stays clear regardless of the
  // app's dark/light theme. The colored severity markers read well against light tiles.
  const tiles = TILES.light;
  const isDark = false;

  // Filter anomalies that have geo coordinates
  // We include 0,0 if country_code is present, as it might be a valid coordinate for some countries or fallback
  const geoAnomalies = anomalies.filter(a =>
    a.latitude !== undefined &&
    a.longitude !== undefined &&
    a.country_code &&
    a.country_code !== "XX"
  );

  return (
    <Paper withBorder radius="lg" shadow="sm" p={0} style={{ height: 400, overflow: "hidden", position: "relative" }}>
      <MapContainer
        center={[20, 0]}
        zoom={2}
        style={{ height: "100%", width: "100%", background: tiles.bg }}
        scrollWheelZoom={false}
      >
        <TileLayer
          attribution={TILE_ATTRIBUTION}
          url={tiles.url}
        />
        
        {geoAnomalies.map((a, i) => {
          const color = getSeverityColor(a.severity);
          
          return (
            <CircleMarker
              key={i}
              center={[a.latitude!, a.longitude!]}
              pathOptions={{
                fillColor: color,
                color: "white",
                weight: 2,
                fillOpacity: 0.8
              }}
              radius={8}
              eventHandlers={{
                click: () => onTrace?.(a.source)
              }}
            >
              <Popup>
                <Stack gap={4} p={4}>
                  <Group gap="xs">
                    <ThemeIcon variant="light" color={a.severity.toLowerCase() === 'critical' ? 'red' : a.severity.toLowerCase() === 'high' ? 'orange' : 'yellow'} size="xs">
                      {getIcon(a.type)}
                    </ThemeIcon>
                    <Text fw={700} size="xs" style={{ textTransform: "uppercase" }}>{(a.type || "unknown").replace(/_/g, " ")}</Text>
                  </Group>
                  <Text size="xs" maw={200}>{a.description}</Text>
                  <Group justify="space-between">
                    <Badge color={a.severity.toLowerCase() === 'critical' ? 'red' : a.severity.toLowerCase() === 'high' ? 'orange' : 'yellow'} size="xs">{a.severity}</Badge>
                    <Text size="10px" c="dimmed">{a.country_code} - {a.source}</Text>
                  </Group>
                  <Text size="10px" c="blue" fw={700} ta="center" mt={4} style={{ cursor: "pointer" }}>Click marker to trace IP route</Text>
                </Stack>
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>

      {/* Legend */}
      <Box style={{ position: "absolute", bottom: 10, left: 10, backgroundColor: isDark ? "rgba(15, 23, 42, 0.8)" : "rgba(255, 255, 255, 0.85)", padding: "4px 8px", borderRadius: 4, backdropFilter: "blur(4px)", zIndex: 1000 }}>
        <Group gap="sm">
          <Group gap={4}>
            <Box style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#fa5252" }} />
            <Text size="10px" c={isDark ? "white" : "dark"} fw={700}>Critical</Text>
          </Group>
          <Group gap={4}>
            <Box style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#fd7e14" }} />
            <Text size="10px" c={isDark ? "white" : "dark"} fw={700}>High</Text>
          </Group>
          <Group gap={4}>
            <Box style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#fab005" }} />
            <Text size="10px" c={isDark ? "white" : "dark"} fw={700}>Medium</Text>
          </Group>
        </Group>
      </Box>

      {geoAnomalies.length === 0 && (
        <Stack align="center" justify="center" h="100%" gap="xs" style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, zIndex: 1000, pointerEvents: "none", backgroundColor: isDark ? "rgba(15, 23, 42, 0.5)" : "rgba(229, 231, 235, 0.5)" }}>
          <IconActivity size={40} color="#94a3b8" />
          <Text c={isDark ? "white" : "dark"} size="sm" fw={500}>No geo-tagged anomalies detected</Text>
        </Stack>
      )}
    </Paper>
  );
};

export default AnomalyMap;
