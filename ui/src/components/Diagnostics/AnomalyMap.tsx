import React, { useState } from "react";
import { Paper, Text, Badge, Stack, Group, ThemeIcon, Box, Tooltip } from "@mantine/core";
import { IconShieldLock, IconLock, IconBug, IconActivity } from "@tabler/icons-react";
import type { Anomaly } from "../../types/gateon";

interface AnomalyMapProps {
  anomalies: Anomaly[];
  onTrace?: (ip: string) => void;
}

const getSeverityColor = (sev: string) => {
  switch (sev.toLowerCase()) {
    case "critical": return "red";
    case "high": return "orange";
    case "medium": return "yellow";
    default: return "blue";
  }
};

const getIcon = (type: string) => {
  if (type.includes("attack") || type.includes("hacker") || type.includes("violation")) return <IconShieldLock size={14} />;
  if (type.includes("brute")) return <IconLock size={14} />;
  if (type.includes("scan") || type.includes("security")) return <IconBug size={14} />;
  return <IconActivity size={14} />;
};

const AnomalyMap: React.FC<AnomalyMapProps> = ({ anomalies, onTrace }) => {
  const [hovered, setHovered] = useState<number | null>(null);

  // Filter anomalies that have geo coordinates
  const geoAnomalies = anomalies.filter(a => 
    a.latitude !== undefined && 
    a.longitude !== undefined && 
    a.country_code && 
    a.country_code !== "XX"
  );

  // Equirectangular projection
  // x: -180 to 180 -> 0% to 100%
  // y: 90 to -90 -> 0% to 100%
  const getPos = (lat: number, lon: number) => {
    const x = ((lon + 180) / 360) * 100;
    const y = ((90 - lat) / 180) * 100;
    return { x: `${x}%`, y: `${y}%` };
  };

  return (
    <Paper withBorder radius="lg" shadow="sm" p={0} style={{ height: 400, overflow: "hidden", position: "relative", backgroundColor: "#0f172a" }}>
      {/* Abstract World Map Background (Dots) */}
      <Box style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, opacity: 0.2, pointerEvents: "none" }}>
        <svg width="100%" height="100%" viewBox="0 0 360 180" preserveAspectRatio="xMidYMid slice">
          <pattern id="dotPattern" x="0" y="0" width="4" height="4" patternUnits="userSpaceOnUse">
             <circle cx="1" cy="1" r="0.8" fill="#334155" />
          </pattern>
          {/* Detailed World Map Paths */}
          <g fill="url(#dotPattern)" stroke="#1e293b" strokeWidth="0.2">
            {/* North America */}
            <path d="M50,30 L70,25 L100,30 L115,50 L100,80 L80,85 L50,80 L40,50 Z" />
            {/* South America */}
            <path d="M90,90 L110,95 L115,120 L100,155 L80,165 L70,140 L80,110 Z" />
            {/* Europe */}
            <path d="M160,25 L190,20 L210,30 L205,55 L170,60 L155,45 Z" />
            {/* Africa */}
            <path d="M155,65 L200,60 L230,85 L220,130 L195,160 L165,150 L145,110 L150,80 Z" />
            {/* Asia */}
            <path d="M210,25 L280,20 L330,30 L350,70 L330,105 L280,115 L225,100 L215,60 Z" />
            {/* Australia */}
            <path d="M300,120 L340,125 L345,150 L310,160 L290,145 Z" />
            {/* Greenland */}
            <path d="M120,10 L150,15 L140,30 L115,25 Z" />
          </g>
        </svg>
      </Box>

      {/* Markers */}
      <Box style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0 }}>
        {geoAnomalies.map((a, i) => {
          const pos = getPos(a.latitude!, a.longitude!);
          const color = getSeverityColor(a.severity);
          const isHovered = hovered === i;

          return (
            <Tooltip
              key={i}
              label={
                <Stack gap={4} p={4}>
                  <Group gap="xs">
                    <ThemeIcon variant="light" color={color} size="xs">
                      {getIcon(a.type)}
                    </ThemeIcon>
                    <Text fw={700} size="xs" style={{ textTransform: "uppercase" }}>{a.type.replace(/_/g, " ")}</Text>
                  </Group>
                  <Text size="xs" maw={200}>{a.description}</Text>
                  <Group justify="space-between">
                    <Badge color={color} size="xs">{a.severity}</Badge>
                    <Text size="10px" c="dimmed">{a.country_code} - {a.source}</Text>
                  </Group>
                  <Text size="10px" c="blue" fw={700} ta="center" mt={4}>Click to trace IP route</Text>
                </Stack>
              }
              opened={isHovered || undefined}
            >
              <Box
                style={{
                  position: "absolute",
                  left: pos.x,
                  top: pos.y,
                  transform: "translate(-50%, -50%)",
                  cursor: "pointer",
                  zIndex: isHovered ? 100 : 10,
                }}
                onMouseEnter={() => setHovered(i)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => onTrace?.(a.source)}
              >
                {/* Ping Animation */}
                <Box
                  style={{
                    position: "absolute",
                    width: 20,
                    height: 20,
                    borderRadius: "50%",
                    backgroundColor: `var(--mantine-color-${color}-6)`,
                    opacity: 0.4,
                    transform: "translate(-25%, -25%)",
                    animation: "ping 2s cubic-bezier(0, 0, 0.2, 1) infinite",
                  }}
                />
                {/* Marker Dot */}
                <Box
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    backgroundColor: `var(--mantine-color-${color}-6)`,
                    border: "2px solid white",
                    boxShadow: "0 0 10px rgba(0,0,0,0.5)",
                  }}
                />
              </Box>
            </Tooltip>
          );
        })}
      </Box>

      <style dangerouslySetInnerHTML={{ __html: `
        @keyframes ping {
          75%, 100% {
            transform: scale(2);
            opacity: 0;
          }
        }
      `}} />

      {/* Legend */}
      <Box style={{ position: "absolute", bottom: 10, left: 10, backgroundColor: "rgba(15, 23, 42, 0.8)", padding: "4px 8px", borderRadius: 4, backdropFilter: "blur(4px)" }}>
        <Group gap="sm">
          <Group gap={4}>
            <Box style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "var(--mantine-color-red-6)" }} />
            <Text size="10px" c="white" fw={700}>Critical</Text>
          </Group>
          <Group gap={4}>
            <Box style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "var(--mantine-color-orange-6)" }} />
            <Text size="10px" c="white" fw={700}>High</Text>
          </Group>
          <Group gap={4}>
            <Box style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "var(--mantine-color-yellow-6)" }} />
            <Text size="10px" c="white" fw={700}>Medium</Text>
          </Group>
        </Group>
      </Box>

      {geoAnomalies.length === 0 && (
        <Stack align="center" justify="center" h="100%" gap="xs" style={{ position: "relative", zIndex: 1 }}>
          <IconActivity size={40} color="#334155" />
          <Text c="dimmed" size="sm">No geo-tagged anomalies detected</Text>
        </Stack>
      )}
    </Paper>
  );
};

export default AnomalyMap;
