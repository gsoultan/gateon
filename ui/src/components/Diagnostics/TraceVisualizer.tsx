import React, { useEffect, useState } from "react";
import { Modal, Text, Stack, Group, Paper, Box, ThemeIcon, Timeline, Badge, Loader, Alert } from "@mantine/core";
import { IconMap2, IconMapPin, IconClock, IconWorld, IconAlertCircle } from "@tabler/icons-react";
import { traceRoute } from "../../hooks/api";
import type { TraceHop } from "../../types/gateon";

interface TraceVisualizerProps {
  opened: boolean;
  onClose: () => void;
  targetIp: string;
}

const TraceVisualizer: React.FC<TraceVisualizerProps> = ({ opened, onClose, targetIp }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hops, setHops] = useState<TraceHop[]>([]);

  useEffect(() => {
    if (opened && targetIp) {
      handleTrace();
    }
  }, [opened, targetIp]);

  const handleTrace = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await traceRoute(targetIp);
      setHops(res.hops);
    } catch (err: any) {
      setError(err.message || "Failed to perform traceroute");
    } finally {
      setLoading(false);
    }
  };

  const getPos = (lat: number, lon: number) => {
    const x = ((lon + 180) / 360) * 100;
    const y = ((90 - lat) / 180) * 100;
    return { x: `${x}%`, y: `${y}%`, rawX: ((lon + 180) / 360) * 360, rawY: ((90 - lat) / 180) * 180 };
  };

  const validHops = hops.filter(h => h.latitude !== 0 || h.longitude !== 0);

  return (
    <Modal 
      opened={opened} 
      onClose={onClose} 
      title={
        <Group>
          <IconMap2 size={20} color="var(--mantine-color-blue-6)" />
          <Text fw={700}>Visual Trace: {targetIp}</Text>
        </Group>
      }
      size="xl"
      radius="md"
    >
      <Stack>
        {loading ? (
          <Stack align="center" py={50}>
            <Loader size="xl" variant="dots" />
            <Text c="dimmed">Tracing route across the globe...</Text>
          </Stack>
        ) : error ? (
          <Alert icon={<IconAlertCircle size={16} />} title="Error" color="red">
            {error}
          </Alert>
        ) : (
          <>
            <Paper withBorder radius="md" style={{ height: 350, position: "relative", backgroundColor: "#0f172a", overflow: "hidden" }}>
               {/* Abstract World Map Background */}
              <Box style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, opacity: 0.1, pointerEvents: "none" }}>
                <svg width="100%" height="100%" viewBox="0 0 360 180" preserveAspectRatio="xMidYMid slice">
                  <g fill="#334155" stroke="#1e293b" strokeWidth="0.2">
                    <path d="M50,30 L70,25 L100,30 L115,50 L100,80 L80,85 L50,80 L40,50 Z" />
                    <path d="M90,90 L110,95 L115,120 L100,155 L80,165 L70,140 L80,110 Z" />
                    <path d="M160,25 L190,20 L210,30 L205,55 L170,60 L155,45 Z" />
                    <path d="M155,65 L200,60 L230,85 L220,130 L195,160 L165,150 L145,110 L150,80 Z" />
                    <path d="M210,25 L280,20 L330,30 L350,70 L330,105 L280,115 L225,100 L215,60 Z" />
                    <path d="M300,120 L340,125 L345,150 L310,160 L290,145 Z" />
                  </g>
                </svg>
              </Box>

              <svg width="100%" height="100%" viewBox="0 0 360 180" style={{ position: "absolute", top: 0, left: 0 }}>
                {/* Animated Path */}
                {validHops.length > 1 && (
                  <path
                    d={`M ${validHops.map(h => {
                      const p = getPos(h.latitude, h.longitude);
                      return `${p.rawX} ${p.rawY}`;
                    }).join(" L ")}`}
                    fill="none"
                    stroke="var(--mantine-color-blue-6)"
                    strokeWidth="1"
                    strokeDasharray="1000"
                    strokeDashoffset="1000"
                    style={{
                      animation: "draw 3s ease-in-out forwards",
                      filter: "drop-shadow(0 0 2px var(--mantine-color-blue-6))",
                    }}
                  />
                )}

                {/* Markers */}
                {validHops.map((h, i) => {
                  const p = getPos(h.latitude, h.longitude);
                  const isLast = i === validHops.length - 1;
                  const isFirst = i === 0;
                  return (
                    <g key={i}>
                      <circle 
                        cx={p.rawX} cy={p.rawY} r={isLast || isFirst ? 3 : 1.5} 
                        fill={isLast ? "red" : isFirst ? "green" : "white"} 
                        style={{ opacity: 0, animation: `fadeIn 0.5s ease-out ${i * 0.3}s forwards` }}
                      >
                        {isLast && (
                           <animate attributeName="r" values="3;6;3" dur="2s" repeatCount="indefinite" />
                        )}
                      </circle>
                    </g>
                  );
                })}
              </svg>

              <style dangerouslySetInnerHTML={{ __html: `
                @keyframes draw {
                  to { stroke-dashoffset: 0; }
                }
                @keyframes fadeIn {
                  from { opacity: 0; transform: scale(0); }
                  to { opacity: 1; transform: scale(1); }
                }
              `}} />
            </Paper>

            <Box p="md">
              <Timeline active={hops.length} bulletSize={24} lineWidth={2}>
                {hops.map((h, i) => (
                  <Timeline.Item 
                    key={i} 
                    bullet={i === 0 ? <IconWorld size={12}/> : i === hops.length - 1 ? <IconMapPin size={12}/> : i + 1}
                    title={
                      <Group justify="space-between">
                        <Text size="sm" fw={700}>{h.ip}</Text>
                        <Badge size="xs" variant="light">{h.rtt_ms}ms</Badge>
                      </Group>
                    }
                  >
                    <Text c="dimmed" size="xs">
                      {h.city ? `${h.city}, ` : ""}{h.country_code}
                    </Text>
                  </Timeline.Item>
                ))}
              </Timeline>
            </Box>
          </>
        )}
      </Stack>
    </Modal>
  );
};

export default TraceVisualizer;
