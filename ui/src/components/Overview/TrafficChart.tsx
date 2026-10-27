// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useId } from "react";
import { Box, Text } from "@mantine/core";
import type { Point } from "./trafficSeries";

interface TrafficChartProps {
  requests: Point[];
  errors: Point[];
  height?: number;
  formatValue: (v: number) => string;
  formatTime: (ts: number) => string;
}

const W = 600;
const PAD = { top: 8, right: 8, bottom: 20, left: 44 };

function path(points: Point[], x: (ts: number) => number, y: (v: number) => number, close: boolean): string {
  if (points.length === 0) return "";
  const d = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(p.ts).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ");
  if (!close) return d;
  const first = points[0];
  const last = points[points.length - 1];
  return `${d} L${x(last.ts).toFixed(1)},${y(0).toFixed(1)} L${x(first.ts).toFixed(1)},${y(0).toFixed(1)} Z`;
}

/**
 * Requests and errors per second as two lines in one SVG. It is drawn by hand
 * because the Overview must load before the charting library does; the
 * detailed charts live on Metrics, which pays for that library when opened.
 */
export function TrafficChart({ requests, errors, height = 180, formatValue, formatTime }: TrafficChartProps) {
  const gradientId = useId();
  const all = [...requests, ...errors];
  if (requests.length < 2) {
    return (
      <Box h={height} style={{ display: "grid", placeItems: "center" }}>
        <Text size="sm" c="dimmed">
          {requests.length === 0 ? "No traffic recorded for this range yet." : "Collecting the first samples…"}
        </Text>
      </Box>
    );
  }
  const minTs = Math.min(...all.map((p) => p.ts));
  const maxTs = Math.max(...all.map((p) => p.ts));
  const maxV = Math.max(1e-9, ...all.map((p) => p.value));
  const x = (ts: number) => PAD.left + ((ts - minTs) / Math.max(1, maxTs - minTs)) * (W - PAD.left - PAD.right);
  const y = (v: number) => PAD.top + (1 - v / maxV) * (height - PAD.top - PAD.bottom);
  const ticks = [0, maxV / 2, maxV];
  return (
    <svg viewBox={`0 0 ${W} ${height}`} width="100%" height={height} role="img" aria-label="Requests and errors per second over time">
      <defs>
        <linearGradient id={gradientId} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="var(--mantine-primary-color-filled)" stopOpacity={0.25} />
          <stop offset="100%" stopColor="var(--mantine-primary-color-filled)" stopOpacity={0} />
        </linearGradient>
      </defs>
      {ticks.map((t) => (
        <g key={t}>
          <line x1={PAD.left} x2={W - PAD.right} y1={y(t)} y2={y(t)} stroke="var(--mantine-color-default-border)" strokeDasharray="2 4" />
          <text x={PAD.left - 6} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--mantine-color-dimmed)">
            {formatValue(t)}
          </text>
        </g>
      ))}
      <path d={path(requests, x, y, true)} fill={`url(#${gradientId})`} />
      <path d={path(requests, x, y, false)} fill="none" stroke="var(--mantine-primary-color-filled)" strokeWidth={2} strokeLinejoin="round" />
      {errors.length > 1 && (
        <path d={path(errors, x, y, false)} fill="none" stroke="var(--mantine-color-red-filled)" strokeWidth={1.5} strokeLinejoin="round" />
      )}
      <text x={PAD.left} y={height - 4} fontSize={11} fill="var(--mantine-color-dimmed)">
        {formatTime(minTs)}
      </text>
      <text x={W - PAD.right} y={height - 4} textAnchor="end" fontSize={11} fill="var(--mantine-color-dimmed)">
        {formatTime(maxTs)}
      </text>
    </svg>
  );
}
