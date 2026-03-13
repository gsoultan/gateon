import { Box } from "@mantine/core";

interface SparklineProps {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
}

export function Sparkline({ data, width = 80, height = 24, color = "var(--mantine-color-indigo-5)" }: SparklineProps) {
  if (!data.length) return null;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const points = data
    .map((v, i) => {
      const x = (i / (data.length - 1 || 1)) * (width - 4) + 2;
      const y = height - 4 - ((v - min) / range) * (height - 8) - 2;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <Box component="svg" width={width} height={height} style={{ overflow: "visible" }}>
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        points={points}
      />
    </Box>
  );
}
