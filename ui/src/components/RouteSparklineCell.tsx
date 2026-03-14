import { useRouteStatsHistory } from "../hooks/useRouteStatsHistory";
import { Sparkline } from "./Sparkline";

interface RouteSparklineCellProps {
  routeId: string;
}

export function RouteSparklineCell({ routeId }: RouteSparklineCellProps) {
  const reqHistory = useRouteStatsHistory(routeId);

  if (!reqHistory || reqHistory.length < 2) return null;

  return (
    <Sparkline
      data={reqHistory}
      width={56}
      height={24}
      color="var(--mantine-color-indigo-5)"
    />
  );
}
