import type { MantineSpacing, MantineFontSize } from "@mantine/core";
import { usePreferencesStore } from "../store/usePreferencesStore";

/** Mantine `Table` spacing/size props derived from the user's density preference. */
export interface TableDensityProps {
  verticalSpacing: MantineSpacing;
  horizontalSpacing: MantineSpacing;
  fontSize: MantineFontSize;
}

const DENSITY_PROPS: Record<"comfortable" | "compact", TableDensityProps> = {
  comfortable: { verticalSpacing: "sm", horizontalSpacing: "md", fontSize: "sm" },
  compact: { verticalSpacing: "xs", horizontalSpacing: "xs", fontSize: "xs" },
};

/**
 * useTableDensity returns Mantine `Table` props that honor the persisted
 * `tableDensity` preference, so every data table reacts instantly when the
 * user switches between comfortable and compact layouts.
 */
export function useTableDensity(): TableDensityProps {
  const density = usePreferencesStore((state) => state.tableDensity);
  return DENSITY_PROPS[density];
}
