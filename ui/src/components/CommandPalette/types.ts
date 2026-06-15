import type { ComponentType } from "react";

/** A single actionable entry in the command palette. */
export interface Command {
  /** Stable id used as the React key. */
  id: string;
  /** Human-readable label shown in the list. */
  label: string;
  /** Optional secondary text (e.g. a description or shortcut hint). */
  description?: string;
  /** Group heading the command is shown under. */
  group: string;
  /** Optional leading icon. */
  icon?: ComponentType<{ size?: number; stroke?: number }>;
  /** Extra terms to match against during search. */
  keywords?: string[];
  /** Invoked when the command is selected. */
  perform: () => void;
}
