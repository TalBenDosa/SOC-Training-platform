"use client";
import { createContext } from "react";
import type { TelemetryEvent } from "@/lib/sim/types";

/**
 * "Investigate this host in EDR" from a log's detail panel. Provided by the team exercise
 * (which knows which hosts have endpoint telemetry and how to open the EDR console with the
 * team's own logs); absent on the single-user dashboard, which has its own header button.
 */
export interface EdrPivot {
  /** The EDR console has endpoint telemetry for this log's host. */
  canOpen: (ev: TelemetryEvent) => boolean;
  open: (ev: TelemetryEvent) => void;
}
export const EdrPivotContext = createContext<EdrPivot | null>(null);
