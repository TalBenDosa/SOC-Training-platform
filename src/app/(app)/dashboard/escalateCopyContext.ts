"use client";
import { createContext } from "react";

/**
 * Wording of the detail panel's "flag this log" button. Tier-1 escalates to Tier-2 (the
 * default copy); in a team exercise Tier-2 / Tier-3 open a case on the log themselves.
 */
export interface EscalateCopy { title: string; hint: string }
export const EscalateCopyContext = createContext<EscalateCopy | null>(null);
