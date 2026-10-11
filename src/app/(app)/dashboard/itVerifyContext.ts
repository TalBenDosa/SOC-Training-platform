"use client";
import { createContext } from "react";
import type { ItVerifyAnswer } from "@/lib/sim/itVerify";

/**
 * "Verify with IT" in a team exercise: the log carries no answer key, so the detail panel asks
 * the server (POST /api/team/sessions/[id]/it-verify). Provided by the team page; absent on the
 * single-user dashboard, which answers locally from the full event.
 */
export type TeamItVerifier = (eventId: string) => Promise<ItVerifyAnswer>;
export const ItVerifyContext = createContext<TeamItVerifier | null>(null);
