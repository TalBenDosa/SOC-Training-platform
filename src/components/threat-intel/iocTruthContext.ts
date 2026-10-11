"use client";
import { createContext } from "react";
import type { IocTruth } from "@/lib/edr/iocIntel";

/**
 * The surrounding case's IOC truth table, for every ThreatIntelDrawer below it
 * that wasn't handed one explicitly. The team room provides the server-built
 * table (/api/team/sessions/[id]/ioc-truth): its feed carries no answer key, so
 * without it an attacker's hash or C2 address looked up as clean.
 */
export const IocTruthContext = createContext<IocTruth | null>(null);
