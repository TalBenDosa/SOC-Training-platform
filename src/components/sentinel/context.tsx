"use client";
import { createContext, useContext } from "react";
import type { KqlTable } from "@/lib/kql/types";
import type {
  IncidentState, SentinelActions, SentinelBookmark, SentinelEntity, SentinelWorkspace,
} from "@/lib/sentinel/types";

export type Screen = "overview" | "logs" | "search" | "incidents" | "hunting" | "entity" | "ti" | "analytics" | "automation";

export interface LogsRequest {
  query: string;
  /** Run as soon as it opens, which is what every investigation link does. */
  run?: boolean;
  /** Bookmarks made from this query go to this incident. */
  incidentId?: string;
}
export interface PlaybookRequest { incidentId?: string; host?: string }
export interface PlaybookRun {
  id: string; at: string; playbook: string; host: string; ok: boolean; message: string; by: string;
  /** "Isolate device" in a team session sends a request for approval: the run stays pending until it is answered. */
  pending?: boolean;
}

export interface SentinelCtx {
  ws: SentinelWorkspace;
  states: Map<string, IncidentState>;
  actions: SentinelActions;
  ended: boolean;
  /** The workspace tables plus HuntingBookmark, which the team's event log feeds. */
  tables: Record<string, KqlTable>;
  bookmarks: SentinelBookmark[];
  /** Incidents that arrived during this visit and have not been opened yet. */
  fresh: Set<string>;
  runs: PlaybookRun[];
  stateOf: (incidentId: string) => IncidentState;
  /** Shows a server refusal. Null is a success and shows nothing. */
  report: (err: string | null) => void;
  openIncident: (id: string, opts?: { entityId?: string }) => void;
  openInvestigation: (id: string) => void;
  openLogs: (req: LogsRequest) => void;
  openPlaybook: (req: PlaybookRequest) => void;
  openEntity: (id: string) => void;
  go: (screen: Screen) => void;
  addToTi: (entity: SentinelEntity, incidentId: string) => void;
  /** The team event log folds bookmarks per incident, so one without an incident is kept here. */
  saveBookmark: SentinelActions["addBookmark"];
  /** `reason` goes with an isolation request to the approver (team sessions). */
  runPlaybook: (playbook: "Isolate device" | "Release device", host: string, incidentTitle?: string, reason?: string) => Promise<PlaybookRun>;
  refresh: () => void;
}

const Ctx = createContext<SentinelCtx | null>(null);
export const SentinelProvider = Ctx.Provider;
export function useSentinel(): SentinelCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useSentinel outside SentinelConsole");
  return c;
}
