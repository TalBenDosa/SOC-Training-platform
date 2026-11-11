/**
 * A mission console: the investigation console (XDR, our own design) a room's
 * console steps run in. It sits on top of the room's mission dataset (the same
 * tables the KQL steps query) and adds what an analyst works with in the
 * product: incidents with their alerts and entities, the detections that raised
 * them, saved hunts, and incidents colleagues already worked.
 *
 * Everything here is evidence and ships to the browser (served at
 * /api/missions/consoles/<id>); the answer keys live in the mission's steps.
 */
import type { AnalyticsRule, HuntingQuery, IncidentState, SentinelAlert, SentinelEntity, SentinelIncident } from "@/lib/sentinel/types";
import type { MissionTable } from "../types";

export interface MissionConsole {
  id: string;
  /** The mission dataset whose VISIBLE tables the console queries. */
  dataset: string;
  /** Workspace name shown in the console's top bar (fictional). */
  name: string;
  /** Tables the console adds to the dataset: SecurityAlert and SecurityIncident. */
  tables: MissionTable[];
  alerts: SentinelAlert[];
  incidents: SentinelIncident[];
  entities: Record<string, SentinelEntity>;
  rules: AnalyticsRule[];
  hunting: HuntingQuery[];
  /** Incidents someone already worked before the learner arrives (closed, owned). */
  states: Record<string, IncidentState>;
  /** Colleagues an incident can be assigned to (the learner is added as "me"). */
  people: string[];
}
