import type { KqlTable } from "@/lib/kql/types";

export type SentinelSeverity = "High" | "Medium" | "Low" | "Informational";
export type IncidentStatus = "New" | "Active" | "Closed";
export type ClosingClassification =
  | "True Positive - suspicious activity"
  | "Benign Positive - suspicious but expected"
  | "False Positive - incorrect alert logic"
  | "False Positive - incorrect data"
  | "Undetermined";

export type EntityKind = "account" | "host" | "ip" | "file" | "process" | "url" | "domain" | "mailbox" | "cloudapp" | "azureresource" | "registry";

export interface SentinelEntity {
  /** Stable within a workspace: `${kind}:${lower-cased name}`. */
  id: string;
  kind: EntityKind;
  /** Display name. */
  name: string;
  /** Identifying facts for the Info card, label to value. */
  info: Record<string, string>;
}

export interface SentinelAlert {
  /** SystemAlertId of the SecurityAlert row. */
  id: string;
  name: string;
  severity: SentinelSeverity;
  /** Provider, as in the ProviderName / ProductName columns. */
  product: string;
  description: string;
  time: string;
  tactics: string[];
  techniques: string[];
  entityIds: string[];
  /** The analytics rule that raised it, when one did. */
  ruleId?: string;
  /** KQL that returns the events behind this alert. Opens in the Logs panel. */
  query: string;
}

export interface SentinelIncident {
  /** Incident number shown in the grid. Stable across rebuilds of one session. */
  number: number;
  /** Stable key, used by every team event about this incident. */
  id: string;
  title: string;
  severity: SentinelSeverity;
  created: string;
  lastUpdate: string;
  alertIds: string[];
  entityIds: string[];
  tactics: string[];
  techniques: string[];
  products: string[];
  description: string;
  /** Events behind the incident, for the Evidence tile. */
  eventCount: number;
  /** KQL that lists those events. */
  eventsQuery: string;
}

export interface AnalyticsRule {
  id: string;
  name: string;
  severity: SentinelSeverity;
  tactics: string[];
  techniques: string[];
  description: string;
  /** The rule's real KQL. Must run in the engine. */
  query: string;
  frequency: string;
  lookback: string;
  dataSources: string[];
  falsePositives: string[];
}

export interface HuntingQuery { id: string; name: string; description: string; tactics: string[]; techniques: string[]; dataSources: string[]; query: string }

export interface EntityInsight {
  title: string;
  description: string;
  /** KQL behind the insight. */
  query: string;
  /** Rows shown in the card. */
  preview: { columns: string[]; rows: string[][] };
}

export interface SentinelWorkspace {
  /** Fictional, derived from the company: `${org}-sentinel-prod`. */
  name: string;
  tables: Record<string, KqlTable>;
  alerts: SentinelAlert[];
  incidents: SentinelIncident[];
  entities: Record<string, SentinelEntity>;
  rules: AnalyticsRule[];
  hunting: HuntingQuery[];
  /** The clock now() uses: the time of the newest released event. */
  now: string;
}

/** What people did in the console. Folded from the team event log, shared by the whole team. */
export interface IncidentState {
  status: IncidentStatus;
  owner: string | null;
  severity: SentinelSeverity;
  classification?: ClosingClassification;
  closingComment?: string;
  comments: { id: string; author: string; text: string; at: string }[];
  bookmarks: SentinelBookmark[];
  tasks: { id: string; title: string; done: boolean; by?: string }[];
  activity: { at: string; actor: string; text: string }[];
}

export interface SentinelBookmark {
  id: string;
  name: string;
  query: string;
  /** The saved rows, capped. */
  columns: string[];
  rows: Record<string, string>[];
  notes: string;
  author: string;
  at: string;
  incidentId?: string;
  entityIds: string[];
}

/** The console's outward actions. The team room gives a real implementation; tests give a fake. */
export interface SentinelActions {
  /** Display name of the viewer and of everyone who can own an incident. */
  me: { id: string; name: string; role: string | null };
  people: string[];
  /** Isolation is a Tier-2 / Tier-3 action, enforced by the database gate. */
  canContain: boolean;
  isolatedHosts: Set<string>;
  setIsolated: (host: string, isolated: boolean, incidentTitle?: string) => Promise<string | null>;
  updateIncident: (incidentId: string, patch: Partial<Pick<IncidentState, "status" | "owner" | "severity" | "classification" | "closingComment">>) => Promise<string | null>;
  addComment: (incidentId: string, text: string) => Promise<string | null>;
  addBookmark: (b: Omit<SentinelBookmark, "id" | "author" | "at">) => Promise<string | null>;
  setTask: (incidentId: string, title: string, done: boolean) => Promise<string | null>;
  /** Telemetry for the after-action report. Never blocks the UI. */
  queryRan: (q: { query: string; ok: boolean; rows: number; incidentId?: string }) => void;
}
