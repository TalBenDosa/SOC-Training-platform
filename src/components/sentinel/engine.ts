// The one place the console touches the KQL engine and the insight queries. Everything else codes
// against these wrappers, so the engine's signatures matter in this file only.
import { formatKqlValue, kqlCompletions, kqlSetsTimeRange, runKql, tokenizeKql } from "@/lib/kql";
import type { KqlCompletion, KqlResult, KqlTable, KqlType } from "@/lib/kql/types";
import { entityInsights, incidentInsights } from "@/lib/sentinel/insights";
import type { EntityInsight, SentinelEntity, SentinelIncident, SentinelWorkspace } from "@/lib/sentinel/types";

export interface TimeRange { from: Date; to: Date }

export function runQuery(query: string, tables: Record<string, KqlTable>, now: string, timeRange?: TimeRange): KqlResult {
  return runKql(query, { tables, now: new Date(now), timeRange });
}

export const setsTimeRange = kqlSetsTimeRange;

let schemaTables: Record<string, KqlTable> = {};
let clock = new Date(0);
/** What autocomplete and colouring know about: set by the console when the workspace changes. */
export function setCompletionTables(tables: Record<string, KqlTable>, now: string) { schemaTables = tables; clock = new Date(now); }

export function completions(text: string, cursor: number): KqlCompletion[] {
  return kqlCompletions(text, cursor, { tables: schemaTables, now: clock });
}

export interface Segment { text: string; kind?: string }

/** Contiguous segments that add up to the text. */
export function tokenize(text: string): Segment[] {
  return tokenizeKql(text, { tables: schemaTables }).map(t => ({ text: t.text, kind: t.class === "other" ? undefined : t.class }));
}

export function fmtValue(v: unknown, type: KqlType): string {
  return formatKqlValue(v, type);
}

export function insightsForIncident(incident: SentinelIncident, ws: SentinelWorkspace): EntityInsight[] {
  return incidentInsights(ws, incident);
}
export function insightsForEntity(entity: SentinelEntity, ws: SentinelWorkspace): EntityInsight[] {
  return entityInsights(ws, entity.id);
}
