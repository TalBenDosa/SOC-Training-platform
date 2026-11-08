/**
 * The team's shared work on an incident, folded from the session's event log. Nothing about an
 * incident's handling lives in the workspace itself: every member folds the same events, so everyone
 * sees the same status, owner, comments, bookmarks and tasks.
 */
import { handoffText } from "@/lib/team/handoff";
import type { ClosingClassification, IncidentState, IncidentStatus, SentinelBookmark, SentinelIncident, SentinelSeverity } from "./types";
import { XDR_ACTOR } from "./xdrBrand";

export interface IncidentLogEvent { type: string; actor_name?: string; payload: unknown; occurred_at: string }

/** The triage list a new incident starts with. */
export const DEFAULT_TASKS = [
  "Review the alerts and the evidence",
  "Identify the affected accounts and hosts",
  "Check related activity in Logs",
  "Decide on containment",
  "Document the findings and classify the incident",
];

type Patch = Partial<Pick<IncidentState, "status" | "owner" | "severity" | "classification" | "closingComment">>;

const taskId = (title: string) => title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

const SYSTEM_ACTOR = XDR_ACTOR;

/** Fold the log, oldest first, whatever order it arrives in. Events about other incidents are ignored. */
export function foldIncidentState(events: IncidentLogEvent[], incident: SentinelIncident): IncidentState {
  const state: IncidentState = {
    status: "New", owner: null, severity: incident.severity, comments: [], bookmarks: [],
    tasks: DEFAULT_TASKS.map(title => ({ id: taskId(title), title, done: false })),
    activity: [{ at: incident.created, actor: SYSTEM_ACTOR, text: "Incident created" }],
  };
  // An escalated incident opens with the analyst's report as its first comment (owner, 2026-11-08),
  // written by the analyst who escalated, so the activity log reads like a real hand-off.
  (incident.handoffs ?? []).forEach((h, i) => {
    const at = h.at ?? incident.created;
    state.comments.push({ id: `handoff-${i}`, author: h.from, text: handoffText(h), at });
    // The card adds "by <actor>": the text names only the seat, so the name shows once (2026-11-08 review).
    state.activity.push({ at, actor: h.from, text: h.kind === "self_opened" ? `Case opened (${h.fromRole})` : `Escalated (${h.fromRole})` });
  });
  const ordered = events.map((e, i) => ({ e, i })).sort((a, b) => Date.parse(a.e.occurred_at) - Date.parse(b.e.occurred_at) || a.i - b.i).map(x => x.e);
  ordered.forEach((ev, i) => {
    const actor = ev.actor_name ?? "Unknown";
    const at = ev.occurred_at;
    const log = (text: string) => state.activity.push({ at, actor, text });
    const p = (ev.payload ?? {}) as Record<string, unknown>;
    if (ev.type === "sentinel.bookmark_added") {
      const b = p as unknown as Partial<SentinelBookmark>;
      if (b.incidentId !== incident.id) return;
      state.bookmarks.push({
        id: b.id ?? `bookmark-${i}`, name: b.name ?? "Bookmark", query: b.query ?? "", columns: b.columns ?? [], rows: b.rows ?? [], notes: b.notes ?? "",
        author: b.author ?? actor, at: b.at ?? at, incidentId: b.incidentId, entityIds: b.entityIds ?? [],
      });
      log(`Bookmark "${b.name ?? "Bookmark"}" added`);
      return;
    }
    if (p.incident_id !== incident.id) return;
    if (ev.type === "sentinel.incident_updated") {
      const patch = (p.patch ?? {}) as Patch;
      if (patch.status !== undefined && patch.status !== state.status) {
        log(`Status changed from ${state.status} to ${patch.status}`);
        state.status = patch.status as IncidentStatus;
      }
      if (patch.owner !== undefined && patch.owner !== state.owner) {
        log(patch.owner ? `Incident assigned to ${patch.owner}` : "Incident unassigned");
        state.owner = patch.owner;
      }
      if (patch.severity !== undefined && patch.severity !== state.severity) {
        log(`Severity changed from ${state.severity} to ${patch.severity}`);
        state.severity = patch.severity as SentinelSeverity;
      }
      if (patch.classification !== undefined && patch.classification !== state.classification) {
        log(`Classification set to ${patch.classification}`);
        state.classification = patch.classification as ClosingClassification;
      }
      if (patch.closingComment !== undefined) state.closingComment = patch.closingComment;
      return;
    }
    if (ev.type === "sentinel.comment_added") {
      const text = typeof p.text === "string" ? p.text : "";
      if (!text) return;
      state.comments.push({ id: `comment-${i}`, author: actor, text, at });
      log("Comment added");
      return;
    }
    if (ev.type === "sentinel.task_set") {
      const title = typeof p.title === "string" ? p.title : "";
      if (!title) return;
      const done = !!p.done;
      const task = state.tasks.find(t => t.title === title);
      if (!task) state.tasks.push({ id: taskId(title), title, done, ...(done ? { by: actor } : {}) });
      else { task.done = done; if (done) task.by = actor; else delete task.by; }
      log(`Task "${title}" ${done ? "completed" : "reopened"}`);
    }
  });
  return state;
}
