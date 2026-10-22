/**
 * Workday: User Activity Logging (the tenant's activity log, REST `activityLogging` /
 * Get_User_Activity), native module. No card in docs/log-schemas yet: the field names are Workday's
 * activity-log columns (requestTime, systemAccount, taskId, taskDisplayName, activityAction, ipAddress,
 * deviceType, userAgent, sessionId, target{descriptor, id, href}) as the Workday REST resource and its
 * connector schemas (Databricks Lakeflow Workday Activity Logging, CData Workday ActivityLogging) list them.
 *
 * One record = one task a Workday account ran: an HR partner initiating a termination, a worker
 * submitting a resignation. The business-process instance it acted on is the `target` (its descriptor
 * names the worker and the effective date, as Workday describes an event instance). Values are strings;
 * requestTime is ISO-8601 UTC with milliseconds.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";

const FIELDS = ["requestTime", "systemAccount", "taskId", "taskDisplayName", "activityAction", "ipAddress", "deviceType", "userAgent", "sessionId", "target", "target.descriptor", "target.id", "target.href"];
const kind: KindSchema = { required: ["requestTime", "systemAccount", "taskId", "taskDisplayName", "activityAction", "target", "target.descriptor", "target.id"], optional: FIELDS };

const schema: SourceSchema = {
  sourceId: "workday", category: "hr", card: "(none: Workday User Activity Logging)", product: "Workday",
  format: "json", vendorMatch: ["workday"], telemetrySources: ["hr"], kinds: { activity: kind },
};

export function kindOf(record: Record<string, unknown>): string | null {
  return typeof record.taskDisplayName === "string" && typeof record.systemAccount === "string" && "requestTime" in record ? "activity" : null;
}

const str = (v: unknown) => (v === undefined || v === null || v === "" ? undefined : String(v));

/** The Workday task a lifecycle event comes from (Workday's own task names). */
function taskOf(eventType: string): { task: string; verb: string } {
  const e = eventType.toLowerCase();
  if (/resign/.test(e)) return { task: "Resign", verb: "Resignation" };
  if (/terminat/.test(e)) return { task: "Terminate Employee", verb: "Termination" };
  if (/hire/.test(e)) return { task: "Hire Employee", verb: "Hire" };
  if (/leave/.test(e)) return { task: "Request Leave of Absence", verb: "Leave of Absence" };
  if (/transfer|job_change|change_job|promot/.test(e)) return { task: "Change Job", verb: "Change Job" };
  if (/contract/.test(e)) return { task: "End Contingent Worker Contract", verb: "End Contract" };
  return { task: eventType.replace(/_/g, " ").replace(/\bworker\b/i, "Worker"), verb: eventType.replace(/_/g, " ") };
}
/** "d.okafor@nexacorp.com" → "D. Okafor" (the worker's display name when the event names only the account). */
const displayOf = (email: string) => email.split("@")[0].split(/[._-]/).filter(Boolean).map((p, i, a) => (p.length === 1 && i < a.length - 1 ? `${p.toUpperCase()}.` : p[0].toUpperCase() + p.slice(1))).join(" ");
const mdY = (d: string) => { const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(d); return m ? `${m[2]}/${m[3]}/${m[1]}` : d; };

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = (ev.raw ?? {}) as Record<string, unknown>;
  const r = (k: string) => str(raw[k]);
  const eventType = r("workday.event_type") ?? r("event.action") ?? ev.event_type;
  const worker = r("workday.worker_email") ?? ev.user_email ?? ev.user?.email;
  const initiator = r("workday.initiated_by") ?? worker;
  if (!worker || !initiator) return null;
  const { task, verb } = taskOf(eventType);
  const effective = r("workday.termination_date") ?? r("workday.effective_date");
  const wid = ctx.hex(`${ctx.companyId}:workday:wid:${(r("workday.worker_id") ?? worker).toLowerCase()}`, 32);
  const instanceId = ctx.hex(`${ev.id}:workday:event`, 32);
  const tenant = ctx.org.toLowerCase();
  const ms = Date.parse(ev.ts);
  const record: Record<string, unknown> = {
    requestTime: new Date(ms).toISOString(),
    systemAccount: initiator.split("@")[0],
    taskId: ctx.hex(`global:workday:task:${task.toLowerCase()}`, 32),
    taskDisplayName: task,
    activityAction: "WRITE",
    ...(ev.src_ip ? { ipAddress: ev.src_ip } : {}),
    deviceType: "Desktop",
    ...(r("user_agent.original") ? { userAgent: r("user_agent.original") } : {}),
    sessionId: ctx.hex(`${ctx.companyId}:workday:session:${initiator.toLowerCase()}:${new Date(ms).toISOString().slice(0, 10)}`, 32),
    target: {
      descriptor: `${verb}: ${displayOf(worker)}${r("workday.worker_id") ? ` (${r("workday.worker_id")})` : ""}${effective ? ` on ${mdY(effective)}` : ""}`,
      id: instanceId,
      href: `https://wd5-services1.myworkday.com/ccx/api/v1/${tenant}/workers/${wid}`,
    },
  };
  return { sourceId: "workday", kind: "activity", format: "json", record, timeMs: ms };
}

const useCases: UseCase[] = [
  {
    id: "workday.departure_initiated", title: "Departure business process started for a worker", sourceId: "workday", kinds: ["activity"],
    severity: "low", mitre: ["T1078"],
    description: "A Resign or Terminate Employee task names a worker who is leaving. Departing staff are the highest-risk window for data theft: put the worker on a watch list and correlate the following days of file, mail, USB and cloud-upload activity with this date.",
    logic: "SPL: index=workday sourcetype=workday:activity taskDisplayName IN (\"Resign\",\"Terminate Employee\") | table requestTime systemAccount target.descriptor",
    match: { field: "taskDisplayName", op: "in", value: ["Resign", "Terminate Employee"] },
    falsePositives: ["Routine leavers: the alert is context for other detections, not an incident on its own"],
  },
  {
    id: "workday.self_service_termination", title: "Worker initiated their own termination", sourceId: "workday", kinds: ["activity"],
    severity: "low", mitre: ["T1078"],
    description: "The account that ran the task is the worker the task is about (a self-service resignation). Combined with bulk downloads in the notice period it is the classic insider exfiltration pattern.",
    logic: "SPL: index=workday taskDisplayName=Resign | table requestTime systemAccount target.descriptor ipAddress",
    match: { field: "taskDisplayName", op: "eq", value: "Resign" },
    falsePositives: ["Every voluntary leaver"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
