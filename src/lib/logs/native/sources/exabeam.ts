/**
 * Exabeam Advanced Analytics, syslog notifications, native module. No card in docs/log-schemas: the keys
 * are the ones Exabeam documents in the Advanced Analytics Administration Guide (i56), "Syslog
 * Notifications Key-Value Pair Definitions": the pairs are separated by a space (reasons_count="3"
 * score="135"), every value is quoted. Two event types are rendered:
 *   - Notable Sessions / Anomalies ("notable_session"): id (the session id, user + login time, e.g.
 *     "npage-201905151524"), url (the session in the timeline), score, start_time (the session's
 *     loginTime, ISO 8601 with offset), status (open / closed), user, src_host, src_ip, accounts,
 *     assets_count, assets, zones, reasons_count, events_count, alerts_count, and labels / reasons when the
 *     session has them;
 *   - Job Status ("job_status"): job_status (Started / Failed / Completed), job_details, job_id,
 *     created_by, timestamp ("December 19 2018, 11:05PM (UTC)").
 *
 * Record: flat, Exabeam's keys, string values. `rawLine` = the key="value" pairs in the same order.
 * The session's id, url and start_time are printed from the row's own time minus the session's age the
 * authored row states (start_time before the notification), so a re-timed row keeps one session.
 *
 * Input: `ueba` events of the Exabeam vendor, keys under `exabeam.`. Other UEBA products (Microsoft
 * Sentinel UEBA, Purview Insider Risk) are not Exabeam records: null.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";

const SESSION_REQUIRED = ["id", "url", "score", "start_time", "status", "user", "accounts", "assets_count", "assets", "reasons_count", "events_count", "alerts_count"];
const SESSION_OPTIONAL = ["end_time", "src_host", "src_ip", "zones", "labels", "reasons"];
/** Key order of the notification (the guide's table order). */
const SESSION_ORDER = ["id", "url", "score", "start_time", "end_time", "status", "user", "src_host", "src_ip", "accounts", "labels", "assets_count", "assets", "zones", "reasons", "reasons_count", "events_count", "alerts_count"];
const JOB_ORDER = ["job_status", "job_details", "job_id", "created_by", "timestamp"];

const schema: SourceSchema = {
  sourceId: "exabeam", category: "ueba", card: "(none: Exabeam AA Administration Guide i56, Syslog Notifications Key-Value Pair Definitions)", product: "Exabeam Advanced Analytics",
  format: "kv", vendorMatch: ["exabeam"], telemetrySources: ["ueba"],
  kinds: {
    notable_session: { required: SESSION_REQUIRED, optional: SESSION_OPTIONAL } satisfies KindSchema,
    job_status: { required: JOB_ORDER, optional: [] } satisfies KindSchema,
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (typeof record.job_status === "string") return "job_status";
  if (typeof record.score === "string" && typeof record.user === "string") return "notable_session";
  return null;
}

const str = (v: unknown) => (v === undefined || v === null || v === "" ? undefined : String(v));
const p2 = (n: number) => String(n).padStart(2, "0");
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

/** ISO 8601 with the zone's offset, as Exabeam prints loginTime ("2019-05-25T08:05:24-07:00"); UTC here. */
const isoOffset = (ms: number) => `${new Date(ms).toISOString().slice(0, 19)}+00:00`;
/** "May 10 2026, 8:00AM (UTC)" (the guide: "December 19 2018, 11:05PM (UTC)"). */
function jobStamp(ms: number): string {
  const d = new Date(ms);
  const h = d.getUTCHours();
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()} ${d.getUTCFullYear()}, ${h % 12 === 0 ? 12 : h % 12}:${p2(d.getUTCMinutes())}${h < 12 ? "AM" : "PM"} (UTC)`;
}
/** yyyyMMddHHmm of the session's login time, the suffix of an Exabeam session id. */
const sessionSuffix = (ms: number) => new Date(ms).toISOString().slice(0, 16).replace(/[-T:]/g, "");

export const kvLine = (r: Record<string, string>, order: string[]) => order.filter(k => r[k] !== undefined).map(k => `${k}="${r[k].replace(/"/g, "'")}"`).join(" ");

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (!/exabeam/i.test(ev.vendor ?? "")) return null;
  const raw = (ev.raw ?? {}) as Record<string, unknown>;
  const x = (k: string) => str(raw[`exabeam.${k}`]);
  const ms = Date.parse(ev.ts);
  if (!Number.isFinite(ms)) return null;
  if (x("job_status")) {
    const record: Record<string, string> = {
      job_status: x("job_status")!,
      job_details: x("job_details") ?? "",
      job_id: x("job_id") ?? ctx.hex(`exabeam:job:${ev.id}`, 24),
      created_by: x("created_by") ?? "admin",
      timestamp: jobStamp(ms),
    };
    return { sourceId: "exabeam", kind: "job_status", format: "kv", record, rawLine: kvLine(record, JOB_ORDER), timeMs: ms };
  }
  const user = x("user") ?? (ev.user_email ?? ev.user?.email)?.split("@")[0];
  if (!user) return null;
  // The session started before this notification by the gap the authored row states (else a stable 5 to 90 minutes).
  // (The feed re-times the authored start_time with the row, so the gap survives re-timing.)
  const authoredStart = Date.parse(x("start_time") ?? "");
  const gap = Number.isFinite(authoredStart) && ms - authoredStart >= 0 && ms - authoredStart < 24 * 3_600_000
    ? ms - authoredStart : ctx.int(`exabeam:session-age:${ev.id}`, 5, 90) * 60_000;
  const start = Math.floor((ms - gap) / 1000) * 1000;
  const id = `${user}-${sessionSuffix(start)}`;
  const record: Record<string, string> = {
    id,
    url: `https://exabeam-aa.${ctx.domain}:8484/uba/#user/${user}/timeline/${id}`,
    score: x("score") ?? "0",
    start_time: isoOffset(start),
    status: x("status") ?? "open",
    user,
    ...(x("src_host") ?? ev.hostname ? { src_host: x("src_host") ?? ev.hostname! } : {}),
    ...(x("src_ip") ?? ev.src_ip ? { src_ip: x("src_ip") ?? ev.src_ip! } : {}),
    accounts: x("accounts") ?? user,
    ...(x("labels") ? { labels: x("labels")! } : {}),
    assets_count: x("assets_count") ?? "1",
    assets: x("assets") ?? (ev.hostname ?? ""),
    ...(x("zones") ? { zones: x("zones")! } : {}),
    ...(x("reasons") ? { reasons: x("reasons")! } : {}),
    reasons_count: x("reasons_count") ?? "0",
    events_count: x("events_count") ?? "0",
    alerts_count: x("alerts_count") ?? "0",
  };
  return { sourceId: "exabeam", kind: "notable_session", format: "kv", record, rawLine: kvLine(record, SESSION_ORDER), timeMs: ms };
}

const useCases: UseCase[] = [
  {
    id: "exabeam.notable_session", title: "Exabeam notable session (risk score 90 or above)", sourceId: "exabeam", kinds: ["notable_session"],
    severity: "high", mitre: ["T1078"],
    description: "Exabeam marks a session notable when the risk of its triggered rules adds up past the threshold (90 by default). Read the reasons, then open the session timeline from the url and check each anomaly against the user's role.",
    logic: "SPL: index=exabeam score>=90 | table start_time user src_host src_ip score reasons reasons_count url",
    match: { field: "score", op: "gte", value: 90 },
    falsePositives: ["New joiners and role changes, whose behaviour the models have not learned yet"],
  },
  {
    id: "exabeam.session_with_alerts", title: "User session that contains security alerts", sourceId: "exabeam", kinds: ["notable_session"],
    severity: "medium", mitre: ["T1078"],
    description: "alerts_count counts the security-product alerts that landed in the session. A session with alerts and a rising score ties several products' detections to one person.",
    logic: "SPL: index=exabeam alerts_count>0 | table start_time user score alerts_count reasons url",
    match: { field: "alerts_count", op: "gt", value: 0 },
    falsePositives: ["A single blocked phishing link or AV detection that was already cleaned"],
  },
  {
    id: "exabeam.job_failed", title: "Exabeam processing job failed", sourceId: "exabeam", kinds: ["job_status"],
    severity: "low", mitre: [],
    description: "A failed reprocessing or model job means sessions may be scored on stale models. Not an attack on its own: tell the platform owner, and remember the gap when you judge scores from that window.",
    logic: "SPL: index=exabeam job_status=Failed | table timestamp job_id job_details created_by",
    match: { field: "job_status", op: "eq", value: "Failed" },
    falsePositives: ["Planned restarts during maintenance"],
  },
  {
    id: "exabeam.job_by_unexpected_admin", title: "Reprocessing job started by an account other than the platform admin", sourceId: "exabeam", kinds: ["job_status"],
    severity: "low", mitre: ["T1685"],
    description: "A reprocess job rebuilds models and can change rule scores. One started by an account that does not run the platform deserves a question.",
    logic: "SPL: index=exabeam job_status=* created_by!=admin | table timestamp created_by job_status job_details",
    match: { not: { field: "created_by", op: "eq", value: "admin" } },
    falsePositives: ["Named platform administrators who run jobs under their own accounts"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
