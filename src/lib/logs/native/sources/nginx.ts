/**
 * nginx access log, native source module (text-native).
 *
 * Card: docs/log-schemas/web-nginx.md. The combined format, plus the nginx variables the estate's
 * log_format adds so a line names its server and its sizes. $time_local is the server's local time.
 * Behind a load balancer $remote_addr is the balancer and the client is in $http_x_forwarded_for:
 * an analyst who pivots on the first column finds only the load balancer.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { balancerIp, isPrivateClient, machineOf, webFacts } from "./_web-common";

const FIELDS = ["remote_addr", "remote_user", "time_local", "request", "status", "body_bytes_sent", "http_referer", "http_user_agent",
  "http_x_forwarded_for", "hostname", "server_addr", "host", "request_length", "request_time"];

const kinds: Record<string, KindSchema> = { access: { required: FIELDS, optional: [] } };

const schema: SourceSchema = {
  sourceId: "nginx", category: "web_server", card: "web-nginx.md", product: "nginx", format: "csv",
  vendorMatch: ["nginx", "web server"],
  telemetrySources: ["web_server"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  return record.remote_addr !== undefined && record.request !== undefined ? "access" : null;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** $time_local: 17/Mar/2026:09:14:02 +0100, in the server's zone. */
export function timeLocal(iso: string, timeZone: string): string {
  const d = new Date(iso);
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-GB", { timeZone, year: "numeric", month: "numeric", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZoneName: "longOffset" })
    .formatToParts(d).map(p => [p.type, p.value]));
  const m = /GMT([+-])(\d{2}):(\d{2})/.exec(parts.timeZoneName ?? "");
  const off = m ? `${m[1]}${m[2]}${m[3]}` : "+0000";
  return `${parts.day}/${MONTHS[Number(parts.month) - 1]}/${parts.year}:${parts.hour}:${parts.minute}:${parts.second} ${off}`;
}

/** The estate's log_format, on the wire. */
export const rawLineOf = (r: Record<string, unknown>) =>
  `${r.remote_addr} - ${r.remote_user} [${r.time_local}] "${r.request}" ${r.status} ${r.body_bytes_sent} "${r.http_referer}" "${r.http_user_agent}" "${r.http_x_forwarded_for}" ${r.hostname} ${r.server_addr} ${r.host} ${r.request_length} ${r.request_time}`;

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (ev.source !== "web_server") return null;
  const f = webFacts(ev);
  const viaBalancer = !isPrivateClient(f.clientIp);
  const uri = f.query ? `${f.path}?${f.query}` : f.path;
  const record: Record<string, unknown> = {
    remote_addr: viaBalancer ? balancerIp(f.serverIp, ctx) : f.clientIp,
    remote_user: "-",
    time_local: timeLocal(ev.ts, ctx.timeZone),
    request: `${f.method} ${uri} HTTP/1.1`,
    status: String(f.status),
    body_bytes_sent: String(f.bytesOut),
    http_referer: f.referer ?? "-",
    http_user_agent: f.userAgent,
    http_x_forwarded_for: viaBalancer ? f.clientIp : "-",
    hostname: machineOf(ev),
    server_addr: f.serverIp ?? "-",
    host: f.hostHeader ?? f.site,
    request_length: String(f.bytesIn),
    request_time: (ctx.int(`nginx-time:${ev.id}`, 8, 620) / 1000).toFixed(3),
  };
  return { sourceId: "nginx", kind: "access", format: "csv", record, rawLine: rawLineOf(record), timeMs: Date.parse(ev.ts) };
}

const useCases: UseCase[] = [
  {
    id: "nginx.traversal_in_request", title: "Traversal sequence in a request that answered 200", sourceId: "nginx", severity: "high", mitre: ["T1190", "T1083"],
    description: "A file-serving page accepted a path that climbs out of its folder and returned content. body_bytes_sent says which file; compare it with the page's normal response.",
    logic: 'SPL: sourcetype=nginx:access status=200 | regex request="\\.\\.(/|%2[fF])|%2[eE]%2[eE]"',
    match: { all: [{ field: "status", op: "eq", value: "200" }, { field: "request", op: "regex", value: "\\.\\.(/|%2[fF])|%2[eE]%2[eE]" }] },
    falsePositives: ["An external scanner against a page that answers 200 with an error body: check body_bytes_sent"],
  },
  {
    id: "nginx.script_in_upload_path", title: "Script executed from an upload folder", sourceId: "nginx", severity: "high", mitre: ["T1505.003"],
    description: "A .php or .jsp answered from a folder users write to. Uploaded content should never run: pivot to the host and look for children of the PHP worker.",
    logic: 'sourcetype=nginx:access request="*/uploads/*.php*"',
    match: { field: "request", op: "regex", value: "/(uploads?|avatars|media|files)/\\S*\\.(php\\d?|phtml|jsp)(\\?|\\s)" },
    falsePositives: ["None expected: a developer's test page still deserves the question"],
  },
  {
    id: "nginx.login_failures", title: "Many failed sign-ins from one client", sourceId: "nginx", severity: "medium", mitre: ["T1110.004"],
    description: "Ten or more 401 responses from one client in ten minutes. Group on http_x_forwarded_for: behind a balancer remote_addr is the balancer.",
    logic: 'sourcetype=nginx:access status=401 | stats count by http_x_forwarded_for | where count>=10',
    match: { field: "status", op: "eq", value: "401" },
    threshold: { groupBy: ["http_x_forwarded_for"], count: 10, windowSec: 600 },
    falsePositives: ["A mobile client bug retrying expired sessions"],
  },
  {
    id: "nginx.object_walk", title: "One client walking an object API", sourceId: "nginx", severity: "high", mitre: ["T1190", "T1119"],
    description: "One client read four or more different numbered objects of an API within ten minutes, all answered 200. A normal customer reads their own record: check whether the numbers are consecutive.",
    logic: 'sourcetype=nginx:access status=200 request="GET /api/*" | rex field=request "/(?<id>\\d+)/" | stats dc(id) by http_x_forwarded_for | where dc(id)>=4',
    match: { all: [{ field: "status", op: "eq", value: "200" }, { field: "request", op: "regex", value: "^GET /api/\\S*/\\d+/" }] },
    threshold: { groupBy: ["http_x_forwarded_for"], count: 4, windowSec: 600, distinct: "request" },
    falsePositives: ["A partner's batch integration on its own key"],
  },
  {
    id: "nginx.large_response", title: "Large response to one request", sourceId: "nginx", severity: "medium", mitre: ["T1041"],
    description: "More than 5 MB answered to a single request. Compare with what the page normally returns.",
    logic: 'sourcetype=nginx:access status=200 body_bytes_sent>5000000',
    match: { all: [{ field: "body_bytes_sent", op: "gt", value: 5_000_000 }, { field: "status", op: "eq", value: "200" }] },
    falsePositives: ["A report or file download page"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
