/**
 * Microsoft IIS access log (W3C extended format), native source module (text-native).
 *
 * Card: docs/log-schemas/web-iis.md. A log file is a #Fields header plus one space-separated line per
 * request, with a hyphen for an empty field and + for a space inside a value; date and time are UTC.
 * Behind a gateway c-ip is the gateway, so the estate logs the client from X-Forwarded-For as a custom
 * field: an analyst who pivots on c-ip finds only the load balancer.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { balancerIp, isLoopbackClient, machineOf, webFacts } from "./_web-common";

/** The estate's #Fields line. */
export const FIELDS = ["date", "time", "s-sitename", "s-computername", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port", "cs-username", "c-ip", "cs-version",
  "cs(User-Agent)", "cs(Referer)", "cs-host", "sc-status", "sc-substatus", "sc-win32-status", "sc-bytes", "cs-bytes", "time-taken", "X-Forwarded-For"];

const kinds: Record<string, KindSchema> = { w3c: { required: FIELDS, optional: [] } };

const schema: SourceSchema = {
  sourceId: "iis", category: "web_server", card: "web-iis.md", product: "Microsoft IIS", format: "csv",
  vendorMatch: ["iis", "web server"],
  telemetrySources: ["web_server"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  return record["cs-uri-stem"] !== undefined && record["sc-status"] !== undefined ? "w3c" : null;
}

/** W3C line: a hyphen for empty, + for a space inside a value. */
export const rawLineOf = (r: Record<string, unknown>) => FIELDS.map(f => String(r[f] ?? "-").replace(/ /g, "+")).join(" ");

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (ev.source !== "web_server") return null;
  const f = webFacts(ev);
  const t = new Date(ev.ts).toISOString();
  const viaGateway = !isLoopbackClient(f.clientIp);
  const record: Record<string, unknown> = {
    date: t.slice(0, 10),
    time: t.slice(11, 19),
    "s-sitename": "W3SVC1",
    "s-computername": machineOf(ev).toUpperCase(),
    "s-ip": f.serverIp ?? "-",
    "cs-method": f.method,
    "cs-uri-stem": f.path,
    "cs-uri-query": f.query || "-",
    "s-port": f.port,
    // Forms sign-in sets the request's user, so IIS logs it; a cookie-only API logs a hyphen.
    "cs-username": ev.user_email ?? "-",
    "c-ip": viaGateway ? balancerIp(f.serverIp, ctx) : f.clientIp,
    "cs-version": "HTTP/1.1",
    "cs(User-Agent)": f.userAgent,
    "cs(Referer)": f.referer ?? "-",
    "cs-host": f.hostHeader ?? f.site,
    "sc-status": f.status,
    "sc-substatus": 0,
    "sc-win32-status": 0,
    "sc-bytes": f.bytesOut,
    "cs-bytes": f.bytesIn,
    "time-taken": ctx.int(`iis-time:${ev.id}`, 12, 480),
    "X-Forwarded-For": viaGateway ? f.clientIp : "-",
  };
  return { sourceId: "iis", kind: "w3c", format: "csv", record, rawLine: rawLineOf(record), timeMs: Date.parse(ev.ts) };
}

const useCases: UseCase[] = [
  {
    id: "iis.traversal_in_query", title: "Traversal sequence in a query string that answered 200", sourceId: "iis", severity: "high", mitre: ["T1190", "T1083"],
    description: "A file-serving page accepted a path that climbs out of its folder and returned content. The size says which file; compare it with the page's normal response.",
    logic: 'SPL: sourcetype=iis sc_status=200 cs_uri_query IN ("*../*","*..%2f*","*%2e%2e*")',
    match: { all: [{ field: "sc-status", op: "eq", value: 200 }, { field: "cs-uri-query", op: "regex", value: "\\.\\.(/|%2f)|%2e%2e" }] },
    falsePositives: ["An external scanner against a page that answers 200 with an error body: check sc-bytes"],
  },
  {
    id: "iis.script_in_upload_path", title: "Script executed from an upload folder", sourceId: "iis", severity: "high", mitre: ["T1505.003"],
    description: "An .aspx, .ashx or .asmx answered from a folder users write to. Uploaded content should never run.",
    logic: 'sourcetype=iis cs_uri_stem IN ("*/uploads/*.as?x","*/images/*.as?x")',
    match: { field: "cs-uri-stem", op: "regex", value: "/(uploads?|images|media|files)/.*\\.as[hpm]x$" },
    falsePositives: ["None expected: a developer's test page still deserves the question"],
  },
  {
    id: "iis.new_script_external", title: "Unfamiliar .aspx hit from outside by one client", sourceId: "iis", severity: "high", kinds: ["w3c"], mitre: ["T1505.003"],
    description: "A POST to a script whose name imitates a real page, from one external client and with a small response. Web shells look like this: few requests, one address, a name one letter away from the real file.",
    logic: 'sourcetype=iis cs_uri_stem="*2.aspx" X_Forwarded_For!="-"',
    match: { all: [{ field: "cs-uri-stem", op: "regex", value: "[a-z]2\\.aspx$" }, { field: "X-Forwarded-For", op: "neq", value: "-" }] },
    falsePositives: ["A versioned page name in a real application"],
  },
  {
    id: "iis.login_failures", title: "Many failed sign-ins through one page", sourceId: "iis", severity: "medium", mitre: ["T1110.004"],
    description: "Ten or more 401 responses from one client in ten minutes. Pivot on X-Forwarded-For, never on c-ip: behind a gateway c-ip is the gateway.",
    logic: 'sourcetype=iis sc_status=401 | stats count by X_Forwarded_For | where count>=10',
    match: { field: "sc-status", op: "eq", value: 401 },
    threshold: { groupBy: ["X-Forwarded-For"], count: 10, windowSec: 600 },
    falsePositives: ["A mobile client bug retrying expired sessions"],
  },
  {
    id: "iis.large_response", title: "Large response to one request", sourceId: "iis", severity: "medium", mitre: ["T1041"],
    description: "More than 5 MB answered to a single request from outside. Compare with what the page normally returns.",
    logic: 'sourcetype=iis sc_status=200 sc_bytes>5000000 X_Forwarded_For!="-"',
    match: { all: [{ field: "sc-bytes", op: "gt", value: 5_000_000 }, { field: "sc-status", op: "eq", value: 200 }, { field: "X-Forwarded-For", op: "neq", value: "-" }] },
    falsePositives: ["A report or file download page"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
