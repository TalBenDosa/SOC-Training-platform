// A rule must run in the engine and match the same rows as its use case. Two checks:
//  1. Feeds: over real team feeds under several stacks, the rule's row filter returns exactly the rows
//     of the records the use case matches, and a threshold rule fires where the use case fires.
//  2. Positives: for every rule, a record built to satisfy the use case is returned by the rule, so a
//     use case the feeds never trigger is still checked.
import { describe, expect, it } from "vitest";
import { nativeView, NATIVE_SOURCES, stackFor, type Stack } from "@/lib/logs/native";
import { matches, runUseCase } from "@/lib/logs/native/engine";
import type { Condition, NativeLog, UseCase } from "@/lib/logs/native/types";
import { runKql } from "@/lib/kql";
import type { KqlRow, KqlTable } from "@/lib/kql/types";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import type { TelemetryEvent } from "@/lib/sim/types";
import { mapRow, specFor } from "./mapRow";
import { NOISE_RULES } from "./noise";
import { compileUseCase, stackUseCases } from "./rules";
import { emptyTable, TABLE_NAMES } from "./tables";

const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
const NOW = new Date("2026-01-02T00:00:00Z");
const CASES: [string, Stack][] = [
  ["nexacorp", {}], ["medcore", {}], ["rocketstack", {}], ["globallogis", {}], ["quantumbank", {}],
  ["medcore", { edr: "crowdstrike", firewall: "fortigate", vpn: "globalprotect" }],
  ["rocketstack", { edr: "mde", firewall: "paloalto", collab: "m365", idp: "entra" }],
  ["globallogis", { firewall: "cisco_asa", email_security: "proofpoint", dns: "infoblox" }],
  ["nexacorp", { firewall: "checkpoint", idp: "okta", vpn: "fortigate_sslvpn" }],
];

interface Corpus { logs: NativeLog[]; tables: Record<string, KqlTable>; rowOf: Map<NativeLog, KqlRow>; cloud?: Stack["cloud"] }

function corpus(company: string, stack: Stack): Corpus {
  const eff = stackFor(company, stack);
  const logs: NativeLog[] = [];
  const tables: Record<string, KqlTable> = Object.fromEntries(TABLE_NAMES.map(n => [n, { ...emptyTable(n), rows: [] }]));
  const rowOf = new Map<NativeLog, KqlRow>();
  for (const diff of ["easy", "medium", "hard"] as const) for (const s of [1, 2, 3]) {
    const tl = buildTeamTimeline(company, diff, `rules-${company}-${s}`, null, teamLoad(diff, roster), stack);
    for (const t of tl) {
      if (t.channel !== "feed") continue;
      const v = nativeView(t.body as unknown as TelemetryEvent, company, stack);
      if (!v) continue;
      const m = mapRow(v.log, { tenantId: "00000000-0000-4000-8000-000000000000", cloud: eff.cloud });
      if (!m) continue;
      logs.push(v.log);
      rowOf.set(v.log, m.row);
      tables[m.table].rows.push(m.row);
    }
  }
  return { logs, tables, rowOf, cloud: eff.cloud };
}

const inKinds = (uc: UseCase, l: NativeLog) => l.sourceId === uc.sourceId && (!uc.kinds || uc.kinds.includes(l.kind));

// Building records that satisfy a use case ────────────────────────────────────

function setPath(rec: Record<string, unknown>, path: string, value: unknown): void {
  if (path in rec || !/[.[]/.test(path)) { rec[path] = value; return; }
  const parts = path.split(".");
  let cur: Record<string, unknown> = rec;
  parts.forEach((p, i) => {
    const arr = p.endsWith("[]");
    const key = arr ? p.slice(0, -2) : p;
    const last = i === parts.length - 1;
    if (last) {
      if (arr) cur[key] = [...(Array.isArray(cur[key]) ? cur[key] as unknown[] : []), value];
      else cur[key] = value;
      return;
    }
    if (arr) {
      const list = (Array.isArray(cur[key]) ? cur[key] : []) as Record<string, unknown>[];
      if (!list.length) list.push({});
      cur[key] = list;
      cur = list[0];
    } else {
      if (typeof cur[key] !== "object" || cur[key] === null) cur[key] = {};
      cur = cur[key] as Record<string, unknown>;
    }
  });
}

/** A string a simple pattern matches: the first branch, literals kept, classes reduced to one character. */
function sampleRegex(src: string): string {
  let s = src.replace(/^\(\?[a-z]+\)/, "").replace(/\\b|\^|\$/g, "");
  for (let i = 0; i < 6; i++) s = s.replace(/\(\?:([^()|]*)(\|[^()]*)?\)\??/g, "$1").replace(/\(([^()|]*)(\|[^()]*)?\)\??/g, "$1");
  s = s.split("|")[0];
  return s.replace(/\[([^\]^])[^\]]*\](\{\d+,?\d*\}|[+*?])?/g, "$1").replace(/\\d(\{\d+,?\d*\}|[+*?])?/g, "1").replace(/\\s(\{\d+,?\d*\}|[+*?])?/g, " ")
    .replace(/\\w(\{\d+,?\d*\}|[+*?])?/g, "a").replace(/\.(\{\d+,?\d*\}|[+*?])?/g, "x").replace(/\\(.)/g, "$1").replace(/[+*?]/g, "");
}

function satisfy(c: Condition, rec: Record<string, unknown>): void {
  if ("all" in c) { c.all.forEach(x => satisfy(x, rec)); return; }
  if ("any" in c) { satisfy(c.any[0], rec); return; }
  if ("not" in c) return;
  const v = c.value;
  switch (c.op) {
    case "eq": case "contains": case "icontains": case "startsWith": case "endsWith": setPath(rec, c.field, v); break;
    case "in": setPath(rec, c.field, (v as unknown[])[0]); break;
    case "regex": setPath(rec, c.field, sampleRegex(String(v))); break;
    case "exists": setPath(rec, c.field, "value"); break;
    case "gt": case "gte": setPath(rec, c.field, Number(v) + 1); break;
    case "lt": case "lte": setPath(rec, c.field, Number(v) - 1); break;
    case "neq": case "nin": setPath(rec, c.field, "zzz-other"); break;
    case "notCidr": setPath(rec, c.field, "203.0.113.7"); break;
    case "cidr": setPath(rec, c.field, String((Array.isArray(v) ? v[0] : v)).split("/")[0]); break;
    default: break;
  }
}

describe("analytics rules against their use cases", () => {
  const mismatches: string[] = [];
  let checked = 0, withHits = 0;
  const fired = new Set<string>();

  for (const [company, stack] of CASES) {
    it(`${company} ${JSON.stringify(stack)}: the same rows`, () => {
      const c = corpus(company, stack);
      const env = { tables: c.tables, now: NOW };
      for (const { uc, compiled } of stackUseCases(company, stack)) {
        const candidates = c.logs.filter(l => inKinds(uc, l));
        const expected = candidates.filter(l => matches(l.record, uc.match));
        const got: KqlRow[] = [];
        for (const b of compiled.bases) {
          const r = runKql(b.query, env);
          if (!r.ok) { mismatches.push(`${uc.id}: ${r.error.message}`); continue; }
          got.push(...r.rows);
        }
        checked++;
        if (expected.length) { withHits++; fired.add(uc.id); }
        const key = (r: KqlRow) => (r.TimeGenerated instanceof Date ? r.TimeGenerated.toISOString() : String(r.TimeGenerated));
        const want = expected.map(l => key(c.rowOf.get(l)!)).sort();
        // Another source's rows in a shared table (AuditLogs) are the same activity, but not this use case's records.
        const own = new Set(c.logs.filter(l => l.sourceId === uc.sourceId).map(l => key(c.rowOf.get(l)!)));
        const have = got.map(key).filter(k => own.has(k)).sort();
        if (want.join() !== have.join()) mismatches.push(`${uc.id}: want ${want.length} rows, got ${have.length}`);
        if (uc.threshold) for (const hit of runUseCase(uc, c.logs)) {
          // The scheduler runs the rule over its lookback: the window that ends at the firing row.
          const end = Math.max(...hit.records.map(i => c.logs[i].timeMs));
          const window = { from: new Date(end - uc.threshold.windowSec * 1000), to: new Date(end + 1) };
          const run = runKql(compiled.query, { ...env, timeRange: window });
          if (!run.ok || run.rows.length === 0) mismatches.push(`${uc.id}: threshold did not fire ${run.ok ? "" : run.error.message}`);
        }
      }
      expect(mismatches.slice(0, 30)).toEqual([]);
    }, 120_000);
  }

  it("every compilable rule returns a record built to satisfy it", () => {
    const problems: string[] = [];
    let built = 0, skipped = 0;
    const all = Object.values(NATIVE_SOURCES).flatMap(s => s?.useCases ?? []);
    for (const uc of all) {
      const cloud = uc.sourceId === "k8s_audit" ? "azure_activity" as const : undefined;
      const compiled = compileUseCase(uc, cloud);
      if (!compiled) continue;
      for (const b of compiled.bases) {
        const kinds = (uc.kinds ?? Object.keys(NATIVE_SOURCES[uc.sourceId]!.schema.kinds)).filter(k => specFor(uc.sourceId, k, cloud) === b.spec);
        const kind = kinds[0];
        const rec: Record<string, unknown> = { ...KIND_FIELDS[uc.sourceId]?.(kind) };
        satisfy(uc.match, rec);
        if (!matches(rec, uc.match)) { skipped++; continue; }
        if (!kind) { skipped++; continue; }
        const log: NativeLog = { sourceId: uc.sourceId, kind, format: "json", record: rec, timeMs: Date.parse("2026-01-01T10:00:00Z"), rawLine: rawLineOf(uc, rec, kind) };
        const m = mapRow(log, { tenantId: "t", cloud });
        if (!m) { problems.push(`${uc.id}: no row`); continue; }
        const r = runKql(b.query, { tables: { [m.table]: { ...emptyTable(m.table), rows: [m.row] } }, now: NOW });
        built++;
        if (!r.ok) problems.push(`${uc.id}: ${r.error.message}`);
        else if (r.rows.length !== 1) problems.push(`${uc.id} on ${m.table}: returned ${r.rows.length}\n${b.query}`);
      }
    }
    console.log(`[rules] positives built ${built}, skipped ${skipped}, problems ${problems.length}`);
    expect(problems.slice(0, 40)).toEqual([]);
    expect(built).toBeGreaterThan(150);
  });

  it("noise rules: KQL and row test agree", () => {
    const problems: string[] = [];
    for (const [company, stack] of CASES.slice(0, 5)) {
      const c = corpus(company, stack);
      const env = { tables: c.tables, now: NOW };
      for (const rule of NOISE_RULES) for (const p of rule.parts) {
        const rows = c.tables[p.table].rows;
        const expected = rows.filter(p.test).length;
        const r = runKql(`${p.table}\n| where ${p.where}`, env);
        if (!r.ok) { problems.push(`${rule.id}/${p.table}: ${r.error.message}`); continue; }
        if (r.rows.length !== expected) problems.push(`${rule.id}/${p.table}: test ${expected}, KQL ${r.rows.length}`);
      }
    }
    expect(problems).toEqual([]);
  }, 120_000);

  it("reports coverage", () => {
    console.log(`[rules] checked ${checked} rule runs, ${withHits} with hits, ${fired.size} distinct rules fired`);
    expect(fired.size).toBeGreaterThan(30);
  });
});

/** The record fields that say which kind a record is. */
const KIND_FIELDS: Record<string, (kind: string) => Record<string, unknown>> = {
  fortigate: k => ({ type: k.split("/")[0], subtype: k.split("/")[1] }),
  fortigate_sslvpn: k => ({ logid: k, type: "event", subtype: "vpn" }),
  cisco_ftd: k => ({ Message_number: k }), cisco_asa: k => ({ Message_number: k }), anyconnect: k => ({ message_id: k }),
  crowdstrike: k => ({ event_simpleName: k }), cyberark: k => ({ SignatureID: k }), windows_security: k => ({ EventID: Number(k) }), sysmon: k => ({ EventID: Number(k) }),
  windows_dns: k => ({ EventID: Number(k) }), okta: k => ({ eventType: k }), paloalto: k => ({ type: k }), globalprotect: k => ({ eventid: k, type: "GLOBALPROTECT" }),
  checkpoint: k => ({ product: { firewall: "VPN-1 & FireWall-1", ips: "SmartDefense", url_filtering: "URL Filtering", app_control: "Application Control", anti_bot: "Anti-Bot" }[k] }),
  aws_cloudtrail: k => ({ eventType: k }), google_workspace: k => ({ id: { applicationName: k } }),
};

/** Text sources keep their fields in the line. */
function rawLineOf(uc: UseCase, rec: Record<string, unknown>, kind: string): string | undefined {
  if (uc.sourceId === "linux_auditd") return `node=host type=${kind} msg=audit(1767255495.147:1): ${Object.entries(rec).map(([k, v]) => `${k.replace(/_decoded$/, "")}="${v}"`).join(" ")}`;
  if (uc.sourceId === "infoblox") return `<30>Jan  1 09:16:28 ns1 named[1]: 01-Jan-2026 09:16:28.455 client ${rec.client_ip ?? "10.0.0.1"}#1: UDP: query: ${rec.qname ?? "a.example"} IN ${rec.qtype ?? "A"} response: ${rec.rcode ?? "NOERROR"} +ED`;
  return undefined;
}
