// The workspace built from real team feeds: real tables and columns, deterministic, append-stable,
// fast, and free of the answer key.
import { readdirSync, readFileSync } from "fs";
import { join } from "path";
import { describe, expect, it } from "vitest";
import { runKql } from "@/lib/kql";
import type { KqlType } from "@/lib/kql/types";
import { buildTeamTimeline, TEAM_ANSWER_FIELDS, teamStoryPool, type TimelineEntry } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import type { TelemetryEvent } from "@/lib/sim/types";
import { EntityBook } from "./entities";
import { columnType, TABLE_NAMES, TABLE_SCHEMAS } from "./tables";
import { buildWorkspace, isProductDetection, type SentinelWorkspaceBuild, warrantsInvestigation } from "./workspace";

const COMPANIES = ["nexacorp", "medcore", "rocketstack", "globallogis", "quantumbank"];
const DIFFS = ["easy", "medium", "hard"] as const;
const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];

function session(company: string, diff: (typeof DIFFS)[number], seed: string, story?: string): { tl: TimelineEntry[]; events: TelemetryEvent[]; ans: Map<string, Record<string, unknown>> } {
  const tl = buildTeamTimeline(company, diff, seed, story ?? null, teamLoad(diff, roster), {}).filter(t => t.channel === "feed");
  return { tl, events: tl.map(t => t.body as unknown as TelemetryEvent), ans: new Map(tl.map(t => [(t.body as unknown as TelemetryEvent).id, (t.answer ?? {}) as Record<string, unknown>])) };
}

const isAttack = (a?: Record<string, unknown>) => a?.expected_verdict === "tp" || a?.expected_verdict === "escalate";

const typeOk: Record<KqlType, (v: unknown) => boolean> = {
  string: v => typeof v === "string", int: v => Number.isInteger(v), long: v => Number.isInteger(v), real: v => typeof v === "number", bool: v => typeof v === "boolean",
  datetime: v => typeof v === "string" && Number.isFinite(Date.parse(v)), timespan: () => true, dynamic: () => true, guid: v => typeof v === "string",
};

describe("schemas", () => {
  it("every table has the common columns the real table has", () => {
    for (const t of TABLE_NAMES) {
      const names = TABLE_SCHEMAS[t].map(c => c.name);
      expect(names, t).toContain("TimeGenerated");
      expect(names, t).toContain("Type");
    }
  });
});

describe("rows", () => {
  for (const company of COMPANIES) {
    it(`${company}: real columns, real types, one row per mapped event`, () => {
      const { events } = session(company, "hard", `rows-${company}`);
      const ws = buildWorkspace(events, { companyId: company });
      const problems: string[] = [];
      for (const [name, table] of Object.entries(ws.tables)) {
        expect(table.name).toBe(name);
        for (const row of table.rows) {
          if (row.Type !== name) problems.push(`${name}: Type ${String(row.Type)}`);
          for (const [col, v] of Object.entries(row)) {
            const t = columnType(name, col);
            if (!t) problems.push(`${name}.${col} is not a real column`);
            else if (!typeOk[t](v)) problems.push(`${name}.${col} (${t}) holds ${typeof v}: ${String(v).slice(0, 40)}`);
          }
        }
      }
      expect([...new Set(problems)].slice(0, 20)).toEqual([]);
      expect(ws.coverage.rows).toBeGreaterThan(20);
      expect(ws.name).toMatch(/-xdr-prod$/);
      expect(Date.parse(ws.now)).toBeGreaterThan(0);
    });
  }

  it("the row carries the native record's values, flattened and renamed as the real tables do", () => {
    const { events } = session("nexacorp", "medium", "flatten");
    const ws = buildWorkspace(events, { companyId: "nexacorp" });
    const signins = ws.tables.SigninLogs.rows;
    expect(signins.length).toBeGreaterThan(0);
    for (const r of signins) {
      expect(typeof r.ResultType).toBe("string");
      expect(String((r.Status as { errorCode?: unknown }).errorCode)).toBe(r.ResultType);
      expect(r.Location).toBe((r.LocationDetails as { countryOrRegion?: unknown }).countryOrRegion);
    }
  });
});

describe("determinism", () => {
  it("the same events give the same workspace", () => {
    const { events } = session("nexacorp", "hard", "same");
    const a = buildWorkspace(events, { companyId: "nexacorp" });
    const b = buildWorkspace(events, { companyId: "nexacorp" });
    expect(JSON.stringify(b.incidents)).toBe(JSON.stringify(a.incidents));
    expect(JSON.stringify(b.alerts)).toBe(JSON.stringify(a.alerts));
  });

  for (const company of COMPANIES) {
    it(`${company}: adding later events never renumbers earlier incidents`, () => {
      const { events } = session(company, "hard", `stable-${company}`);
      const seen = new Map<string, { number: number; firstAlert: string; created: string }>();
      for (let n = 10; n <= events.length; n += 7) {
        const ws = buildWorkspace(events.slice(0, n), { companyId: company });
        for (const inc of ws.incidents) {
          const before = seen.get(inc.id);
          if (before) {
            expect(inc.number, inc.title).toBe(before.number);
            expect(inc.alertIds[0]).toBe(before.firstAlert);
            expect(inc.created).toBe(before.created);
          } else seen.set(inc.id, { number: inc.number, firstAlert: inc.alertIds[0], created: inc.created });
        }
        const numbers = ws.incidents.map(i => i.number);
        expect(numbers).toEqual([...numbers].sort((x, y) => x - y));
        expect(new Set(numbers).size).toBe(numbers.length);
      }
      const final = buildWorkspace(events, { companyId: company });
      for (const [id, s] of seen) expect(final.incidents.find(i => i.id === id)?.number, id).toBe(s.number);
    });
  }

  it("builds a few hundred events in about 100 ms", () => {
    const parts = COMPANIES.slice(0, 1).flatMap(c => DIFFS.flatMap(d => [1, 2, 3].flatMap(s => session(c, d, `perf-${s}`).events)));
    const events = parts.slice(0, 400);
    expect(events.length).toBe(400);
    buildWorkspace(events, { companyId: "nexacorp" }); // warm the rule cache, as the first poll does
    let best = Infinity;
    for (let i = 0; i < 3; i++) {   // the suite runs on busy workers: the best of three is the code's cost
      const t0 = performance.now();
      buildWorkspace(events, { companyId: "nexacorp" });
      best = Math.min(best, performance.now() - t0);
    }
    expect(best).toBeLessThan(250); // CI headroom; about 60 ms on a laptop
  });
});

describe("the existence of an incident does not reveal the attack", () => {
  // Answer data is used here, in the test, and nowhere in production code.
  const totals: Record<string, { benign: number; attack: number }> = {};
  const tactics: Record<string, { benign: number; attack: number }> = {};
  let stories = 0, covered = 0;

  for (const company of COMPANIES) for (const diff of DIFFS) {
    it(`${company} ${diff}`, () => {
      for (const s of [1, 2]) {
        const { tl, events, ans } = session(company, diff, `leak-${company}-${s}`);
        const ws = buildWorkspace(events, { companyId: company });
        const t = totals[company] ??= { benign: 0, attack: 0 };
        for (const inc of ws.incidents) {
          const ids = inc.alertIds.flatMap(a => ws.alertEventIds[a] ?? []);
          const attack = ids.some(i => isAttack(ans.get(i)));
          t[attack ? "attack" : "benign"]++;
          for (const tac of inc.tactics) (tactics[tac] ??= { benign: 0, attack: 0 })[attack ? "attack" : "benign"]++;
        }
        const groups = new Map<string, string[]>();
        for (const e of tl) {
          const a = e.answer as Record<string, unknown> | undefined;
          if (isAttack(a) && a?.incident_id) groups.set(String(a.incident_id), [...(groups.get(String(a.incident_id)) ?? []), (e.body as unknown as TelemetryEvent).id]);
        }
        const inIncident = new Set(ws.incidents.flatMap(i => i.alertIds.flatMap(a => ws.alertEventIds[a] ?? [])));
        for (const ids of groups.values()) { stories++; if (ids.some(i => inIncident.has(i))) covered++; }
      }
    }, 60_000);
  }

  it("benign incidents are at least as common as attack incidents, per company", () => {
    console.log(`[incidents] ${JSON.stringify(totals)}`);
    for (const [company, t] of Object.entries(totals)) {
      expect(t.benign, company).toBeGreaterThanOrEqual(t.attack);
      expect(t.attack, company).toBeGreaterThan(0);
    }
  });

  it("no tactic appears on attack incidents alone", () => {
    console.log(`[tactics] ${JSON.stringify(tactics)}`);
    for (const [tac, t] of Object.entries(tactics)) if (t.attack >= 5) expect(t.benign, tac).toBeGreaterThan(0);
  });

  // The rest reach Sentinel when an analyst escalates them, tested below.
  it("most attack stories raise an incident on their own", () => {
    console.log(`[coverage] ${covered}/${stories}`);
    expect(covered / stories).toBeGreaterThan(0.85);
  });

  it("every story in the pools raises an incident", () => {
    let total = 0, hit = 0;
    for (const company of COMPANIES) {
      for (const story of teamStoryPool(company, "medium", null).slice(0, 12)) {
        const { tl, events } = session(company, "medium", `pool-${story.id}`, story.id);
        const ws = buildWorkspace(events, { companyId: company });
        const inIncident = new Set(ws.incidents.flatMap(i => i.alertIds.flatMap(a => ws.alertEventIds[a] ?? [])));
        const attack = tl.filter(t => isAttack(t.answer) && (t.answer as Record<string, unknown>).origin === "story").map(t => (t.body as unknown as TelemetryEvent).id);
        total++;
        if (attack.some(i => inIncident.has(i))) hit++;
      }
    }
    console.log(`[coverage-pool] ${hit}/${total}`);
    expect(hit / total).toBeGreaterThan(0.95);
  }, 120_000);
});

describe("no answer data", () => {
  const SRC = join(process.cwd(), "src/lib/sentinel");
  const production = readdirSync(SRC).filter(f => f.endsWith(".ts") && !f.endsWith(".test.ts"));

  it("production code names no answer field", () => {
    expect(production.length).toBeGreaterThan(7);
    const problems: string[] = [];
    for (const f of production) {
      const text = readFileSync(join(SRC, f), "utf8");
      for (const field of TEAM_ANSWER_FIELDS) {
        const hits = text.match(new RegExp(`\\b${field}\\b`, "g")) ?? [];
        // A team event about an incident says which one: the console's own payload, not the feed's field.
        const allowed = f === "state.ts" && field === "incident_id" ? (text.match(/\bp\.incident_id\b/g) ?? []).length : 0;
        if (hits.length !== allowed) problems.push(`${f}: ${field}`);
      }
    }
    expect(problems).toEqual([]);
  });

  it("production code imports nothing from the team timeline", () => {
    for (const f of production) expect(readFileSync(join(SRC, f), "utf8"), f).not.toMatch(/@\/lib\/team\/buildTimeline/);
  });

  it("the production paths over an event never touch an answer field", () => {
    const { events } = session("nexacorp", "hard", "trap");
    const read: string[] = [];
    const trapped = events.map(ev => new Proxy(ev, {
      get(t, k, r) { if ((TEAM_ANSWER_FIELDS as readonly (string | symbol)[]).includes(k)) read.push(String(k)); return Reflect.get(t, k, r); },
    }));
    const book = new EntityBook();
    for (const ev of trapped) { book.add(ev); isProductDetection(ev); }
    expect(read).toEqual([]);
  });

  it("the public feed carries no answer field, so the native layer has none to read", () => {
    for (const company of COMPANIES) {
      const { events } = session(company, "hard", `pub-${company}`);
      for (const ev of events) for (const f of TEAM_ANSWER_FIELDS) expect(ev, `${ev.id}: ${f}`).not.toHaveProperty(f);
    }
  });

  it("no row, alert or incident text names an answer field or carries a planted answer", () => {
    const MARK = "ZZ-ANSWER-MARK";
    for (const company of COMPANIES) {
      const { events } = session(company, "hard", `text-${company}`);
      const poisoned = events.map(e => ({ ...e, fp_explanation: MARK, it_verify_message: MARK, supports_inject: MARK, feed_origin: MARK }));
      const ws: SentinelWorkspaceBuild = buildWorkspace(poisoned as TelemetryEvent[], { companyId: company });
      const text = JSON.stringify({ tables: ws.tables, alerts: ws.alerts, incidents: ws.incidents, entities: ws.entities });
      expect(text).not.toContain(MARK);
      for (const f of TEAM_ANSWER_FIELDS) expect(text, f).not.toContain(f);
    }
  });

  it("titles and descriptions never state a verdict", () => {
    const VERDICT = /\b(false positive|true positive|benign|not malicious|confirmed (malicious|attack|compromise)|is an attack|this is (an? )?(attack|compromise)|known good|expected activity|safe to ignore|authori[sz]ed by|approved by)\b/i;
    const problems = new Set<string>();
    for (const company of COMPANIES) for (const diff of DIFFS) {
      const { events } = session(company, diff, `verdict-${company}`);
      const ws = buildWorkspace(events, { companyId: company });
      for (const x of [...ws.incidents, ...ws.alerts]) {
        const title = "title" in x ? x.title : x.name;
        if (VERDICT.test(title)) problems.add(`title: ${title}`);
        if (VERDICT.test(x.description)) problems.add(`description: ${x.description.slice(0, 160)}`);
      }
    }
    expect([...problems]).toEqual([]);
  }, 60_000);
});

describe("alerts and incidents", () => {
  for (const company of COMPANIES) {
    it(`${company}: alerts open real rows, incidents follow their alerts`, () => {
      const { events } = session(company, "hard", `open-${company}`);
      const ws = buildWorkspace(events, { companyId: company });
      const env = { tables: ws.tables, now: new Date(ws.now) };
      const alertIds = new Set(ws.alerts.map(a => a.id));
      expect(alertIds.size).toBe(ws.alerts.length);
      expect(ws.tables.SecurityAlert.rows.length).toBe(ws.alerts.length);
      expect(ws.tables.SecurityIncident.rows.length).toBe(ws.incidents.length);
      const problems: string[] = [];
      for (const a of ws.alerts) {
        const r = runKql(a.query, env);
        if (!r.ok) problems.push(`${a.name}: ${r.error.message}`);
        else if (r.rows.length === 0) problems.push(`${a.name}: no rows\n${a.query}`);
        for (const id of a.entityIds) if (!ws.entities[id]) problems.push(`${a.name}: entity ${id} missing`);
      }
      for (const inc of ws.incidents) {
        const r = runKql(inc.eventsQuery, env);
        if (!r.ok) problems.push(`incident ${inc.number}: ${r.error.message}`);
        expect(inc.alertIds.every(id => alertIds.has(id))).toBe(true);
        const members = ws.alerts.filter(a => inc.alertIds.includes(a.id));
        const rank = { High: 3, Medium: 2, Low: 1, Informational: 0 };
        expect(rank[inc.severity]).toBe(Math.max(...members.map(a => rank[a.severity])));
        if (new Set(members.map(a => a.name)).size > 1) expect(inc.title).toMatch(/^Multi-stage incident/);
      }
      expect(problems.slice(0, 15)).toEqual([]);
    });
  }

  it("product detections carry the real product names", () => {
    const all = new Set<string>();
    for (const company of COMPANIES) {
      const { events } = session(company, "hard", `prod-${company}`);
      const ws = buildWorkspace(events, { companyId: company });
      for (const a of ws.alerts) all.add(a.product);
    }
    // The console's own analytics raise as XDR Analytics, never as Azure or Microsoft Sentinel.
    expect(all).toContain("XDR Analytics");
    for (const p of all) expect(p).not.toMatch(/Sentinel/);
    expect(all).toContain("Microsoft Defender Advanced Threat Protection");
    for (const p of all) expect(p).not.toMatch(/^Microsoft Defender for (Office|Endpoint)|^IPS$/);
  });

  it("console text has no em dashes", () => {
    for (const company of COMPANIES) {
      const { events } = session(company, "hard", `dash-${company}`);
      const ws = buildWorkspace(events, { companyId: company });
      expect(JSON.stringify({ a: ws.alerts.map(a => [a.name, a.description]), i: ws.incidents.map(i => [i.title, i.description]), r: ws.rules.map(r => [r.name, r.description, r.falsePositives]), h: ws.hunting })).not.toContain("\u2014");
    }
  });

  it("scheduled alerts name their rule", () => {
    const { events } = session("nexacorp", "hard", "rule-link");
    const ws = buildWorkspace(events, { companyId: "nexacorp" });
    const ids = new Set(ws.rules.map(r => r.id));
    for (const a of ws.alerts) if (a.ruleId) expect(ids.has(a.ruleId), a.ruleId).toBe(true);
  });
});

describe("incidents are for deep investigation", () => {
  it("opens one for linked alerts, or a serious alert with activity around it, and not for a lone alert", () => {
    expect(warrantsInvestigation(2, "Low", 0)).toBe(true);
    expect(warrantsInvestigation(1, "High", 3)).toBe(true);
    expect(warrantsInvestigation(1, "High", 2)).toBe(false);
    expect(warrantsInvestigation(1, "Medium", 40)).toBe(false);
    expect(warrantsInvestigation(1, "Low", 40)).toBe(false);
    expect(warrantsInvestigation(1, "Low", 0, ["CommandAndControl"])).toBe(true);
  });

  it("an alert that opens no incident stays in SecurityAlert for KQL", () => {
    const { events } = session("nexacorp", "hard", "deep-1");
    const ws = buildWorkspace(events, { companyId: "nexacorp" });
    const inIncident = new Set(ws.incidents.flatMap(i => i.alertIds));
    expect(ws.alerts.some(a => !inIncident.has(a.id))).toBe(true);
    expect(ws.tables.SecurityAlert.rows.length).toBe(ws.alerts.length);
    expect(ws.tables.SecurityIncident.rows.length).toBe(ws.incidents.length);
  });

  it("an escalated log opens an incident even when no rule raised it", () => {
    const { events } = session("nexacorp", "hard", "deep-2");
    const plain = buildWorkspace(events, { companyId: "nexacorp" });
    const raised = new Set(Object.values(plain.alertEventIds).flat());
    const quiet = events.find(e => !raised.has(e.id) && plain.tables.DeviceProcessEvents.rows.length > 0);
    expect(quiet).toBeTruthy();
    const ws = buildWorkspace(events, { companyId: "nexacorp", escalated: [{ eventId: quiet!.id, summary: "Tier-1 wants a second look" }] });
    const opened = ws.incidents.find(i => i.alertIds.some(a => (ws.alertEventIds[a] ?? []).includes(quiet!.id)));
    expect(opened).toBeTruthy();
    expect(ws.alerts.some(a => a.description === "Tier-1 wants a second look")).toBe(true);
    // Everything that was there before keeps its number.
    for (const i of plain.incidents) expect(ws.incidents.find(x => x.id === i.id)?.number ?? i.number).toBe(i.number);
  });
});

describe("entities", () => {
  it("cards hold real facts: UPN, department and title; OS, IP and last seen; geo and ASN", () => {
    const { events } = session("nexacorp", "hard", "cards");
    const ws = buildWorkspace(events, { companyId: "nexacorp" });
    const list = Object.values(ws.entities);
    const account = list.find(e => e.kind === "account" && e.info.UPN);
    expect(account?.info.UPN).toContain("@");
    expect(list.some(e => e.kind === "account" && e.info.Title)).toBe(true);
    const departments = COMPANIES.flatMap(c => Object.values(buildWorkspace(session(c, "hard", "dept").events, { companyId: c }).entities)).filter(e => e.kind === "account" && e.info.Department);
    expect(departments.length).toBeGreaterThan(0);
    const host = list.find(e => e.kind === "host" && e.info.OS);
    expect(host?.info["Last seen"]).toBeTruthy();
    expect(list.some(e => e.kind === "ip" && e.info.Country)).toBe(true);
    for (const e of list) expect(e.id).toBe(`${e.kind}:${e.name.toLowerCase()}`);
    const geo = events.find(ev => ev.geo?.asn && ev.src_ip);
    if (geo) {
      const ip = ws.entities[`ip:${geo.src_ip}`];
      if (ip) expect(ip.info.ASN).toBe(String(geo.geo?.asn));
    }
  });
});
