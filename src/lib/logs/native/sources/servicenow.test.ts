import { describe, it, expect } from "vitest";
import { source, kindOf, sysId } from "./servicenow";
import { corpusFor, type CorpusEvent } from "../testing/corpus";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { sampleLogs, violationsOf, convertAll, contains, flatSamples } from "./_dnsHostItsm.testkit";
import { helpdeskMfaResetScenarioEvents } from "@/lib/sim/scenario-packs/helpdeskMfaReset.events";
import { aiLlmJackingScenarioEvents } from "@/lib/sim/scenario-packs/aiLlmJacking.events";
import { buildBackupFalsePositiveScenario } from "@/lib/sim/scenario-packs/backupFalsePositive";

/*
 * Card samples: 4 of 5 validate. SKIPPED: §4.2 — the same change rendered with
 * sysparm_display_value=all ({display_value, value} on every field). The card allows that shape only
 * when a connector is configured so and forbids mixing it with raw mode; this module renders raw mode,
 * so kindOf() returns null for display-mode records.
 *
 * Inputs: every corpus "soar" event (all ServiceNow, from serviceNowRecord) plus the ServiceNow records
 * of the three scenario packs that use the emitter (help-desk MFA reset, LLMjacking, backup FP).
 */
const samples = sampleLogs(source, kindOf);
const packEvents: CorpusEvent[] = [
  ...helpdeskMfaResetScenarioEvents().events.map(ev => ({ ev, origin: "story" as const, companyId: "nexacorp" })),
  ...aiLlmJackingScenarioEvents().events.map(ev => ({ ev, origin: "story" as const, companyId: "quantumbank" })),
  ...buildBackupFalsePositiveScenario().events.map(ev => ({ ev, origin: "story" as const, companyId: "nexacorp" })),
].filter(c => c.ev.source === "soar");
const events = [...corpusFor(source.schema.telemetrySources), ...packEvents];
const converted = convertAll(source, events);

describe("servicenow — card samples", () => {
  it("raw-mode card samples validate with zero violations; display-mode sample skipped", () => {
    expect(samples.skipped.length).toBe(1);
    expect(samples.logs.length).toBe(flatSamples(source.schema.card).length - 1);
    for (const l of samples.logs) expect(violationsOf(l, source), l.kind).toEqual([]);
  });
});

describe("servicenow — conversion", () => {
  it("every ServiceNow record converts with zero violations (≥95% coverage)", () => {
    const sn = converted.filter(c => (c.c.ev.vendor ?? "").toLowerCase().includes("servicenow"));
    for (const c of converted) {
      expect(c.error, c.c.ev.id).toBeUndefined();
      if (c.log) {
        expect(violationsOf(c.log, source), c.c.ev.id).toEqual([]);
        expect(c.log.timeMs).toBe(Date.parse(c.c.ev.ts));
      }
    }
    const ok = sn.filter(c => c.log).length;
    console.log(`[servicenow] ${ok}/${sn.length} ServiceNow records (${packEvents.length} from scenario packs); kinds ${JSON.stringify(converted.reduce((a, c) => (c.log ? { ...a, [c.log.kind]: (a[c.log.kind] ?? 0) + 1 } : a), {} as Record<string, number>))}`);
    expect(ok / sn.length).toBeGreaterThanOrEqual(0.95);
  });
  it("raw-mode shape: strings only, {link,value} references, UTC datetimes, empty journals", () => {
    for (const { log } of converted) {
      if (!log) continue;
      const r = (log.record.result ?? {}) as Record<string, unknown>;
      expect(Object.keys(log.record)).toEqual(["result"]);
      for (const [k, v] of Object.entries(r)) {
        if (typeof v === "object" && v !== null) {
          expect(Object.keys(v).sort(), k).toEqual(["link", "value"]);
          expect((v as { value: string }).value).toMatch(/^[0-9a-f]{32}$/);
          expect((v as { link: string }).link).toMatch(/^https:\/\/[a-z]+\.service-now\.com\/api\/now\/table\/\w+\/[0-9a-f]{32}$/);
        } else expect(typeof v, k).toBe("string");
        if (/(_on|_at|_date)$/.test(k) && v) expect(String(v), k).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
      }
      expect(r.work_notes).toBe("");
      expect(r.comments).toBe("");
    }
  });
  it("evidence survives: number, short description, people as sys_user references, one sys_id per ticket", () => {
    const byNumber = new Map<string, string>();
    for (const { c, log } of converted) {
      if (!log) continue;
      const ev = c.ev, r = log.record.result as Record<string, unknown>, ctx = makeCtx(c.companyId);
      expect(r.number).toBe(ev.raw["servicenow.number"]);
      if (ev.raw["servicenow.short_description"]) expect(r.short_description).toBe(ev.raw["servicenow.short_description"]);
      for (const k of ["caller_id", "assigned_to", "opened_by", "requested_by", "requested_for"]) {
        const email = ev.raw[`servicenow.${k}`] as string | undefined;
        if (email && k in r) expect((r[k] as { value: string }).value, `${ev.id} ${k}`).toBe(sysId(ctx, "sys_user", email));
      }
      if (ev.user_email) expect(contains(r, sysId(ctx, "sys_user", ev.user_email)) || contains(r, ev.user_email.split("@")[0]), `${ev.id} user`).toBe(true);
      const prev = byNumber.get(String(r.number));
      if (prev) expect(r.sys_id).toBe(prev);
      byNumber.set(String(r.number), String(r.sys_id));
    }
  });
  it("non-ServiceNow SOAR events render as null", () => {
    const fake = { ...events[0].ev, vendor: "Palo Alto Cortex XSOAR" };
    expect(source.fromTelemetry(fake, makeCtx("nexacorp"))).toBeNull();
  });
  it("is deterministic", () => {
    for (const c of events) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
  });
});

describe("servicenow — use cases", () => {
  // Change-process fixtures built from the card's §4.1 approved normal change: (a) the same change as an
  // emergency change, (b) moved to Implement while approval is still "requested".
  const chg = flatSamples(source.schema.card).find(r => (r.result as Record<string, unknown>)?.sys_class_name === "change_request" && (r.result as Record<string, unknown>).sys_id) as { result: Record<string, unknown> };
  const fixtures: NativeLog[] = [
    { sourceId: "servicenow", kind: "change_request", format: "json", timeMs: 1, record: { result: { ...chg.result, type: "emergency" } } },
    { sourceId: "servicenow", kind: "change_request", format: "json", timeMs: 2, record: { result: { ...chg.result, state: "-1", approval: "requested" } } },
  ];
  const story = converted.filter(c => c.log).map(c => c.log!);
  const pool = [...samples.logs, ...story, ...fixtures];
  it("every use case fires on card-sample / story logs", () => {
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("servicenow.")).toBe(true);
      const hits = runUseCase(uc, pool);
      // No benign/company ServiceNow noise exists in the corpus; high rules are checked against the authored records.
      const authoredHits = runUseCase(uc, story).length;
      console.log(`[servicenow] ${uc.id}: ${hits.length} hit(s) on samples+stories+fixtures (${authoredHits} on authored records)`);
      expect(hits.length, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(authoredHits / Math.max(1, story.length)).toBeLessThan(0.02);
    }
  });
});
