import { describe, it, expect } from "vitest";
import { source, kindOf, isSentinelSecurityAlert } from "./sentinel_alert";
import { corpus, cardSamples } from "../testing/corpus";
import { standardChecks } from "../testing/standardChecks";
import { validateNative } from "../validate";
import { makeCtx } from "../ctx";
import { nativeView } from "../index";
import { entraObjectId } from "./_identity-common";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { runUseCase } from "../engine";
import { siemMirror, enrichEvent } from "@/app/(app)/dashboard/useLiveEvents";
import type { TelemetryEvent } from "@/lib/sim/types";

/*
 * Card samples: both blocks of siem-sentinel-securityalert.md are SecurityAlert rows; none skipped.
 *
 * Documented nulls (fromTelemetry -> null): a SIEM row of another product (Claude Enterprise, Thinkst
 * Canary, AWS Cost Anomaly Detection) and a Sentinel UEBA anomaly (BehaviorAnalytics, not SecurityAlert).
 */
type Rec = Record<string, unknown>;
const alerts = corpus().filter(c => isSentinelSecurityAlert(c.ev));
const parse = (s: unknown) => JSON.parse(String(s)) as unknown;
const MIRROR_RULES = new Set(["sentinel_alert.forwarded-edr-detection", "sentinel_alert.multi-alert-entity"]);

describe("sentinel_alert: card samples", () => {
  const samples = cardSamples(source.schema.card) as Rec[];
  it("every sample is a SecurityAlert row and validates with zero violations", () => {
    expect(samples.length).toBeGreaterThanOrEqual(2);
    for (const r of samples) {
      expect(kindOf(r)).toBe("SecurityAlert");
      expect(validateNative({ sourceId: "sentinel_alert", kind: "SecurityAlert", format: "json", record: r, timeMs: 0 }, source.schema)).toEqual([]);
    }
  });
});

describe("sentinel_alert: standard checks", () => {
  const rep = standardChecks(source, kindOf, { cards: [source.schema.card] });
  it("records validate, evidence survives, output is deterministic", () => {
    console.log(`[sentinel_alert] card ${rep.cardChecked}, converted ${rep.nativeConverted}/${rep.nativeTotal} native, ${rep.crossConverted}/${rep.crossTotal} cross-vendor`);
    expect(rep.cardViolations).toEqual([]);
    expect(rep.violations.slice(0, 10)).toEqual([]);
    expect(rep.evidenceMissing.slice(0, 10)).toEqual([]);
    expect(rep.nondeterministic).toEqual([]);
    expect(rep.nativeConverted).toBe(alerts.length);
  });
  it("use cases fire on stories and stay quiet on noise", () => {
    console.log(`[sentinel_alert] use cases ${JSON.stringify(rep.useCaseHits)}, noise ${rep.noiseCount}`);
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const [id, h] of Object.entries(rep.useCaseHits)) {
      // The SIEM mirror of an EDR detection is made while the feed streams (siemMirror), never authored:
      // the two rules that read it are checked on mirror rows below.
      if (!MIRROR_RULES.has(id)) expect(h.attack, id).toBeGreaterThan(0);
      if (["high", "critical"].includes(h.severity)) expect(h.noise, id).toBeLessThanOrEqual(Math.max(1, Math.floor(rep.noiseCount * 0.02)));
    }
  });
});

describe("sentinel_alert: what it renders", () => {
  it("renders every Sentinel alert of the corpus, and nothing else", () => {
    expect(alerts.length).toBeGreaterThan(40);
    for (const c of alerts) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId)), c.ev.id).not.toBeNull();
    const others = corpus().filter(c => c.ev.source === "siem" && !isSentinelSecurityAlert(c.ev));
    for (const c of others) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId)), c.ev.id).toBeNull();
  });

  it("writes Log Analytics shapes: JSON-string columns, the product's enums, no ECS mirrors", () => {
    for (const c of alerts) {
      const r = source.fromTelemetry(c.ev, makeCtx(c.companyId))!.record;
      expect(Array.isArray(parse(r.Entities)), c.ev.id).toBe(true);
      expect(typeof parse(r.ExtendedProperties), c.ev.id).toBe("object");
      if (r.Techniques !== undefined) expect(Array.isArray(parse(r.Techniques)), c.ev.id).toBe(true);
      expect(typeof r.Tactics).toBe("string");
      expect(["High", "Medium", "Low", "Informational"]).toContain(r.AlertSeverity);
      expect(Object.keys(r).filter(k => k.includes("."))).toEqual([]);
      expect(Date.parse(String(r.StartTime))).toBeLessThanOrEqual(Date.parse(String(r.EndTime)));
      expect(Date.parse(String(r.EndTime))).toBeLessThanOrEqual(Date.parse(String(r.TimeGenerated)));
    }
  });

  it("names the company's tenant and the person's Entra object id, whoever authored the row", () => {
    const ev = sentinelAlert({ id: "t-sa-1", ts: "2026-11-09T09:41:12.000Z", companyId: "nexacorp", host: "WS-FIN-0412", user: "r.alvarez@nexacorp.com", alertName: "Test rule", severity: "high" });
    for (const company of ["nexacorp", "medcore"]) {
      const ctx = makeCtx(company);
      const r = source.fromTelemetry(ev, ctx)!.record;
      expect(r.TenantId).toBe(ctx.tenant.azureTenantId);
      const acct = (parse(r.Entities) as Rec[]).find(e => e.Type === "account")!;
      expect(acct.AadUserId).toBe(entraObjectId(ctx, "r.alvarez@nexacorp.com"));
    }
  });

  it("the feed renders a Sentinel alert natively; a UEBA anomaly keeps its own view", () => {
    const ev = sentinelAlert({ id: "t-sa-2", ts: "2026-11-09T10:00:00.000Z", companyId: "rocketstack", host: "ENG-LT-0101", alertName: "Forwarded detection", severity: "medium" });
    expect(nativeView(ev, "rocketstack")?.log.sourceId).toBe("sentinel_alert");
    const ueba = { ...ev, raw: { AlertName: "Anomalous sign-in", "entity.type": "user", "entity.name": "a.b" } } as TelemetryEvent;
    expect(nativeView(ueba, "rocketstack")).toBeNull();
  });
});

describe("sentinel_alert: the SIEM mirror of an EDR detection", () => {
  const edr = (id: string, ts: string) => enrichEvent({
    id, ts, source: "edr", vendor: "CrowdStrike Falcon", event_type: "edr_alert", severity: "high", is_detection: true,
    hostname: "ENG-LT-0101", user_email: "d.kim@rocketstack.io", src_ip: "10.20.4.31", mitre_technique: "T1059.001",
    process: { name: "powershell.exe", cmdline: "powershell.exe -nop -enc SQBFAFgA" }, raw: {},
  } as TelemetryEvent, 0);
  const mirrors = [edr("t-m-1", "2026-11-09T10:00:00.000Z"), edr("t-m-2", "2026-11-09T10:20:00.000Z")].map((e, i) => siemMirror(e, i)!);
  const logs = mirrors.map(m => nativeView(m, "rocketstack")!.log);

  it("renders natively, names the host, and the two mirror rules fire", () => {
    for (const l of logs) {
      expect(l.sourceId).toBe("sentinel_alert");
      expect(validateNative(l, source.schema)).toEqual([]);
      expect(String(l.record.Entities)).toContain("ENG-LT-0101");
    }
    for (const id of MIRROR_RULES) {
      const uc = source.useCases.find(u => u.id === id)!;
      expect(runUseCase(uc, logs).length, id).toBeGreaterThan(0);
    }
  });
});
