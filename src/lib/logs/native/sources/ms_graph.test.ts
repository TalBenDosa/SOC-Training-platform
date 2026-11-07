import { describe, it, expect } from "vitest";
import { source, kindOf } from "./ms_graph";
import { source as mde } from "./mde";
import { corpus, corpusFor, cardSamples, type CorpusEvent } from "../testing/corpus";
import { standardChecks } from "../testing/standardChecks";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { describeEvent } from "@/lib/sim/describeEvent";
import { isProductDetection, microsoftProductOf, sourceFor, type Stack } from "../stack";
import { isProductDetection as workspaceTest } from "@/lib/sentinel/workspace";
import { nativize } from "../index";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";

/*
 * Card samples: every block of siem-ms-graph-alerts.md is an indexed alerts_v2 record; none skipped.
 *
 * Documented nulls (fromTelemetry -> null):
 *   - the event is not a product detection: raw logs stay in their own format;
 *   - the product is not Microsoft's: Check Point, Cisco, a third-party WAF, GitHub, Guardium, a non-Purview DLP.
 *
 * The API call of a cloud event has no place in an alert, so it is left out of the evidence check.
 */
type Rec = Record<string, unknown>;
const alertOf = (l: NativeLog) => ((l.record.data as Rec)["ms-graph"]) as Rec;
const evidence = (l: NativeLog) => alertOf(l).evidence as Rec[];
const MICROSOFT: Stack = { edr: "mde", idp: "entra", collab: "m365", email_security: "defender_o365" };
const render = (c: CorpusEvent) => source.fromTelemetry(c.ev, makeCtx(c.companyId));

const detections = corpus().filter(c => microsoftProductOf(c.ev, MICROSOFT));
const logs = detections.map(c => ({ c, log: render(c)! }));

describe("ms_graph: card samples", () => {
  const samples = cardSamples(source.schema.card) as Rec[];
  it("every sample is an indexed alert and validates with zero violations", () => {
    expect(samples.length).toBeGreaterThanOrEqual(5);
    for (const r of samples) {
      expect(kindOf(r)).toBe("alerts_v2");
      expect(validateNative({ sourceId: "ms_graph", kind: "alerts_v2", format: "json", record: r, timeMs: 0 }, source.schema)).toEqual([]);
    }
  });
});

describe("ms_graph: standard checks", () => {
  const evidenceValues = (c: CorpusEvent) => {
    const e = c.ev;
    return [e.src_ip, e.dst_ip, e.user_email?.split("@")[0], e.process?.cmdline, e.process?.hash?.sha256, e.file?.sha256, e.dns?.query]
      .filter((x): x is string => typeof x === "string" && x.length > 2);
  };
  const rep = standardChecks(source, kindOf, { cards: [source.schema.card], evidence: evidenceValues });
  it("records validate, evidence survives, output is deterministic", () => {
    console.log(`[ms_graph] card ${rep.cardChecked}, converted ${rep.nativeConverted}/${rep.nativeTotal} native, ${rep.crossConverted}/${rep.crossTotal} cross-vendor`);
    expect(rep.cardViolations).toEqual([]);
    expect(rep.violations.slice(0, 10)).toEqual([]);
    expect(rep.evidenceMissing.slice(0, 10)).toEqual([]);
    expect(rep.nondeterministic).toEqual([]);
    expect(rep.nativeConverted + rep.crossConverted).toBe(detections.filter(c => source.schema.telemetrySources.includes(c.ev.source)).length);
  });
  it("use cases fire on stories and stay quiet on noise", () => {
    console.log(`[ms_graph] use cases ${JSON.stringify(rep.useCaseHits)}, noise ${rep.noiseCount}`);
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const [id, h] of Object.entries(rep.useCaseHits)) {
      expect(h.attack, id).toBeGreaterThan(0);
      if (["high", "critical"].includes(h.severity)) expect(h.noise, id).toBeLessThanOrEqual(Math.floor(rep.noiseCount * 0.02));
    }
  });
});

describe("ms_graph: what it renders", () => {
  it("every Microsoft detection renders, with the documented enum values", () => {
    const SERVICE = new Set(["microsoftDefenderForEndpoint", "microsoftDefenderForIdentity", "microsoftDefenderForCloudApps", "microsoftDefenderForOffice365",
      "microsoft365Defender", "azureAdIdentityProtection", "dataLossPrevention", "microsoftDefenderForCloud", "microsoftSentinel", "unknown"]);
    const DETECTION = new Set(["microsoftDefenderForEndpoint", "antivirus", "microsoftDefenderForOffice365", "microsoftDefenderForIdentity", "cloudAppSecurity",
      "microsoft365Defender", "azureAdIdentityProtection", "microsoftDataLossPrevention", "microsoftDefenderForCloud", "scheduledAlerts", "builtInMl",
      "microsoftDefenderThreatIntelligenceAnalytics", "microsoftInsiderRiskManagement"]);
    const pairs = new Map<string, number>();
    expect(detections.length).toBeGreaterThan(100);
    for (const { c, log } of logs) {
      expect(log, c.ev.id).not.toBeNull();
      const a = alertOf(log);
      expect(SERVICE.has(a.serviceSource as string), `${c.ev.id} ${a.serviceSource}`).toBe(true);
      expect(DETECTION.has(a.detectionSource as string), `${c.ev.id} ${a.detectionSource}`).toBe(true);
      expect(["informational", "low", "medium", "high"]).toContain(a.severity);
      const k = `${a.serviceSource}/${a.detectionSource}`;
      pairs.set(k, (pairs.get(k) ?? 0) + 1);
    }
    console.log(`[ms_graph] pairs ${JSON.stringify([...pairs])}`);
    for (const need of ["microsoftDefenderForEndpoint/microsoftDefenderForEndpoint", "microsoftDefenderForEndpoint/antivirus", "azureAdIdentityProtection/azureAdIdentityProtection",
      "dataLossPrevention/microsoftDataLossPrevention", "microsoftSentinel/scheduledAlerts", "microsoftDefenderForIdentity/microsoftDefenderForIdentity", "microsoftDefenderForCloud/microsoftDefenderForCloud"]) {
      expect(pairs.get(need), need).toBeGreaterThan(0);
    }
  });

  it("is indexed the way the Wazuh module sends it", () => {
    for (const { log } of logs) {
      expect(log.record.data).toMatchObject({ integration: "ms-graph", "ms-graph": { resource: "security", relationship: "alerts_v2" } });
      expect(log.record.decoder).toEqual({ name: "json-msgraph" });
    }
  });

  it("portal links keep the real URL shape and the tenant", () => {
    for (const { c, log } of logs) {
      const a = alertOf(log), tid = makeCtx(c.companyId).tenant.azureTenantId;
      expect(a.alertWebUrl).toBe(`https://security.microsoft.com/alerts/${a.id}?tid=${tid}`);
      expect(a.incidentWebUrl).toBe(`https://security.microsoft.com/incidents/${a.incidentId}?tid=${tid}`);
    }
  });

  it("times follow the event", () => {
    for (const { c, log } of logs) {
      const a = alertOf(log), t = Date.parse(c.ev.ts);
      expect(Date.parse(a.firstActivityDateTime as string)).toBe(t);
      expect(Date.parse(a.lastActivityDateTime as string)).toBe(t);
      const created = Date.parse(a.createdDateTime as string);
      expect(created).toBeGreaterThanOrEqual(t);
      expect(created - t).toBeLessThan(10_000);
      expect(a.createdDateTime).toMatch(/\.\d{7}Z$/);
    }
    const c = logs[0].c;
    const later = source.fromTelemetry({ ...c.ev, ts: "2026-11-07T10:00:00.000Z" }, makeCtx(c.companyId))!;
    expect(alertOf(later).firstActivityDateTime).toBe("2026-11-07T10:00:00.000Z");
  });

  it("a Defender for Endpoint alert is the alert its AlertEvidence row names", () => {
    let joined = 0;
    for (const { c, log } of logs) {
      if (alertOf(log).serviceSource !== "microsoftDefenderForEndpoint") continue;
      const row = mde.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (row?.kind !== "AlertEvidence") continue;
      const p = (row.record as { properties: Rec }).properties;
      expect(alertOf(log).id).toBe(p.AlertId);
      joined++;
      const device = evidence(log).find(e => e["@odata.type"] === "#microsoft.graph.security.deviceEvidence");
      if (device) expect(device.mdeDeviceId).toBe(p.DeviceId);
    }
    expect(joined).toBeGreaterThan(20);
  });

  it("the row description reads the alert title from the record", () => {
    const { c, log } = logs.find(x => !x.c.ev.raw?.AlertName && x.c.ev.is_detection)!;
    const line = describeEvent({ ...c.ev, raw: log.record }, { fieldsOnly: true, preferFields: true });
    expect(line).toContain(alertOf(log).title as string);
  });

  it("raw logs and other vendors' detections are not alerts", () => {
    for (const c of corpusFor(source.schema.telemetrySources)) {
      if (microsoftProductOf(c.ev, MICROSOFT)) continue;
      expect(render(c), c.ev.id).toBeNull();
    }
    expect(source.fromTelemetry(corpus().find(c => c.ev.source === "firewall" && c.ev.is_detection)!.ev, makeCtx("nexacorp"))).toBeNull();
  });
});

describe("the detection test matches the Sentinel workspace", () => {
  it("over the whole corpus", () => {
    const off: string[] = [];
    for (const c of corpus()) {
      const log = nativize(c.ev, c.companyId, undefined);
      // The workspace reads the Defender for Cloud alert off the record, stack.ts off the raw keys that make it one.
      if (workspaceTest(c.ev, log ?? undefined) !== (isProductDetection(c.ev) || false)) off.push(`${c.ev.id} ${c.ev.source}/${c.ev.vendor}`);
    }
    expect(off.slice(0, 10)).toEqual([]);
  });
  it("sourceFor keeps a raw log on its own product", () => {
    const raw = corpus().find(c => c.ev.source === "edr" && !isProductDetection(c.ev))!;
    expect(sourceFor(raw.ev, { ...MICROSOFT, detection_feed: "ms_graph" })).toBe("mde");
  });
});

describe("use case logic", () => {
  it("the threshold rule needs three titles in one category", () => {
    const uc = source.useCases.find(u => u.id === "ms_graph.repeated-alerts-one-category")!;
    const one = logs[0].log;
    const same = [one, one, one].map((l, i) => ({ ...l, timeMs: i * 1000 }));
    expect(runUseCase(uc, same)).toEqual([]);
  });
});

export type { TelemetryEvent };
