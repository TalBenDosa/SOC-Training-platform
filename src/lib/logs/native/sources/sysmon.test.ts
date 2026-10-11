import { describe, it, expect } from "vitest";
import { source, kindOf } from "./sysmon";
import { corpusFor } from "../testing/corpus";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { sampleLogs, violationsOf, convertAll, contains, isNoise, flatSamples, type Converted } from "./_dnsHostItsm.testkit";

/*
 * Card samples: all 6 records of host-sysmon.md (events 1, 22, 3, 11, 10, 13) are supported — none skipped.
 *
 * Documented nulls (the converter returns null, never a faked record):
 *  - Sysmon-filed events whose authored event id is not a Sysmon event (e.g. a Security 4663 object-access
 *    record filed under source "sysmon").
 *  - A process event whose image path cannot be resolved (Sysmon 1 always carries a full Image path).
 *  - EDR verdict records (edr_alert / av_* / quarantine), file reads, logons, IDS, DLP — Sysmon has no such event.
 *  - EDR telemetry from Linux hosts (this card is Sysmon for Windows).
 *  - Network events without a destination IP, process-access events without a target or GrantedAccess,
 *    file/registry events without a path, or actor-less events (EDR rows that name no process).
 */
const samples = sampleLogs(source, kindOf);
const events = corpusFor(source.schema.telemetrySources);
const converted = convertAll(source, events);
const native = converted.filter(c => c.c.ev.source === "sysmon");
const cross = converted.filter(c => c.c.ev.source === "edr");

const isForeignId = (c: Converted) => {
  const id = (c.c.ev.raw?.["winlog.event_id"] ?? c.c.ev.raw?.["event.code"]) as string | undefined;
  return id !== undefined && !source.schema.kinds[String(id)];
};

describe("sysmon — card samples", () => {
  it("every supported card sample validates with zero violations", () => {
    expect(samples.skipped).toEqual([]);
    expect(samples.logs.length).toBe(flatSamples(source.schema.card).length);
    for (const l of samples.logs) expect(violationsOf(l, source), `event ${l.kind}`).toEqual([]);
  });
});

describe("sysmon — corpus conversion", () => {
  it("every converted event validates with zero violations", () => {
    for (const c of converted) {
      expect(c.error, c.c.ev.id).toBeUndefined();
      if (!c.log) continue;
      expect(violationsOf(c.log, source), `${c.c.ev.id} → ${c.log.kind}`).toEqual([]);
      expect(c.log.timeMs).toBe(Date.parse(c.c.ev.ts));
      expect(c.log.rawLine).toMatch(/^<Event xmlns=.*<EventData>.*<\/EventData><\/Event>$/);
      expect(String(c.log.record.UtcTime)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/);
    }
  });
  it("coverage: ≥95% of Sysmon-authored events, sensible floor for EDR telemetry", () => {
    const natCandidates = native.filter(c => !isForeignId(c));
    const natOk = natCandidates.filter(c => c.log).length;
    const crossOk = cross.filter(c => c.log).length;
    const nullTypes: Record<string, number> = {};
    for (const c of cross) if (!c.log) nullTypes[c.c.ev.event_type] = (nullTypes[c.c.ev.event_type] ?? 0) + 1;
    console.log(`[sysmon] native ${natOk}/${natCandidates.length} (+${native.length - natCandidates.length} non-Sysmon event ids → null); EDR→Sysmon ${crossOk}/${cross.length}; EDR nulls by type ${JSON.stringify(nullTypes)}`);
    for (const c of natCandidates) if (!c.log) console.log(`[sysmon] native null: ${c.c.ev.id} ${c.c.ev.event_type}`);
    expect(natOk / natCandidates.length).toBeGreaterThanOrEqual(0.95);
    expect(crossOk / cross.length).toBeGreaterThanOrEqual(0.5);
    // Every EDR process-creation on a Windows host with a known image renders.
    const winProc = cross.filter(c => c.c.ev.event_type === "process_create" && /\\/.test(c.c.ev.process?.path ?? ""));
    expect(winProc.every(c => c.log)).toBe(true);
  });
  it("evidence survives verbatim", () => {
    for (const { c, log } of converted) {
      if (!log) continue;
      const ev = c.ev, rec = log.record, k = log.kind;
      if (ev.hostname) expect(contains(rec, ev.hostname), `${ev.id} host`).toBe(true);
      const email = ev.user_email ?? ev.user?.email;
      const userCands = [email, email?.split("@")[0], ev.process?.user, ...["winlog.event_data.User", "user.name", "crowdstrike.UserName", "AccountName", "InitiatingProcessAccountName", "s1.srcProcUser"].map(k => ev.raw?.[k] as string | undefined)].filter(Boolean) as string[];
      if (userCands.length && ["1", "3", "11", "13", "22"].includes(k)) expect(userCands.some(u => contains(rec, u)) || /^NT AUTHORITY/.test(String(rec.User)), `${ev.id} user`).toBe(true);
      if (k === "1" && ev.process?.cmdline) expect(contains(rec, ev.process.cmdline), `${ev.id} cmdline`).toBe(true);
      if (k === "1" && ev.process?.hash?.sha256) expect(contains(rec, ev.process.hash.sha256), `${ev.id} sha256`).toBe(true);
      if ((k === "23" || k === "26") && ev.file?.sha256) expect(contains(rec, ev.file.sha256), `${ev.id} file sha256`).toBe(true);
      if (k === "3") {
        if (ev.dst_ip) expect(rec.DestinationIp, `${ev.id} dst`).toBe(ev.dst_ip);
        if (ev.src_ip) expect(rec.SourceIp, `${ev.id} src`).toBe(ev.src_ip);
        if (ev.network?.domain) expect(contains(rec, ev.network.domain), `${ev.id} domain`).toBe(true);
      }
      if (k === "22") {
        if (ev.dns?.query) expect(rec.QueryName, `${ev.id} query`).toBe(ev.dns.query);
        if (ev.network?.domain) expect(contains(rec, ev.network.domain), `${ev.id} domain`).toBe(true);
      }
      if (k === "11" && ev.file?.path) expect(rec.TargetFilename).toBe(ev.file.path);
    }
  });
  it("ProcessGuid links a child to its parent", () => {
    const procs = converted.filter(c => c.log?.kind === "1").map(c => c.log!.record);
    const guids = new Set(procs.map(r => r.ProcessGuid));
    const linked = procs.filter(r => guids.has(r.ParentProcessGuid as string));
    console.log(`[sysmon] ${linked.length}/${procs.length} process events have their parent rendered with the same GUID`);
    expect(linked.length).toBeGreaterThan(0);
  });
  it("is deterministic", () => {
    for (const c of events) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
  });
});

describe("sysmon — use cases", () => {
  const story = converted.filter(c => c.c.origin === "story" && c.log).map(c => c.log!);
  const pool = [...samples.logs, ...story];
  const noise = converted.filter(c => isNoise(c.c) && c.log).map(c => c.log!);
  it("every use case fires on card-sample / story logs; high+ stay quiet on noise", () => {
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("sysmon.")).toBe(true);
      const hits = runUseCase(uc, pool);
      const noiseHits = new Set(runUseCase(uc, noise).flatMap(h => h.records)).size;
      console.log(`[sysmon] ${uc.id}: ${hits.length} hit(s) on samples+stories, ${noiseHits}/${noise.length} noise records`);
      expect(hits.length, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
