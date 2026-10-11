import { describe, it, expect } from "vitest";
import { source, kindOf, alertInfoFor } from "./mde";
import { edrFacts } from "./edr-normalize";
import { corpusFor, cardSamples, type CorpusEvent } from "../testing/corpus";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";

/*
 * Card samples: all 6 blocks of edr-defender-endpoint.md are supported kinds (DeviceProcessEvents,
 * DeviceEvents/DnsQueryResponse, DeviceNetworkEvents, DeviceFileEvents, AlertInfo, AlertEvidence).
 * Sample 4.1 is the Event Hub message `{"records":[…]}` — unwrapped to its single record; none skipped.
 *
 * Documented nulls (fromTelemetry → null):
 *   - edrFacts marks the event unsupported (USB / device control, file-read scans, file events without a path);
 *   - a process event with no image name, path or command line (Defender never emits a nameless
 *     ProcessCreated row) — e.g. the scheduled-task event of the cracked-software story;
 *   - a network event with no remote IP in the facts (inbound / IMDS events authored without one).
 */
type Rec = Record<string, unknown>;
const props = (l: NativeLog) => (l.record as { properties: Rec }).properties;

function deepStrings(v: unknown, out: string[] = []): string[] {
  if (v === null || v === undefined) return out;
  if (Array.isArray(v)) { for (const x of v) deepStrings(x, out); return out; }
  if (typeof v === "object") { for (const x of Object.values(v as Rec)) deepStrings(x, out); return out; }
  out.push(String(v));
  // AdditionalFields is a JSON string: its members are evidence too.
  if (typeof v === "string" && /^[[{]/.test(v)) { try { deepStrings(JSON.parse(v), out); } catch { /* not JSON */ } }
  return out;
}
const contains = (r: unknown, s: string) => deepStrings(r).some(x => x.includes(s));
const isNoise = (c: CorpusEvent) => c.origin !== "story" && c.ev.expected_verdict !== "tp" && c.ev.severity !== "high" && c.ev.severity !== "critical";
const nativeVendor = (v?: string) => source.schema.vendorMatch.some(m => (v ?? "").toLowerCase().includes(m));

const samples: NativeLog[] = cardSamples(source.schema.card)
  .flatMap(x => ((x as Rec).records ? ((x as Rec).records as Rec[]) : [x as Rec]))
  .map(r => ({ sourceId: "mde", kind: kindOf(r) ?? "?", format: "json", record: r, timeMs: Date.parse(String((r.properties as Rec).Timestamp)) }));

const events = corpusFor(source.schema.telemetrySources);
const converted = events.map(c => ({ c, log: source.fromTelemetry(c.ev, makeCtx(c.companyId)) }));

function documentedNull(ev: TelemetryEvent): boolean {
  const f = edrFacts(ev);
  if (f.kind === "unsupported") return true;
  if (f.kind === "process" && !f.proc.name && !f.proc.path && !f.proc.cmdline) return true;
  if (f.kind === "network" && !f.net.remoteIp) return true;
  return false;
}

describe("mde — card samples", () => {
  it("the Event Hub wrapper is not a record; every sample record validates with zero violations", () => {
    expect(kindOf(cardSamples(source.schema.card)[0] as Rec)).toBeNull();
    expect(samples.length).toBe(6);
    for (const l of samples) {
      expect(source.schema.kinds[l.kind], l.kind).toBeDefined();
      expect(validateNative(l, source.schema), l.kind).toEqual([]);
    }
  });
});

describe("mde — corpus conversion", () => {
  it("converts every EDR/AV event (or returns null for a documented reason) with zero violations", () => {
    for (const { c, log } of converted) {
      if (!log) { expect(documentedNull(c.ev), `unexpected null ${c.ev.id}`).toBe(true); continue; }
      expect(validateNative(log, source.schema), `${c.ev.id} ${log.kind}`).toEqual([]);
      expect(log.timeMs).toBe(Date.parse(c.ev.ts));
      const r = log.record as Rec;
      expect(r.operationName).toBe("Publish");
      expect(r.category).toBe(`AdvancedHunting-${log.kind}`);
      expect(r.tenantId).toBe(makeCtx(c.companyId).tenant.azureTenantId);
      const p = props(log);
      expect(String(p.Timestamp)).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z$/);
      expect(String(r.time)).toMatch(/\.\d{7}Z$/);
      if ("DeviceId" in p) expect(String(p.DeviceId)).toMatch(/^[0-9a-f]{40}$/);
      for (const k of ["AdditionalFields", "AttackTechniques", "Categories"]) if (p[k] !== undefined && p[k] !== null) expect(typeof p[k], k).toBe("string");
    }
  });

  it("coverage: ≥95% of Defender-authored supported events; cross-vendor floor", () => {
    const supported = converted.filter(x => edrFacts(x.c.ev).kind !== "unsupported");
    const nat = supported.filter(x => nativeVendor(x.c.ev.vendor));
    const cross = supported.filter(x => !nativeVendor(x.c.ev.vendor));
    const natOk = nat.filter(x => x.log).length, crossOk = cross.filter(x => x.log).length;
    const kinds: Record<string, number> = {};
    for (const x of converted) if (x.log) kinds[x.log.kind] = (kinds[x.log.kind] ?? 0) + 1;
    console.log(`[mde] native ${natOk}/${nat.length}, cross-vendor ${crossOk}/${cross.length}, unsupported-by-facts ${converted.length - supported.length}; kinds ${JSON.stringify(kinds)}`);
    expect(natOk / nat.length).toBeGreaterThanOrEqual(0.95);
    expect(crossOk / cross.length).toBeGreaterThanOrEqual(0.95);
  });

  it("evidence survives verbatim", () => {
    for (const { c, log } of converted) {
      if (!log) continue;
      const f = edrFacts(c.ev);
      const p = props(log);
      const id = `${c.ev.id} ${log.kind}`;
      expect(contains(p, f.host!), `${id} host`).toBe(true);
      // Account columns exist on every Device* table and on Process-entity AlertEvidence rows.
      const accountRow = log.kind !== "AlertEvidence" || p.EntityType === "Process";
      if (accountRow && (f.user || f.userEmail)) expect((f.user && contains(p, f.user)) || (f.userEmail && contains(p, f.userEmail)), `${id} user`).toBe(true);
      if (f.proc.cmdline) expect(contains(p, f.proc.cmdline), `${id} cmdline`).toBe(true);
      if (f.parent.cmdline) expect(contains(p, f.parent.cmdline), `${id} parent cmdline`).toBe(true);
      if (f.proc.sha256) expect(contains(p, f.proc.sha256), `${id} process sha256`).toBe(true);
      const fileRow = log.kind === "DeviceFileEvents" || (log.kind === "AlertEvidence" && p.EntityType === "File");
      if (fileRow && f.file.sha256) expect(contains(p, f.file.sha256), `${id} file sha256`).toBe(true);
      if (fileRow && f.file.path) expect(contains(p, f.file.path) || contains(p, f.file.path.replace(/[\\/][^\\/]+$/, "")), `${id} file path`).toBe(true);
      if (log.kind === "DeviceNetworkEvents") {
        // Device IP exists as a column only on network rows (LocalIP); Device* process/file/registry rows have none.
        if (c.ev.src_ip) expect(contains(p, c.ev.src_ip), `${id} src_ip`).toBe(true);
        if (c.ev.dst_ip) expect(contains(p, c.ev.dst_ip), `${id} dst_ip`).toBe(true);
        if (c.ev.network?.url) expect(contains(p, c.ev.network.url), `${id} url`).toBe(true);
        if (c.ev.network?.domain && !c.ev.network.url) expect(contains(p, c.ev.network.domain), `${id} domain`).toBe(true);
      }
      if (log.kind === "DeviceEvents" && c.ev.dns?.query) expect(contains(p, c.ev.dns.query), `${id} dns`).toBe(true);
    }
  });

  it("is deterministic", () => {
    for (const c of events) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
  });

  it("same host → same DeviceId; InitiatingProcess* on child rows describes the same process as its ProcessCreated row", () => {
    const byHost = new Map<string, Set<string>>();
    for (const { log } of converted) if (log && props(log).DeviceId) {
      const p = props(log);
      const s = byHost.get(String(p.DeviceName).toLowerCase()) ?? new Set();
      s.add(String(p.DeviceId)); byHost.set(String(p.DeviceName).toLowerCase(), s);
    }
    for (const [h, ids] of byHost) expect(ids.size, h).toBe(1);

    // Corpus pairs: child row whose InitiatingProcessId + image equals a ProcessCreated row on the same device.
    const logs = converted.map(x => x.log).filter((l): l is NativeLog => !!l);
    const procRows = logs.filter(l => l.kind === "DeviceProcessEvents").map(props);
    let pairs = 0;
    for (const l of logs) {
      if (!["DeviceNetworkEvents", "DeviceFileEvents", "DeviceEvents", "DeviceRegistryEvents"].includes(l.kind)) continue;
      const ch = props(l);
      for (const pr of procRows) {
        if (pr.DeviceId !== ch.DeviceId || pr.ProcessId !== ch.InitiatingProcessId || String(pr.FileName).toLowerCase() !== String(ch.InitiatingProcessFileName).toLowerCase()) continue;
        pairs++;
        expect(ch.InitiatingProcessUniqueId, `${ch.DeviceName} ${ch.InitiatingProcessFileName}`).toBe(pr.ProcessUniqueId);
      }
    }
    console.log(`[mde] corpus process ↔ child-row pairs: ${pairs}`);

    // Events authored WITHOUT a PID still join: PID / UniqueId / SHA1 are seeded from host + image.
    const base = { ts: "2026-05-20T14:00:00.000Z", source: "edr" as const, vendor: "Microsoft Defender for Endpoint", hostname: "WS-ENG-3301", user_email: "a.jones@nexacorp.com" };
    const procEv = { ...base, id: "t-proc", event_type: "process_create", process: { name: "powershell.exe", parent_name: "cmd.exe" } } as unknown as TelemetryEvent;
    const netEv = { ...base, id: "t-net", ts: "2026-05-20T14:00:05.000Z", event_type: "net_connection", dst_ip: "203.0.113.10", dst_port: 443, process: { name: "powershell.exe", parent_name: "cmd.exe" } } as unknown as TelemetryEvent;
    const ctx = makeCtx("nexacorp");
    const pr = props(source.fromTelemetry(procEv, ctx)!), nr = props(source.fromTelemetry(netEv, ctx)!);
    expect(nr.DeviceId).toBe(pr.DeviceId);
    expect(nr.InitiatingProcessFileName).toBe(pr.FileName);
    expect(nr.InitiatingProcessId).toBe(pr.ProcessId);
    expect(nr.InitiatingProcessUniqueId).toBe(pr.ProcessUniqueId);
    expect(nr.InitiatingProcessSHA1).toBe(pr.SHA1);
    expect(nr.InitiatingProcessParentId).toBe(pr.InitiatingProcessId);
    expect(nr.InitiatingProcessCommandLine).toBe(pr.ProcessCommandLine);
  });

  it("alertInfoFor builds the joinable AlertInfo row", () => {
    const ev = converted.find(x => x.log?.kind === "AlertEvidence")!.log!;
    const info = alertInfoFor(ev)!;
    expect(validateNative(info, source.schema)).toEqual([]);
    expect(props(info).AlertId).toBe(props(ev).AlertId);
  });
});

describe("mde — use cases", () => {
  const story = converted.filter(x => x.c.origin === "story" && x.log).map(x => x.log!);
  const withInfo = (ls: NativeLog[]) => [...ls, ...ls.map(alertInfoFor).filter((l): l is NativeLog => !!l)];
  const pool = [...samples, ...withInfo(story)];
  const noise = withInfo(converted.filter(x => isNoise(x.c) && x.log).map(x => x.log!));

  it("every use case fires on card-sample / story logs; high+ stay quiet on noise", () => {
    expect(source.useCases.length).toBeGreaterThanOrEqual(6);
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("mde.")).toBe(true);
      const hits = runUseCase(uc, pool);
      const noiseHits = new Set(runUseCase(uc, noise).flatMap(h => h.records)).size;
      console.log(`[mde] ${uc.id}: ${hits.length} hit(s) on samples+stories, ${noiseHits}/${noise.length} noise records`);
      expect(hits.length, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
