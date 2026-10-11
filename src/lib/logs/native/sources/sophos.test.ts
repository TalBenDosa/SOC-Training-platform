import { describe, it, expect } from "vitest";
import { source, kindOf } from "./sophos";
import { edrFacts } from "./edr-normalize";
import { isPrivate } from "./_edr_mde_sophos_common";
import { corpusFor, cardSamples, type CorpusEvent } from "../testing/corpus";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";

/*
 * Card samples (edr-sophos.md): 6 of 7 blocks are supported kinds (3 SIEM events, 1 SIEM alert,
 * 1 Detections API item, 1 Data Lake row). SKIPPED: §4.7 Live Discover journal row {time, sophosPID, name} —
 * the card marks its column set UNVERIFIED and it is an on-demand query result, not a native stream.
 *
 * Documented nulls (fromTelemetry → null):
 *   - network / dns / file / registry / logon facts: Sophos has no native per-event stream for them (card §4.7, §6);
 *   - process events from Linux/macOS endpoints: only the Windows Data Lake query's column set is documented;
 *   - a process event with no image name, path or command line;
 *   - edrFacts marks the event unsupported (USB / device control, file-read scans).
 */
type Rec = Record<string, unknown>;
function deepStrings(v: unknown, out: string[] = []): string[] {
  if (v === null || v === undefined) return out;
  if (Array.isArray(v)) { for (const x of v) deepStrings(x, out); return out; }
  if (typeof v === "object") { for (const x of Object.values(v as Rec)) deepStrings(x, out); return out; }
  out.push(String(v));
  return out;
}
const contains = (r: unknown, s: string) => deepStrings(r).some(x => x.includes(s));
const isNoise = (c: CorpusEvent) => c.origin !== "story" && c.ev.expected_verdict !== "tp" && c.ev.severity !== "high" && c.ev.severity !== "critical";
const nativeVendor = (v?: string) => source.schema.vendorMatch.some(m => (v ?? "").toLowerCase().includes(m));

const raw = cardSamples(source.schema.card) as Rec[];
const timeOf = (r: Rec) => Date.parse(String(r.when ?? r.time ?? r.calendar_time));
const samples: NativeLog[] = raw.filter(r => kindOf(r)).map(r => ({ sourceId: "sophos", kind: kindOf(r)!, format: "json", record: r, timeMs: timeOf(r) }));

const events = corpusFor(source.schema.telemetrySources);
const converted = events.map(c => ({ c, log: source.fromTelemetry(c.ev, makeCtx(c.companyId)) }));

/** Events Sophos can represent natively (see header). */
function representable(ev: TelemetryEvent): boolean {
  const f = edrFacts(ev);
  if (f.kind === "detection") return true;
  if (f.kind === "process") return f.os === "Win" && !!(f.proc.name || f.proc.path || f.proc.cmdline);
  return false;
}

describe("sophos — card samples", () => {
  it("every supported card sample validates with zero violations (only the §4.7 journal row is skipped)", () => {
    const skipped = raw.filter(r => !kindOf(r));
    expect(skipped.length).toBe(1);
    expect(Object.keys(skipped[0]).sort()).toEqual(["name", "sophosPID", "time"]);
    expect(samples.map(s => s.kind).sort()).toEqual(["alert", "detection", "event", "event", "event", "running_processes_windows_sophos"]);
    for (const l of samples) expect(validateNative(l, source.schema), l.kind).toEqual([]);
  });
});

describe("sophos — corpus conversion", () => {
  it("converts every representable EDR/AV event with zero violations, null otherwise", () => {
    for (const { c, log } of converted) {
      if (!representable(c.ev)) { expect(log, `${c.ev.id} should be null`).toBeNull(); continue; }
      expect(log, `unexpected null ${c.ev.id}`).not.toBeNull();
      expect(validateNative(log!, source.schema), `${c.ev.id} ${log!.kind}`).toEqual([]);
      expect(log!.timeMs).toBe(Date.parse(c.ev.ts));
      expect(kindOf(log!.record), c.ev.id).toBe(log!.kind);
      const r = log!.record;
      if (log!.kind === "event") {
        expect(String(r.type)).toMatch(/^Event::/);
        expect(String(r.severity)).toMatch(/^(none|low|medium|high|critical)$/);
        expect(String(r.when)).toMatch(/\.000Z$/);
      }
      if (log!.kind === "detection") expect(typeof r.severity).toBe("number");
      if (log!.kind === "running_processes_windows_sophos") expect(String(r.sophos_pid)).toMatch(/^\d+:\d{18}$/);
    }
  });

  it("coverage: ≥95% of Sophos-authored representable events; cross-vendor floor", () => {
    const natAll = converted.filter(x => nativeVendor(x.c.ev.vendor));
    const nat = natAll.filter(x => representable(x.c.ev));
    const cross = converted.filter(x => !nativeVendor(x.c.ev.vendor) && representable(x.c.ev));
    const natOk = nat.filter(x => x.log).length, crossOk = cross.filter(x => x.log).length;
    const kinds: Record<string, number> = {};
    for (const x of converted) if (x.log) kinds[x.log.kind] = (kinds[x.log.kind] ?? 0) + 1;
    const why = natAll.filter(x => !representable(x.c.ev)).map(x => `${x.c.ev.id}(${edrFacts(x.c.ev).kind}/${edrFacts(x.c.ev).os})`);
    console.log(`[sophos] native ${natOk}/${nat.length} representable (of ${natAll.length} Sophos-authored; not representable: ${why.join(", ") || "none"}), cross-vendor ${crossOk}/${cross.length} representable (${converted.filter(x => !x.log).length} total nulls); kinds ${JSON.stringify(kinds)}`);
    expect(natOk / nat.length).toBeGreaterThanOrEqual(0.95);
    expect(crossOk / cross.length).toBeGreaterThanOrEqual(0.95);
  });

  it("evidence survives verbatim", () => {
    for (const { c, log } of converted) {
      if (!log) continue;
      const f = edrFacts(c.ev);
      const r = log.record;
      const id = `${c.ev.id} ${log.kind}`;
      expect(contains(r, f.host!), `${id} host`).toBe(true);
      if (f.user) expect(contains(r, f.user), `${id} user`).toBe(true);
      if (isPrivate(f.hostIp)) expect(contains(r, f.hostIp!), `${id} device ip`).toBe(true);
      if (log.kind === "event") {
        // SIEM events have no command-line field (card §6) — only hashes, paths, user, device.
        const sha = f.file.sha256 ?? f.proc.sha256;
        if (sha) expect(contains(r, sha), `${id} sha256`).toBe(true);
        if (f.file.path && !/^memory:/i.test(f.file.path)) expect(contains(r, f.file.path), `${id} file path`).toBe(true);
      } else {
        if (f.proc.cmdline) expect(contains(r, f.proc.cmdline), `${id} cmdline`).toBe(true);
        if (f.proc.sha256) expect(contains(r, f.proc.sha256), `${id} process sha256`).toBe(true);
      }
    }
  });

  it("is deterministic and keeps one endpoint_id per host", () => {
    const ids = new Map<string, Set<string>>();
    for (const c of events) {
      const a = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      expect(a).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
      if (!a) continue;
      const r = a.record as Rec;
      const eid = String(r.endpoint_id ?? (r.device as Rec | undefined)?.id);
      const host = String(r.location ?? r.meta_hostname ?? (r.device as Rec | undefined)?.entity).toLowerCase();
      ids.set(`${c.companyId}:${host}`, (ids.get(`${c.companyId}:${host}`) ?? new Set()).add(eid));
    }
    for (const [h, s] of ids) expect(s.size, h).toBe(1);
  });
});

describe("sophos — use cases", () => {
  const story = converted.filter(x => x.c.origin === "story" && x.log).map(x => x.log!);
  const pool = [...samples, ...story];
  const noise = converted.filter(x => isNoise(x.c) && x.log).map(x => x.log!);

  it("every use case fires on card-sample / story logs; high+ stay quiet on noise", () => {
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("sophos.")).toBe(true);
      const hits = runUseCase(uc, pool);
      const noiseHits = new Set(runUseCase(uc, noise).flatMap(h => h.records)).size;
      console.log(`[sophos] ${uc.id}: ${hits.length} hit(s) on samples+stories, ${noiseHits}/${noise.length} noise records`);
      expect(hits.length, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
