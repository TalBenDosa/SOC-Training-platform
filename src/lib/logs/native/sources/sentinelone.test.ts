import { describe, it, expect } from "vitest";
import { source, kindOf } from "./sentinelone";
import { corpusFor } from "../testing/corpus";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { edrFacts } from "./edr-normalize";
import { isPrivate } from "./_cs-s1-common";
import { sampleLogs, violationsOf, convertAll, contains, isNoise, type Converted } from "./_cs-s1.testkit";

/*
 * Card samples: all 6 JSON blocks of edr-sentinelone.md are supported kinds (Process Creation,
 * DNS Resolved, IP Connect, File Creation, Behavioral Indicators, Threats API element) — none
 * skipped. "Behavioral Indicators" is card-only: detections render as the Threat object.
 *
 * Documented nulls among events edrFacts marks supported (see the module header):
 *  - registry and logon events: the card lists event.type names ("Registry Value Modified",
 *    "Login") but documents no key names for them, so no record is rendered;
 *  - process events without any image name / command line;
 *  - network events without an IPv4 peer.
 *
 * Evidence: the Threats API carries the malicious process's ARGUMENTS
 * (threatInfo.maliciousProcessArguments, image path stripped — card §4.6), so for threats the
 * argument part of the command line is checked; a threat carries no network peers.
 */
const samples = sampleLogs(source, kindOf);
const events = corpusFor(source.schema.telemetrySources);
const converted = convertAll(source, events);
const nativeVendor = (v?: string) => source.schema.vendorMatch.some(m => (v ?? "").toLowerCase().includes(m));

function documentedNull(c: Converted): string | null {
  const ev = c.c.ev;
  const f = edrFacts(ev);
  if (f.kind === "unsupported") return f.unsupportedReason ?? "unsupported";
  if (f.kind === "usb") return "USB mount (device-control telemetry has no documented record in the card)";
  if (f.kind === "registry") return "registry (no documented keys)";
  if (f.kind === "logon") return "logon (no documented keys)";
  if (f.kind === "process" && !f.proc.name && !f.proc.path && !f.proc.cmdline) return "process event without an image";
  if (f.kind === "network" && !f.net.remoteIp && !(f.net.localIp && !isPrivate(f.net.localIp))) return "network event without an IPv4 peer";
  return null;
}

const argsOf = (cmd: string) => cmd.replace(/^\s*("[^"]*"|\S+)\s*/, "");

function evidence(c: Converted): string[] {
  const { ev } = c.c;
  const log = c.log!;
  const f = edrFacts(ev);
  const out: string[] = [];
  if (f.host) out.push(f.host);
  if (f.user && !["system", "root"].includes(f.user.toLowerCase()) && (log.kind !== "IP Connect" || f.proc.name)) out.push(f.user);
  if (log.kind === "IP Connect") { if (ev.dst_ip) out.push(ev.dst_ip); if (ev.src_ip) out.push(ev.src_ip); }
  else if (ev.src_ip && isPrivate(ev.src_ip) && log.kind === "threat") out.push(ev.src_ip);
  if (f.proc.cmdline) {
    if (log.kind === "threat") { const a = argsOf(f.proc.cmdline); if (a) out.push(a); } else out.push(f.proc.cmdline);
  }
  if (log.kind === "Process Creation" && f.proc.sha256) out.push(f.proc.sha256);
  if (log.kind.startsWith("File ") && log.kind !== "File Deletion" && f.file.sha256) out.push(f.file.sha256);
  if (log.kind === "threat" && (f.file.sha256 ?? f.proc.sha256)) out.push((f.file.path && f.file.sha256) || f.proc.sha256 || f.file.sha256!);
  if (log.kind.startsWith("DNS") && f.dns.query) out.push(f.dns.query);
  return out;
}

describe("sentinelone — card samples", () => {
  it("every card sample is a supported kind and validates with zero violations", () => {
    expect(samples.skipped).toEqual([]);
    expect(samples.logs.length).toBe(6);
    for (const l of samples.logs) expect(violationsOf(l, source), l.kind).toEqual([]);
  });
});

describe("sentinelone — corpus conversion", () => {
  it("converts every EDR/AV event (or returns null for a documented reason) with zero violations", () => {
    for (const c of converted) {
      expect(c.error, c.c.ev.id).toBeUndefined();
      if (!c.log) { expect(documentedNull(c), `unexpected null ${c.c.ev.id}`).not.toBeNull(); continue; }
      expect(violationsOf(c.log, source), `${c.c.ev.id} ${c.log.kind}`).toEqual([]);
      expect(c.log.timeMs).toBe(Date.parse(c.c.ev.ts));
      if (c.log.kind !== "threat") {
        // Cloud Funnel 2.0: flat object, dotted keys, epoch-ms number + ISO string for the same instant.
        for (const v of Object.values(c.log.record)) expect(v === null || typeof v !== "object", c.c.ev.id).toBe(true);
        expect(c.log.record["event.time"]).toBe(c.log.timeMs);
        expect(c.log.record.timestamp).toBe(new Date(c.log.timeMs).toISOString());
      }
    }
  });
  it("coverage: ≥95% of SentinelOne-authored supported events, cross-vendor floor", () => {
    const nat = converted.filter(c => nativeVendor(c.c.ev.vendor) && c.supported);
    const cross = converted.filter(c => !nativeVendor(c.c.ev.vendor) && c.supported);
    const natOk = nat.filter(c => c.log).length, crossOk = cross.filter(c => c.log).length;
    const reasons = new Map<string, number>();
    for (const c of converted.filter(x => !x.log)) { const r = documentedNull(c) ?? "?"; reasons.set(r, (reasons.get(r) ?? 0) + 1); }
    console.log(`[sentinelone] native ${natOk}/${nat.length}, cross-vendor ${crossOk}/${cross.length}; nulls: ${JSON.stringify(Object.fromEntries(reasons))}`);
    expect(natOk / nat.length).toBeGreaterThanOrEqual(0.95);
    expect(crossOk / cross.length).toBeGreaterThanOrEqual(0.9);
  });
  it("evidence survives verbatim (host, user, IPs, command line, hashes, DNS name)", () => {
    const misses: string[] = [];
    for (const c of converted) {
      if (!c.log) continue;
      for (const v of evidence(c)) if (!contains(c.log.record, v)) misses.push(`${c.c.ev.id} ${c.log.kind} missing ${v}`);
    }
    expect(misses).toEqual([]);
  });
  it("is deterministic", () => {
    for (const c of events) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
  });
  it("correlates: same host → same agent.uuid; child's src.process.uid / action's process.unique.key = tgt.process.uid; storyline shared", () => {
    const logs = converted.filter(c => c.log && c.c.origin === "story").map(c => ({ c: c.c, r: c.log!.record as Record<string, unknown>, kind: c.log!.kind }));
    const byHost = new Map<string, string>();
    for (const { c, r, kind } of logs) {
      const host = kind === "threat" ? (r.agentRealtimeInfo as Record<string, string>).agentComputerName : (r["endpoint.name"] as string);
      const uuid = kind === "threat" ? (r.agentRealtimeInfo as Record<string, string>).agentUuid : (r["agent.uuid"] as string);
      const key = `${c.companyId}:${host}`;
      if (byHost.has(key)) expect(byHost.get(key), key).toBe(uuid); else byHost.set(key, uuid);
    }
    // Rendering is per event (stateless), so the chain root is known only up to the parent: storylines are
    // fully consistent inside an incident (TelemetryEvent.incident_id) and for chains whose root is the
    // parent (parent started by a shell); deeper chains outside an incident — and DNS/IP/file events whose
    // actor's parent is not authored — start a new storyline (counted, not asserted).
    const created = logs.filter(l => l.kind === "Process Creation");
    const tgt = new Map(created.map(l => [l.r["tgt.process.uid"] as string, l]));
    const consistentScope = (parent: (typeof logs)[number], child: (typeof logs)[number]) =>
      (!!parent.c.ev.incident_id && parent.c.ev.incident_id === child.c.ev.incident_id) || parent.r["tgt.process.isStorylineRoot"] === true;
    let deep = 0;
    const childLinks = created.filter(l => tgt.has(l.r["src.process.uid"] as string));
    for (const l of childLinks) {
      const parent = tgt.get(l.r["src.process.uid"] as string)!;
      if (consistentScope(parent, l)) expect(l.r["src.process.storyline.id"], String(l.c.ev.id)).toBe(parent.r["tgt.process.storyline.id"]);
      else if (l.r["src.process.storyline.id"] !== parent.r["tgt.process.storyline.id"]) deep++;
    }
    const actions = logs.filter(l => l.kind !== "Process Creation" && l.kind !== "threat" && l.r["process.unique.key"]);
    const linked = actions.filter(l => tgt.has(l.r["process.unique.key"] as string));
    for (const l of linked) {
      const proc = tgt.get(l.r["process.unique.key"] as string)!;
      if (consistentScope(proc, l)) expect(l.r["src.process.storyline.id"], String(l.c.ev.id)).toBe(proc.r["tgt.process.storyline.id"]);
      else if (l.r["src.process.storyline.id"] !== proc.r["tgt.process.storyline.id"]) deep++;
    }
    console.log(`[sentinelone] links outside an incident whose chain root is not visible in the event (new storyline): ${deep}`);
    const stories = new Set(created.map(l => l.r["tgt.process.storyline.id"]));
    const threatsLinked = logs.filter(l => l.kind === "threat" && stories.has((l.r.threatInfo as Record<string, string>).storyline)).length;
    console.log(`[sentinelone] child→parent links ${childLinks.length}; actions linked to their Process Creation ${linked.length}/${actions.length}; threats sharing a telemetry storyline ${threatsLinked}`);
    expect(childLinks.length).toBeGreaterThan(5);
    expect(linked.length).toBeGreaterThan(0);
    expect(threatsLinked).toBeGreaterThan(0);
  });
});

describe("sentinelone — use cases", () => {
  const story = converted.filter(c => c.c.origin === "story" && c.log).map(c => c.log!);
  const pool = [...samples.logs, ...story];
  const noise = converted.filter(c => isNoise(c.c) && c.log).map(c => c.log!);

  it("every use case fires on card-sample / story logs; high+ stay quiet on noise", () => {
    expect(source.useCases.length).toBeGreaterThanOrEqual(6);
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("sentinelone.")).toBe(true);
      expect(uc.sourceId).toBe("sentinelone");
      for (const k of uc.kinds ?? []) expect(source.schema.kinds[k], `${uc.id} kind ${k}`).toBeDefined();
      const hits = runUseCase(uc, pool);
      const noiseHits = new Set(runUseCase(uc, noise).flatMap(h => h.records)).size;
      console.log(`[sentinelone] ${uc.id}: ${hits.length} hit(s) on samples+stories, ${noiseHits}/${noise.length} noise records`);
      expect(hits.length, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
