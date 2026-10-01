import { describe, it, expect } from "vitest";
import { source, kindOf } from "./crowdstrike";
import { corpusFor } from "../testing/corpus";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { edrFacts } from "./edr-normalize";
import { isPrivate } from "./_cs-s1-common";
import { sampleLogs, violationsOf, convertAll, contains, isNoise, type Converted } from "./_cs-s1.testkit";

/*
 * Card samples: all 10 JSON blocks of edr-crowdstrike.md are supported kinds (FDR PR2 ×2, DnsRequest,
 * NetworkConnectIP4, PeFileWritten, UserLogon, Alerts API v2 resource, Event Streams
 * EppDetectionSummaryEvent, aidmaster, userinfo) — none skipped. The last three are card-only kinds:
 * fromTelemetry never produces them (the platform has no host-inventory / stream events).
 *
 * Documented nulls among events edrFacts marks supported (see the module header):
 *  - file deletions (ExecutableDeleted / no documented field inventory);
 *  - process events without any image name / command line (e.g. an MDE ScheduledTaskCreated row
 *    whose only process is the initiator);
 *  - network events without an IPv4 peer;
 *  - client-side logon failures (ssh to a remote bastion is not a logon on the sensor host).
 *
 * Evidence exemptions that follow the native format (card §5/§6): raw Windows ProcessRollup2,
 * DnsRequest, NetworkConnectIP4 and registry events carry NO user name (UserSid / AuthenticationId
 * only — the name comes from UserLogon); FDR context events (DNS / network / file / registry) carry
 * no command line (join ContextProcessId → PR2.TargetProcessId); NetworkConnectIP4 carries no domain
 * or URL (the name is on the DnsRequest of the same ContextProcessId); an alert carries the
 * triggering process, not its network peers.
 */
const samples = sampleLogs(source, kindOf);
const events = corpusFor(source.schema.telemetrySources);
const converted = convertAll(source, events);
const nativeVendor = (v?: string) => source.schema.vendorMatch.some(m => (v ?? "").toLowerCase().includes(m));

function documentedNull(c: Converted): string | null {
  const ev = c.c.ev;
  const f = edrFacts(ev);
  if (f.kind === "unsupported") return f.unsupportedReason ?? "unsupported";
  if (f.kind === "file" && ev.event_type === "file_delete") return "file deletion";
  if (f.kind === "process" && !f.proc.name && !f.proc.path && !f.proc.cmdline) return "process event without an image";
  if (f.kind === "network" && !f.net.remoteIp && !ev.raw?.["crowdstrike.remote_address"] && !(f.net.localIp && !isPrivate(f.net.localIp))) return "network event without an IPv4 peer";
  if (f.kind === "logon") return "client-side logon (remote server)";
  return null;
}

const NO_USER = new Set(["DnsRequest", "NetworkConnectIP4", "NetworkReceiveAcceptIP4", "AsepValueUpdate", "RegGenericValueUpdate"]);
const NO_CMD = new Set(["DnsRequest", "NetworkConnectIP4", "NetworkReceiveAcceptIP4", "AsepValueUpdate", "RegGenericValueUpdate", "PeFileWritten", "NewScriptWritten", "OoxmlFileWritten", "ZipFileWritten", "GenericFileWritten"]);
const NET_KINDS = new Set(["NetworkConnectIP4", "NetworkReceiveAcceptIP4"]);
const FILE_KINDS = new Set(["PeFileWritten", "NewScriptWritten", "OoxmlFileWritten", "ZipFileWritten", "GenericFileWritten"]);

function evidence(c: Converted): string[] {
  const { ev } = c.c;
  const log = c.log!;
  const f = edrFacts(ev);
  const out: string[] = [];
  if (f.host) out.push(f.host);
  const pr2NoUser = log.kind === "ProcessRollup2" && log.record.event_platform !== "Lin"; // only Linux PR2 carries UserName
  if (f.user && !NO_USER.has(log.kind) && !pr2NoUser) out.push(f.user);
  if (NET_KINDS.has(log.kind)) { if (ev.dst_ip) out.push(ev.dst_ip); if (ev.src_ip) out.push(ev.src_ip); }
  else if (ev.src_ip && isPrivate(ev.src_ip) && log.kind !== "alert") out.push(ev.src_ip);
  if (f.proc.cmdline && !NO_CMD.has(log.kind) && (log.kind !== "alert" || log.record.cmdline === f.proc.cmdline || !f.file.path)) out.push(f.proc.cmdline);
  if (log.kind === "ProcessRollup2" && f.proc.sha256) out.push(f.proc.sha256);
  if (FILE_KINDS.has(log.kind) && f.file.sha256) out.push(f.file.sha256);
  if (log.kind === "alert" && (f.file.sha256 ?? f.proc.sha256)) out.push((f.file.path && f.file.sha256) || f.proc.sha256 || f.file.sha256!);
  if (log.kind === "DnsRequest" && f.dns.query) out.push(f.dns.query);
  return out;
}

describe("crowdstrike — card samples", () => {
  it("every card sample is a supported kind and validates with zero violations", () => {
    expect(samples.skipped).toEqual([]);
    expect(samples.logs.length).toBe(10);
    for (const l of samples.logs) expect(violationsOf(l, source), l.kind).toEqual([]);
  });
});

describe("crowdstrike — corpus conversion", () => {
  it("converts every EDR/AV event (or returns null for a documented reason) with zero violations", () => {
    for (const c of converted) {
      expect(c.error, c.c.ev.id).toBeUndefined();
      if (!c.log) { expect(documentedNull(c), `unexpected null ${c.c.ev.id}`).not.toBeNull(); continue; }
      expect(violationsOf(c.log, source), `${c.c.ev.id} ${c.log.kind}`).toEqual([]);
      expect(c.log.timeMs).toBe(Date.parse(c.c.ev.ts));
      // FDR values are strings (card §2) — only the alert resource is typed.
      if (c.log.kind !== "alert") for (const [k, v] of Object.entries(c.log.record)) expect(typeof v, `${c.c.ev.id} ${k}`).toBe("string");
    }
  });
  it("coverage: ≥95% of CrowdStrike-authored supported events, cross-vendor floor", () => {
    const nat = converted.filter(c => nativeVendor(c.c.ev.vendor) && c.supported);
    const cross = converted.filter(c => !nativeVendor(c.c.ev.vendor) && c.supported);
    const natOk = nat.filter(c => c.log).length, crossOk = cross.filter(c => c.log).length;
    const reasons = new Map<string, number>();
    for (const c of converted.filter(x => !x.log)) { const r = documentedNull(c) ?? "?"; reasons.set(r, (reasons.get(r) ?? 0) + 1); }
    console.log(`[crowdstrike] native ${natOk}/${nat.length}, cross-vendor ${crossOk}/${cross.length}; nulls: ${JSON.stringify(Object.fromEntries(reasons))}`);
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
  it("correlates: same host → same aid; a child's ParentProcessId / an action's ContextProcessId = the process's TargetProcessId", () => {
    const logs = converted.filter(c => c.log && c.c.origin === "story").map(c => ({ c: c.c, r: c.log!.record as Record<string, string>, kind: c.log!.kind }));
    const aidByHost = new Map<string, string>();
    for (const { c, r, kind } of logs) {
      const host = `${c.companyId}:${kind === "alert" ? (r as unknown as { device: { hostname: string } }).device.hostname : r.ComputerName}`;
      const aid = kind === "alert" ? r.agent_id : r.aid;
      if (aidByHost.has(host)) expect(aidByHost.get(host), host).toBe(aid); else aidByHost.set(host, aid);
      expect(r.cid).toBe(makeCtx(c.companyId).tenant.crowdstrikeCid);
    }
    const tpids = new Set(logs.filter(l => l.kind === "ProcessRollup2").map(l => l.r.TargetProcessId));
    const linkedParents = logs.filter(l => l.kind === "ProcessRollup2" && tpids.has(l.r.ParentProcessId)).length;
    const actions = logs.filter(l => l.r.ContextProcessId && l.r.ContextBaseFileName);
    const linkedActions = actions.filter(l => tpids.has(l.r.ContextProcessId)).length;
    console.log(`[crowdstrike] story PR2 with parent PR2 in corpus: ${linkedParents}; actions linked to their PR2: ${linkedActions}/${actions.length}`);
    expect(linkedParents).toBeGreaterThan(5);
    expect(linkedActions).toBeGreaterThan(0);
  });
});

describe("crowdstrike — use cases", () => {
  const story = converted.filter(c => c.c.origin === "story" && c.log).map(c => c.log!);
  const pool = [...samples.logs, ...story];
  const noise = converted.filter(c => isNoise(c.c) && c.log).map(c => c.log!);

  it("every use case fires on card-sample / story logs; high+ stay quiet on noise", () => {
    expect(source.useCases.length).toBeGreaterThanOrEqual(6);
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("crowdstrike.")).toBe(true);
      expect(uc.sourceId).toBe("crowdstrike");
      for (const k of uc.kinds ?? []) expect(source.schema.kinds[k], `${uc.id} kind ${k}`).toBeDefined();
      const hits = runUseCase(uc, pool);
      const noiseHits = new Set(runUseCase(uc, noise).flatMap(h => h.records)).size;
      console.log(`[crowdstrike] ${uc.id}: ${hits.length} hit(s) on samples+stories, ${noiseHits}/${noise.length} noise records`);
      expect(hits.length, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
