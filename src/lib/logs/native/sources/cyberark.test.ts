import { describe, it, expect } from "vitest";
import { source, kindOf, cefLine } from "./cyberark";
import { corpusFor, type CorpusEvent } from "../testing/corpus";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { sampleLogs, violationsOf, convertAll, flatSamples, isNoise } from "./_dnsHostItsm.testkit";
import { buildPamVaultAbuseScenario } from "@/lib/sim/scenario-packs/pamVaultAbuse";

/*
 * Card samples: all 7 (codes 4, 7, 295, 300, 411, 302, 38) validate; none skipped.
 *
 * Inputs: every corpus "iam" event (CyberArk PAM checkouts / PSM sessions / check-ins of the
 * QuantumBank stories and noise; the Okta / Entra "iam" rows are identity-provider records and
 * render as null here) plus the two CyberArk records of the PAM vault-abuse scenario pack.
 */
const samples = sampleLogs(source, kindOf);
const packEvents: CorpusEvent[] = buildPamVaultAbuseScenario().events
  .filter(ev => /cyberark/i.test(ev.vendor ?? ""))
  .map(ev => ({ ev, origin: "story" as const, companyId: "nexacorp" }));
const events = [...corpusFor(source.schema.telemetrySources), ...packEvents];
const converted = convertAll(source, events);
const isCyberArk = (c: CorpusEvent) => /cyberark/i.test(c.ev.vendor ?? "");
const rec = (l: NativeLog) => l.record as Record<string, string>;
const pick = (raw: Record<string, unknown>, ...keys: string[]) => keys.map(k => raw[k]).find(v => v !== undefined && v !== "") as string | undefined;

describe("cyberark — card samples", () => {
  it("every card sample validates with zero violations", () => {
    expect(samples.skipped).toEqual([]);
    expect(samples.logs.length).toBe(flatSamples(source.schema.card).length);
    for (const l of samples.logs) expect(violationsOf(l, source), l.kind).toEqual([]);
  });
  it("the rebuilt CEF line equals the card's raw line (XSL quoting rules)", () => {
    for (const l of samples.logs) {
      const { raw, ...r } = rec(l);
      expect(cefLine(r as Record<string, string>), l.kind).toBe(raw);
    }
  });
});

describe("cyberark — conversion", () => {
  it("every CyberArk event converts with zero violations; other iam vendors are null", () => {
    for (const c of converted) {
      expect(c.error, c.c.ev.id).toBeUndefined();
      if (!isCyberArk(c.c)) { expect(c.log, c.c.ev.id).toBeNull(); continue; }
      expect(c.log, c.c.ev.id).not.toBeNull();
      expect(violationsOf(c.log!, source), c.c.ev.id).toEqual([]);
      expect(c.log!.timeMs).toBe(Date.parse(c.c.ev.ts));
    }
    const ca = converted.filter(c => isCyberArk(c.c));
    console.log(`[cyberark] ${ca.filter(c => c.log).length}/${ca.length} CyberArk events (${packEvents.length} from the scenario pack); codes ${JSON.stringify(ca.reduce((a, c) => (c.log ? { ...a, [c.log.kind]: (a[c.log.kind] ?? 0) + 1 } : a), {} as Record<string, number>))}`);
    expect(ca.length).toBeGreaterThanOrEqual(10);
  });
  it("native shape: Cyber-Ark / Vault header, strings only, labels always printed, rawLine rebuilt from the record", () => {
    for (const { log } of converted) {
      if (!log) continue;
      const r = rec(log);
      expect(r.DeviceVendor).toBe("Cyber-Ark");
      expect(r.DeviceProduct).toBe("Vault");
      expect(r.SignatureID).toBe(log.kind);
      expect(r.act).toBe(r.Name);
      expect(["5", "7"]).toContain(r.Severity);
      for (const [k, v] of Object.entries(r)) expect(typeof v, k).toBe("string");
      expect(r.timestamp).toMatch(/^[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}$/);
      if (r.fname) expect(r.fname).toMatch(/^Root\\(Operating System|Database|Application|Network Device)-[A-Za-z0-9]+-.+-.+$/);
      expect(log.rawLine).toBe(cefLine(r));
      expect(log.rawLine).toMatch(/^[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} VAULT01 CEF:0\|Cyber-Ark\|Vault\|/);
      expect(log.rawLine).not.toMatch(/undefined|NaN|\[object Object\]/);
    }
  });
  it("evidence survives: Vault user, station, account, safe, reason, request id", () => {
    for (const { c, log } of converted) {
      if (!log) continue;
      const r = rec(log), raw = c.ev.raw ?? {};
      const cpm = ["22", "24", "31", "38", "57", "60"].includes(log.kind);
      const psm = ["300", "301", "302", "303", "359", "361", "411"].includes(log.kind);
      if (c.ev.user_email && !cpm) expect(r.suser, c.ev.id).toBe(c.ev.user_email.split("@")[0]);
      if (cpm) expect(r.suser).toBe("PasswordManager");
      const station = pick(raw, "cyberark.station") ?? c.ev.src_ip;
      if (station && !cpm && !psm) expect(r.shost, c.ev.id).toBe(station);
      if (psm && raw["cyberark.station"]) expect(r.shost, c.ev.id).toBe(raw["cyberark.station"]);
      const account = pick(raw, "pam.account.name", "ca.account", "pam.account.name");
      if (account) {
        expect(r.duser, c.ev.id).toBe(account.split("@")[0]);
        if (account.includes("@")) expect(r.dhost, c.ev.id).toBe(account.split("@")[1]);
      }
      const safe = pick(raw, "cyberark.safe", "ca.safe", "pam.vault.name");
      if (safe) expect(r.cs2, c.ev.id).toBe(safe);
      const reason = pick(raw, "cyberark.reason");
      if (reason) expect(r.reason, c.ev.id).toBe(reason);
      const req = pick(raw, "access.request.id");
      if (req && req !== "-") expect(r.cn1, c.ev.id).toBe(req.match(/\d+/)![0]); else expect(r.cn1, c.ev.id).toBeUndefined();
    }
  });
  it("a PSM session's records share one externalId GUID; the 295 reveal has none", () => {
    for (const { log } of converted) {
      if (!log) continue;
      if (["300", "302"].includes(log.kind)) expect(rec(log).externalId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      if (log.kind === "295") expect(rec(log).externalId).toBeUndefined();
    }
    const ctx = makeCtx("quantumbank");
    const base = { id: "fx-psm", ts: "2026-06-25T13:11:00.000Z", source: "iam", vendor: "CyberArk PAM", event_type: "privileged_operation", user_email: "e.steiner@quantumbank.ch",
      raw: { "pam.vault.name": "CoreBankingAdmins", "pam.account.name": "svc-corebanking-admin@corebanking-db01", "event.action": "session-start" } } as never;
    const start = source.fromTelemetry(base, ctx)!;
    const end = source.fromTelemetry({ ...(base as object), id: "fx-psm-end", ts: "2026-06-25T14:19:00.000Z", raw: { ...(base as { raw: object }).raw, "event.action": "session-end" } } as never, ctx)!;
    expect([start.kind, end.kind]).toEqual(["300", "302"]);
    expect(rec(end).externalId).toBe(rec(start).externalId);
    expect(rec(start).shost).toBe("10.100.0.45");   // PSM server, not the user's workstation
    expect(rec(start).app).toBe("RDP");
  });
  it("is deterministic", () => {
    for (const c of events) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
  });
});

describe("cyberark — use cases", () => {
  const card = samples.logs;
  const byCode = (code: string) => card.find(l => l.kind === code)!;
  const clone = (l: NativeLog, timeMs: number, patch: Record<string, string>): NativeLog => ({ ...l, timeMs, record: { ...l.record, ...patch } });
  const fixtures: NativeLog[] = [
    // three failed Vault logons from one station inside 90 s (card §4.1)
    ...[0, 40, 90].map(s => clone(byCode("4"), 10_000_000 + s * 1000, {})),
    // five different account objects revealed by one user inside an hour (card §4.3)
    ...["adm.yoav", "adm.dana", "adm.itay", "adm.maya", "adm.ron"].map((u, i) => clone(byCode("295"), 20_000_000 + i * 300_000, { fname: `Root\\Operating System-WinDomain-nexacorp.local-${u}`, duser: u })),
    // the card's logon record as a Vault group change
    clone(byCode("7"), 30_000_000, { SignatureID: "265", Name: "Add Group Member", act: "Add Group Member", cs1: "noa.katz" }),
  ];
  for (const f of fixtures) f.kind = rec(f).SignatureID;
  const story = converted.filter(c => c.log && c.c.origin === "story").map(c => c.log!);
  const noise = converted.filter(c => c.log && isNoise(c.c)).map(c => c.log!);
  const pool = [...card, ...story, ...fixtures];
  it("every use case fires on card-sample / story / fixture logs; high ones stay quiet on noise", () => {
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("cyberark.")).toBe(true);
      const hits = runUseCase(uc, pool);
      const storyHits = runUseCase(uc, story).length;
      const noiseHits = runUseCase(uc, noise).length;
      console.log(`[cyberark] ${uc.id}: ${hits.length} hit(s) on samples+stories+fixtures (${storyHits} on stories, ${noiseHits}/${noise.length} on noise)`);
      expect(hits.length, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
  it("the off-hours dual-control bypass of the vault-abuse pack is caught; its sanctioned PSM break-glass is not", () => {
    const pack = converted.filter(c => c.log && c.c.ev.id.startsWith("evt_pva_")).map(c => c.log!);
    const bypass = source.useCases.find(u => u.id === "cyberark.tier0_retrieve_no_dual_control")!;
    const hits = runUseCase(bypass, pack).flatMap(h => h.records.map(i => pack[i].kind));
    expect(hits).toEqual(["295"]);
  });
});
