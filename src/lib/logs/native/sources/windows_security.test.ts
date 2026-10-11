import { describe, it, expect } from "vitest";
import { source, kindOf } from "./windows_security";
import { corpusFor } from "../testing/corpus";
import { runUseCase } from "../engine";
import { sampleLogs, violationsOf, convertAll, contains, flatSamples, isNoise, type Converted } from "./_dnsHostItsm.testkit";

/*
 * Card samples: docs/log-schemas/windows-security.md §4 ships JSON samples for
 * 4625, 4776, 4740, 4771, 4688, 4769, 4768, 4624, 4672, 7045, 4720, 4728, 5136, 4662
 * (the 4697 twin is a table, not a JSON block, so it is not parsed as a sample).
 * All parsed samples are supported kinds — none skipped.
 *
 * Documented nulls (converter returns null, event keeps the legacy view — never a faked record):
 *  - An onprem_ad event with no resolvable EventID (an MDI alert filed under source "ad").
 *  - An event id this card does not document a shape for: share access 5140 / 5145 / 4663,
 *    TerminalServices 1149 / 21 / 23, TaskScheduler 201, PowerShell 4104, 4798, 4778/4779,
 *    group-attribute changes 4737 / 4755 / 4735.
 */
const samples = sampleLogs(source, kindOf);
const events = corpusFor(source.schema.telemetrySources);
const converted = convertAll(source, events);
const SUPPORTED = new Set(Object.keys(source.schema.kinds));
const authoredId = (c: Converted) => (c.c.ev.raw?.["winlog.event_id"] ?? c.c.ev.raw?.["event.code"]) as string | undefined;
const supportable = converted.filter(c => { const id = authoredId(c); return id !== undefined && SUPPORTED.has(String(id)); });

describe("windows_security — card samples", () => {
  it("every supported card sample validates with zero violations", () => {
    expect(samples.skipped).toEqual([]);
    expect(samples.logs.length).toBe(flatSamples(source.schema.card).length);
    for (const l of samples.logs) expect(violationsOf(l, source), `event ${l.kind}`).toEqual([]);
  });
  it("kindOf classifies by EventID and rejects undocumented ids", () => {
    expect(kindOf({ EventID: 4624 })).toBe("4624");
    expect(kindOf({ EventID: 5140 })).toBeNull();
    expect(kindOf({})).toBeNull();
  });
});

describe("windows_security — corpus conversion", () => {
  it("every converted event validates with zero violations and is well-formed", () => {
    for (const c of converted) {
      expect(c.error, c.c.ev.id).toBeUndefined();
      if (!c.log) continue;
      expect(violationsOf(c.log, source), `${c.c.ev.id} → ${c.log.kind}`).toEqual([]);
      expect(c.log.timeMs).toBe(Date.parse(c.c.ev.ts));
      // Windows is shown as the SIEM's normalised JSON — not raw EVTX XML (Tal, 2026-10-03).
      expect(c.log.format).toBe("json");
      expect(c.log.rawLine).toBeUndefined();
      expect(typeof c.log.record.EventID).toBe("number");
      expect(typeof c.log.record.EventRecordID).toBe("number");
      expect(String(c.log.record.TimeCreated)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$/);
      // EventData values are strings (only EventID / EventRecordID are numbers).
      for (const [key, v] of Object.entries(c.log.record)) {
        if (key === "EventID" || key === "EventRecordID") continue;
        expect(typeof v, `${c.c.ev.id} ${key}`).toBe("string");
      }
    }
  });
  it("coverage: ≥95% of supportable-id events render; unsupported ids become null", () => {
    const ok = supportable.filter(c => c.log).length;
    const nullTypes: Record<string, number> = {};
    for (const c of converted) if (!c.log) { const id = authoredId(c) ?? "(no id)"; nullTypes[id] = (nullTypes[id] ?? 0) + 1; }
    console.log(`[windows_security] supportable ${ok}/${supportable.length}; total rendered ${converted.filter(c => c.log).length}/${converted.length}; nulls by id ${JSON.stringify(nullTypes)}`);
    for (const c of supportable) if (!c.log) console.log(`[windows_security] supportable null: ${c.c.ev.id} id=${authoredId(c)}`);
    expect(ok / supportable.length).toBeGreaterThanOrEqual(0.95);
  });
  it("evidence survives verbatim (user, SIDs, IPs, service name, status, group, process)", () => {
    for (const { c, log } of converted) {
      if (!log) continue;
      const ev = c.ev, rec = log.record, k = log.kind;
      // Host-logged kinds (logon / process / service) carry the acting host in Computer; DC-logged
      // kinds (Kerberos / directory / lockout / account mgmt) carry the DC, so the workstation shows
      // elsewhere — don't require ev.hostname in those records.
      const hostLogged = ["4624", "4625", "4634", "4648", "4672", "4688", "4697", "7045"];
      if (ev.hostname && hostLogged.includes(k) && !/^\d+\.\d+\.\d+\.\d+$/.test(ev.hostname) && !ev.raw?.["winlog.computer_name"])
        expect(contains(rec, ev.hostname.split(".")[0]), `${ev.id} host`).toBe(true);
      // user — any authored form (email local-part, user.name sam, authored TargetUserName).
      const email = ev.user_email ?? ev.user?.email;
      const userForms = [email?.split("@")[0], (ev.raw?.["user.name"] as string | undefined)?.split("\\").pop(),
        ev.raw?.["winlog.event_data.TargetUserName"] as string | undefined, ev.raw?.["winlog.event_data.SubjectUserName"] as string | undefined]
        .filter((x): x is string => !!x);
      const userKinds = ["4624", "4625", "4634", "4768", "4769", "4771", "4776", "4720", "4722", "4723", "4724", "4725", "4726", "4740", "4662", "4672", "1102"];
      if (userForms.length && userKinds.includes(k)) expect(userForms.some(u => contains(rec, u)), `${ev.id} user`).toBe(true);
      // source IP (member-server events keep plain IPv4; DC Kerberos events keep the ::ffff: form, still contains the dotted octets).
      const ipKinds = ["4624", "4625", "4648", "4768", "4769", "4771"];
      // Skip when the authored record explicitly says no source ("-" = local / console logon).
      const authIp = ev.raw?.["winlog.event_data.IpAddress"] as string | undefined;
      if (ev.src_ip && ipKinds.includes(k) && /^\d/.test(ev.src_ip) && authIp !== "-") expect(contains(rec, ev.src_ip), `${ev.id} src_ip`).toBe(true);
      // service name on a TGS request
      const svc = ev.raw?.["winlog.event_data.ServiceName"] as string | undefined;
      if (k === "4769" && svc) expect(contains(rec, svc), `${ev.id} ServiceName`).toBe(true);
      // process command line on 4688
      if (k === "4688" && ev.process?.cmdline) expect(contains(rec, ev.process.cmdline), `${ev.id} cmdline`).toBe(true);
      // authored ticket encryption type (the Kerberoasting / AS-REP RC4 signal)
      const tet = ev.raw?.["winlog.event_data.TicketEncryptionType"] as string | undefined;
      if ((k === "4768" || k === "4769") && tet) expect(contains(rec, tet.toLowerCase()), `${ev.id} TicketEncryptionType`).toBe(true);
    }
  });
  it("conversion is deterministic", () => {
    const again = convertAll(source, events);
    for (let i = 0; i < converted.length; i++) {
      expect(JSON.stringify(again[i].log), converted[i].c.ev.id).toBe(JSON.stringify(converted[i].log));
    }
  });
  it("the 4740 caller computer / IP sits in TargetDomainName, not an invented CallerComputerName field", () => {
    const locks = converted.filter(c => c.log?.kind === "4740");
    expect(locks.length).toBeGreaterThan(0);
    for (const c of locks) {
      expect(Object.keys(c.log!.record)).not.toContain("CallerComputerName");
      // The caller computer name (or, when the authored event only had an IP, that IP) rides in TargetDomainName.
      const caller = c.c.ev.raw?.["winlog.event_data.CallerComputerName"] as string | undefined;
      const expected = caller ?? (c.c.ev.src_ip ? `\\\\${c.c.ev.src_ip}` : undefined);
      if (expected) expect(String(c.log!.record.TargetDomainName)).toContain(expected.replace(/^\\\\/, ""));
    }
  });
});

describe("windows_security — use cases", () => {
  const attack = converted.filter(c => c.c.origin === "story" && c.log).map(c => c.log!);
  const sampleLogsList = samples.logs;
  const noise = converted.filter(c => isNoise(c.c) && c.log).map(c => c.log!);

  it("each use case fires on an attack / card log; high+critical stay quiet on noise", () => {
    const pool = [...attack, ...sampleLogsList];
    const report: Record<string, { attack: number; noise: number; sev: string }> = {};
    for (const uc of source.useCases) {
      const a = runUseCase(uc, pool).length;
      const n = runUseCase(uc, noise).reduce((s, h) => s + h.records.length, 0);
      report[uc.id] = { attack: a, noise: n, sev: uc.severity };
    }
    console.log(`[windows_security] use cases (noise pool ${noise.length}):`, JSON.stringify(report, null, 1));
    for (const uc of source.useCases) expect(report[uc.id].attack, `${uc.id} should fire`).toBeGreaterThan(0);
    for (const uc of source.useCases) {
      if (uc.severity === "high" || uc.severity === "critical") {
        expect(report[uc.id].noise / Math.max(noise.length, 1), `${uc.id} noise rate`).toBeLessThan(0.02);
      }
    }
  });
});
