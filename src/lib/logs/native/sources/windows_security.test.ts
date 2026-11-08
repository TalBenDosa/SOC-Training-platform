import { describe, it, expect } from "vitest";
import { source, kindOf } from "./windows_security";
import { corpusFor } from "../testing/corpus";
import { makeCtx } from "../ctx";
import type { TelemetryEvent } from "@/lib/sim/types";
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
 *  - An event id with no documented shape (card or Microsoft's per-event reference):
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
    // Share / file access, privilege use, task registration and PnP follow Microsoft's per-event reference.
    for (const id of [5140, 5145, 4663, 4673, 4698, 6416]) expect(kindOf({ EventID: id })).toBe(String(id));
    expect(kindOf({ EventID: 4104 })).toBeNull();
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

// Sdema review 2026-11-08 (K5, K2): the spray a lockout row closes is in the record set, at its real pace.
describe("windows_security: the authentication burst a story row carries", () => {
  const ctx = makeCtx("nexacorp");
  const users = ["j.chen", "r.avraham", "m.levi", "d.cohen", "s.patel", "a.kaplan", "l.ferreira", "t.harris", "m.torres"];
  const attempts = [
    ...users.map((u, i) => ({ at: -150 + i * 7, user: `${u}@nexacorp.com` })),
    ...users.map((u, i) => ({ at: -76 + i * 7, user: `${u}@nexacorp.com`, ...(u === "m.torres" ? { status: "0x0" } : {}) })),
    { at: -0.4, user: "j.chen@nexacorp.com" },
  ];
  const lockout = {
    id: "burst-4740", ts: "2026-05-10T17:02:30.000Z", source: "ad", vendor: "Windows Security", event_type: "account_lockout", hostname: "SRV-NXC-DC01",
    raw: { "event.code": "4740", "winlog.event_data.TargetUserName": "j.chen", "winlog.event_data.CallerComputerName": "WIN-3VQ8KD2RLMP" },
    _burst: { host: "SRV-NXC-RDS01", dc: true, ip: "185.220.101.45", workstation: "WIN-3VQ8KD2RLMP", attempts },
  } as unknown as TelemetryEvent;
  const rows = source.companions!(lockout, ctx).map(l => l.record as Record<string, unknown>);
  const own = source.fromTelemetry(lockout, ctx)!.record as Record<string, unknown>;
  it("one 4625 per failed guess on the RDS host with every field an analyst proves a spray from", () => {
    const fails = rows.filter(r => r.EventID === 4625);
    expect(fails).toHaveLength(18);
    expect(new Set(fails.map(r => r.TargetUserName)).size).toBe(9);
    for (const r of fails) expect(r).toMatchObject({ Computer: "SRV-NXC-RDS01.nexacorp.com", Status: "0xc000006d", SubStatus: "0xc000006a", FailureReason: "%%2313",
      LogonType: "3", LogonProcessName: "NtLmSsp ", AuthenticationPackageName: "NTLM", WorkstationName: "WIN-3VQ8KD2RLMP", IpAddress: "185.220.101.45", IpPort: "0", TargetDomainName: "NEXACORP" });
    const span = (Date.parse(String(fails.at(-1)!.TimeCreated)) - Date.parse(String(fails[0].TimeCreated))) / 1000;
    expect(span).toBeGreaterThan(120);
    expect(span).toBeLessThanOrEqual(180);
  });
  it("the DC validated every attempt (4776), the success is a 4624 type 3, and the lockout follows the third j.chen failure", () => {
    const dc = rows.filter(r => r.EventID === 4776);
    expect(dc).toHaveLength(19);
    expect(dc.every(r => r.Computer === "SRV-NXC-DC01.nexacorp.com" && r.Workstation === "WIN-3VQ8KD2RLMP")).toBe(true);
    expect(rows.filter(r => r.EventID === 4624)).toEqual([expect.objectContaining({ TargetUserName: "m.torres", LogonType: "3", IpAddress: "185.220.101.45" })]);
    const chen = rows.filter(r => r.EventID === 4625 && r.TargetUserName === "j.chen");
    expect(chen).toHaveLength(3);
    expect(Date.parse(String(own.TimeCreated))).toBeGreaterThan(Date.parse(String(chen[2].TimeCreated)));
    expect(own).toMatchObject({ EventID: 4740, TargetUserName: "j.chen", TargetDomainName: "WIN-3VQ8KD2RLMP" });
    // Record ids climb on each host, and the DC's run ends below the 4740's own.
    const ids = dc.map(r => Number(r.EventRecordID));
    expect(ids).toEqual([...ids].sort((a, b) => a - b));
    expect(ids.at(-1)!).toBeLessThan(Number(own.EventRecordID));
  });
  it("a row with no burst has no companions", () => {
    expect(source.companions!({ ...lockout, _burst: undefined } as unknown as TelemetryEvent, ctx)).toEqual([]);
  });
});

describe("windows_security: renderer defaults an analyst would catch", () => {
  const ctx = makeCtx("nexacorp");
  const ev = (id: string, raw: Record<string, unknown>, extra: Partial<TelemetryEvent> = {}) =>
    source.fromTelemetry({ id, ts: "2026-05-10T09:00:00.000Z", source: "ad", vendor: "Windows Security", event_type: "auth_failure", hostname: "SRV-NXC-FS01", ...extra, raw } as TelemetryEvent, ctx)!.record as Record<string, unknown>;
  it("a batch-logon 4625 made by the computer has SubjectLogonId 0x3e7 and its caller's pid", () => {
    const r = ev("d1", { "event.code": "4625", "winlog.event_data.TargetUserName": "svc-report", "winlog.event_data.LogonType": "4",
      "winlog.event_data.SubjectUserSid": "S-1-5-18", "winlog.event_data.SubjectUserName": "SRV-NXC-FS01$", "winlog.event_data.ProcessName": "C:\\Windows\\System32\\svchost.exe" });
    expect(r.SubjectLogonId).toBe("0x3e7");
    expect(r.ProcessId).not.toBe("0x0");
  });
  it("a foreign domain SID is re-homed onto the organization's domain (RID kept)", () => {
    const r = ev("d2", { "event.code": "4720", "winlog.event_data.TargetUserName": "svc-backup2", "winlog.event_data.TargetSid": "S-1-5-21-1111111111-2222222222-3333333333-1353" }, { event_type: "account_create" });
    expect(r.TargetSid).toBe("S-1-5-21-3421479547-3897544621-1789562108-1353");
  });
  it("a Remote Desktop 4624 is made by winlogon.exe, and WorkstationName is never an FQDN", () => {
    const r = ev("d3", { "event.code": "4624", "winlog.event_data.TargetUserName": "administrator", "winlog.event_data.LogonType": "10", "winlog.event_data.WorkstationName": "SRV-NXC-DC01.nexacorp.com", "winlog.event_data.IpAddress": "10.10.20.150" }, { event_type: "auth_success" });
    expect(r.ProcessName).toBe("C:\\Windows\\System32\\winlogon.exe");
    expect(r.WorkstationName).toBe("SRV-NXC-DC01");
  });
});
