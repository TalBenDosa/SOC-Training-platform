// Tal's QA report (2026-11-12), section 1 "Active Directory / Windows Security": every rule pinned over the
// whole corpus (every company's pool, the benign pool and every story), so a new row cannot bring one back.
import { describe, expect, it } from "vitest";
import { source } from "./windows_security";
import { corpus } from "../testing/corpus";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { windowsFeedSource } from "@/lib/logs/windowsFeedSource";
import { windowsEventSections, windowsValueMeaning } from "@/lib/logs/windowsEventView";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";

type Rec = Record<string, string | number>;
const rows = corpus().filter(c => source.schema.telemetrySources.includes(c.ev.source as string));
const rendered: { c: (typeof rows)[number]; log: NativeLog; r: Rec }[] = [];
for (const c of rows) {
  const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
  if (log) rendered.push({ c, log, r: log.record as Rec });
}
const of = (...ids: string[]) => rendered.filter(x => ids.includes(String(x.r.EventID)));
const isDc = (h: string) => /(^|[-_])DC\d*($|[-_.])/i.test(h);

describe("Windows Security QA rules (2026-11-12)", () => {
  it("renders a real share of the corpus", () => expect(rendered.length).toBeGreaterThan(150));

  it("the wire form is EVTX XML and no invented field rides in the record", () => {
    for (const { c, log, r } of rendered) {
      expect(log.format, c.ev.id).toBe("xml");
      expect(log.rawLine, c.ev.id).toContain(`<EventRecordID>${r.EventRecordID}</EventRecordID>`);
      expect(Object.keys(r), c.ev.id).not.toContain("KeywordsText");
    }
  });

  it("a local logon (2 / 7 / 11) is User32 / Negotiate from 127.0.0.1 port 0, by the computer", () => {
    const local = of("4624", "4625").filter(x => ["2", "7", "11"].includes(String(x.r.LogonType)));
    expect(local.length).toBeGreaterThan(5);
    for (const { c, r } of local) {
      expect([r.LogonProcessName, r.AuthenticationPackageName, r.IpAddress, r.IpPort], c.ev.id).toEqual(["User32 ", "Negotiate", "127.0.0.1", "0"]);
      expect([String(r.SubjectUserName).endsWith("$"), r.SubjectUserSid, r.SubjectLogonId], c.ev.id).toEqual([true, "S-1-5-18", "0x3e7"]);
    }
  });

  it("a service / batch logon is Advapi / Negotiate with no network address", () => {
    for (const { c, r } of of("4624", "4625").filter(x => ["4", "5"].includes(String(x.r.LogonType)))) {
      expect([r.LogonProcessName, r.AuthenticationPackageName, r.IpAddress, r.IpPort], c.ev.id).toEqual(["Advapi  ", "Negotiate", "-", "-"]);
      if (r.LogonType === "5") expect(r.ProcessName, c.ev.id).toBe("C:\\Windows\\System32\\services.exe");
    }
  });

  it("a 4625's Failure Information follows its SubStatus (an expired password is %%2309 / 0xc000006e)", () => {
    const want: Record<string, [string, string]> = { "0xc0000064": ["0xc000006d", "%%2313"], "0xc000006a": ["0xc000006d", "%%2313"], "0xc0000071": ["0xc000006e", "%%2309"], "0xc0000072": ["0xc000006e", "%%2310"] };
    for (const { c, r } of of("4625")) {
      expect(String(r.FailureReason), c.ev.id).toMatch(/^%%\d{4}$/);
      const w = want[String(r.SubStatus)];
      if (w) expect([r.Status, r.FailureReason], c.ev.id).toEqual(w);
    }
    expect(of("4625").some(x => x.r.FailureReason === "%%2309")).toBe(true);
  });

  it("a machine Subject is SYSTEM's session; a person's Subject carries their own SID and a real session", () => {
    for (const { c, r } of rendered) {
      const name = r.SubjectUserName;
      if (name === undefined || name === "-") continue;
      const nb = makeCtx(c.companyId).netbios.toUpperCase();
      expect(String(name).toUpperCase(), c.ev.id).not.toBe(`${nb}$`);
      if (String(name).endsWith("$")) {
        expect([r.SubjectUserSid, String(r.SubjectLogonId).toLowerCase()], c.ev.id).toEqual(["S-1-5-18", "0x3e7"]);
      } else if (!/^(system|local service|network service|anonymous logon)$/i.test(String(name))) {
        expect(r.SubjectUserSid, `${c.ev.id} ${name}`).not.toBe("S-1-5-18");
        expect(String(r.SubjectLogonId), c.ev.id).not.toMatch(/^0x(1a2b3c|abc123|123456)$/i);
      }
    }
  });

  it("4648: the Subject is the person who used the credentials, and the target is a real account", () => {
    for (const { c, r } of of("4648")) {
      if (c.ev.user_email) expect(r.SubjectUserSid, c.ev.id).not.toBe("S-1-5-18");
      expect(r.TargetUserName, c.ev.id).not.toBe("domain-admin");
    }
  });

  it("one account, one spelling: a record never names the row's user without its dot (tharris / t.harris)", () => {
    for (const { c, r } of rendered) {
      const local = c.ev.user_email?.split("@")[0];
      if (!local?.includes(".")) continue;
      const dotless = local.replace(/\./g, "").toLowerCase();
      for (const k of ["SubjectUserName", "TargetUserName"]) if (r[k] !== undefined) expect(String(r[k]).toLowerCase(), `${c.ev.id} ${k}`).not.toBe(dotless);
    }
  });

  it("one account, one SID within a company", () => {
    const sids = new Map<string, Set<string>>();
    for (const { c, r } of rendered) for (const [n, s] of [["TargetUserName", "TargetUserSid"], ["TargetUserName", "TargetSid"], ["SubjectUserName", "SubjectUserSid"]] as const) {
      const name = String(r[n] ?? ""), sid = String(r[s] ?? "");
      if (!name || name === "-" || name.endsWith("$") || name.includes("@") || !/^S-1-5-21-/.test(sid) || /^(4728|4729|4732|4733|4756|4757)$/.test(String(r.EventID))) continue;
      const key = `${c.companyId}:${name.toLowerCase()}`;
      if (!sids.has(key)) sids.set(key, new Set());
      sids.get(key)!.add(sid);
    }
    const clash = [...sids].filter(([, v]) => v.size > 1).map(([k, v]) => `${k}: ${[...v].join(" / ")}`);
    expect(clash).toEqual([]);
  });

  it("an admin's reset is 4724; 4723 is only a user changing their own password", () => {
    for (const { c, r } of of("4723")) {
      const subj = String(r.SubjectUserName ?? "-").toLowerCase();
      if (subj !== "-") expect(subj, c.ev.id).toBe(String(r.TargetUserName).toLowerCase());
    }
    for (const c of rows) {
      const id = String(c.ev.raw?.["winlog.event_id"] ?? c.ev.raw?.["event.code"] ?? "");
      if (id === "4723") expect(c.ev.description ?? "", c.ev.id).not.toMatch(/\breset\b/i);
    }
  });

  it("Kerberos, lockout and directory records are the DC's; a renewal is 4770", () => {
    for (const { c, r } of of("4768", "4769", "4770", "4771", "4740", "4662", "5136", "5137")) expect(String(r.Computer), c.ev.id).toSatisfy(isDc);
    for (const c of rows) if (c.ev.raw?.["event.code"] === "4768" || c.ev.raw?.["winlog.event_id"] === "4768") expect(c.ev.description ?? "", c.ev.id).not.toMatch(/renew/i);
    expect(of("4770").length).toBeGreaterThan(0);
  });

  it("a 4740 is written by DC$ with the caller workstation by name", () => {
    for (const { c, r } of of("4740")) {
      expect(String(r.TargetDomainName), c.ev.id).not.toMatch(/^\\\\/);
      expect(String(r.SubjectUserName), c.ev.id).toMatch(/\$$/);
    }
  });

  it("a service ticket names the service account, never the SPN", () => {
    for (const { c, r } of of("4769", "4770")) expect(String(r.ServiceName), c.ev.id).not.toContain("/");
  });

  it("EventRecordID only grows with time on each computer", () => {
    for (const company of new Set(rendered.map(x => x.c.companyId))) {
      const byHost = new Map<string, NativeLog[]>();
      for (const x of rendered.filter(y => y.c.companyId === company)) {
        const h = String(x.r.Computer);
        if (!byHost.has(h)) byHost.set(h, []);
        byHost.get(h)!.push(x.log);
      }
      for (const [h, logs] of byHost) {
        const sorted = [...logs].sort((a, b) => a.timeMs - b.timeMs);
        for (let i = 1; i < sorted.length; i++) if (sorted[i].timeMs - sorted[i - 1].timeMs >= 1000)
          expect(Number(sorted[i].record.EventRecordID), `${company} ${h}`).toBeGreaterThan(Number(sorted[i - 1].record.EventRecordID));
      }
    }
  });

  it("no hand-typed placeholder GUIDs anywhere in the corpus", () => {
    const blob = JSON.stringify(corpus().map(c => c.ev));
    const guids = blob.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi) ?? [];
    const placeholder = /^(a1b2c3d4-e5f6|f1e2d3c4-b5a6|a7b8c9d0-1234|c3d4e5f6-7890|9a1b2c3d-4e5f|b8c9d0e1-2345|c9d0e1f2-3456)|1234567890(ab)?$|-1234-5678-/i;
    expect([...new Set(guids.filter(g => placeholder.test(g)))]).toEqual([]);
  });

  it("NexaCorp's file server has one name, and no person signs in from a printer", () => {
    const blob = JSON.stringify(BENIGN_EVENTS);
    for (const alias of ["SRV-FILE01", "SRV-NXC-FS02", "SRV-NXC-FILES01"]) expect(blob.includes(alias), alias).toBe(false);
    for (const e of BENIGN_EVENTS as TelemetryEvent[]) {
      const ws = String(e.raw?.["winlog.event_data.WorkstationName"] ?? e.raw?.["winlog.event_data.Workstation"] ?? "");
      if (/^PRINTER/i.test(ws)) expect(e.user_email ?? "", e.id).toMatch(/^svc-/);
    }
  });
});

describe("the feed tag of a Windows row is who wrote it", () => {
  const ev = (o: Partial<TelemetryEvent> & { id: string; code: string }): TelemetryEvent =>
    ({ ts: "2026-11-12T10:00:00Z", source: "ad", event_type: "auth_success", severity: "low", raw: { "event.code": o.code }, ...o } as TelemetryEvent);
  it("System 7045, a DC's records, a member's Security log", () => {
    expect(windowsFeedSource(ev({ id: "a", code: "7045", hostname: "WS-OPS-2214" }))).toBe("windows_system");
    expect(windowsFeedSource(ev({ id: "b", code: "4624", hostname: "WS-HR-1142" }))).toBe("windows_security");
    expect(windowsFeedSource(ev({ id: "c", code: "4625", hostname: "WS-HR-1142", source: "windows_security" }))).toBe("windows_security");
    expect(windowsFeedSource(ev({ id: "d", code: "4768", hostname: "SRV-NXC-DC01" }))).toBe("ad");
    expect(windowsFeedSource(ev({ id: "e", code: "4624", hostname: "SRV-NXC-DC01" }))).toBe("ad");
    expect(windowsFeedSource({ ...ev({ id: "f", code: "x" }), raw: {} })).toBeUndefined();
  });
  it("every corpus row of the same event id on the same machine gets one tag", () => {
    const tags = new Map<string, Set<string>>();
    for (const c of rows) {
      const t = windowsFeedSource(c.ev); if (!t || !c.ev.hostname) continue;
      const k = `${c.ev.hostname}`;
      if (!tags.has(k)) tags.set(k, new Set());
      tags.get(k)!.add(t);
    }
    const mixed = [...tags].filter(([, v]) => v.has("ad") && v.has("windows_security")).map(([k]) => k);
    expect(mixed).toEqual([]);
  });
});

describe("the Analysis view reads like Event Viewer", () => {
  const fail = rendered.find(x => x.r.EventID === 4625 && x.r.FailureReason === "%%2313")!;
  it("groups a 4625 and decodes its codes", () => {
    const titles = windowsEventSections(fail.r).map(s => s.title);
    expect(titles).toEqual(expect.arrayContaining(["Event", "Subject", "Account For Which Logon Failed", "Failure Information", "Network Information", "Detailed Authentication Information"]));
    expect(windowsEventSections(fail.r).find(s => s.title === "Failure Information")!.rows.map(([k]) => k)).toEqual(["Status", "FailureReason", "SubStatus"]);
    expect(windowsValueMeaning("FailureReason", "%%2313", fail.r)).toBe("Unknown user name or bad password");
    expect(windowsValueMeaning("Status", "0xc000006d", fail.r)).toBe("Bad user name or authentication information");
    expect(windowsValueMeaning("LogonType", "3")).toBe("Network");
    expect(windowsValueMeaning("Status", "0x18", { EventID: 4771 })).toMatch(/Pre-authentication failed/);
    expect(windowsValueMeaning("TicketEncryptionType", "0x17")).toMatch(/^RC4-HMAC/);
    expect(windowsValueMeaning("Keywords", "0x8010000000000000")).toBe("Audit Failure");
  });
  it("every field lands in exactly one group", () => {
    for (const { r } of rendered.slice(0, 200)) {
      const n = windowsEventSections(r).reduce((a, s) => a + s.rows.length, 0);
      expect(n).toBe(Object.values(r).filter(v => v !== undefined && v !== null).length);
    }
  });
});
