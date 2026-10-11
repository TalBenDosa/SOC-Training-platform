import { describe, it, expect } from "vitest";
import { source, kindOf } from "./m365";
import { validateNative } from "../validate";
import { cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";
import { convertAll, highFired, hitCounts, isNativeVendor, isPlanted, present, strings } from "./collab-email-testkit";
import { isGuid } from "./collab-email-shared";

const schema = source.schema;
const toLog = (record: Record<string, unknown>): NativeLog =>
  ({ sourceId: "m365", kind: kindOf(record)!, format: "json", record, timeMs: Date.parse(`${record.CreationTime}Z`) });

// All 10 card samples (S1–S10) are UAL records of supported kinds — none skipped.
const samples = cardSamples(schema.card) as Record<string, unknown>[];
const sampleLogs = samples.filter(r => { const k = kindOf(r); return k !== null && !!schema.kinds[k]; }).map(toLog);
const sample = (op: string) => samples.find(s => s.Operation === op)!;

const converted = convertAll(source);

/**
 * Native-vendor events that are null BY DESIGN (not UAL records):
 *  - mail-flow events (MessageDelivered / SpamFiltered / MessageReceived) — email-security telemetry, rendered by defender_o365 / proofpoint;
 *  - Graph-only calls (MailFolders.List, CalendarEvents.List) — not audited in the UAL.
 */
function documentedNull(log: NativeLog | null, ev: Converted["ev"]): boolean {
  if (log) return false;
  const op = String(ev.raw?.["data.office365.Operation"] ?? ev.raw?.Operation ?? ev.raw?.["event.action"] ?? "");
  return /^(MessageDelivered|SpamFiltered|MessageReceived|MailFolders\.List|CalendarEvents\.List)$/.test(op) ||
    (ev.event_type === "email_received" || ev.event_type === "email_blocked");
}
type Converted = { ev: import("@/lib/sim/types").TelemetryEvent };

describe("m365 — card samples", () => {
  it("every card sample validates with zero violations", () => {
    expect(sampleLogs.length).toBe(10);
    for (const l of sampleLogs) expect(validateNative(l, schema), `${l.record.Operation}`).toEqual([]);
  });
});

describe("m365 — corpus conversion", () => {
  it("every converted event validates; native coverage ≥ 95 % (excluding documented nulls)", () => {
    for (const { ce, log } of converted) if (log) expect(validateNative(log, schema), ce.ev.id).toEqual([]);
    const native = converted.filter(c => isNativeVendor(source, c.ce.ev));
    const nonNull = native.filter(c => c.log);
    const eligible = native.filter(c => !documentedNull(c.log, c.ce.ev));
    const cross = converted.filter(c => !isNativeVendor(source, c.ce.ev));
    console.log(`[m365] native ${nonNull.length}/${native.length} non-null (documented nulls ${native.length - eligible.length}); ` +
      `eligible coverage ${(100 * eligible.filter(c => c.log).length / eligible.length).toFixed(1)} %; ` +
      `cross-vendor ${cross.filter(c => c.log).length}/${cross.length}`);
    console.log(`[m365] native nulls: ${native.filter(c => !c.log).map(c => c.ce.ev.id).join(", ")}`);
    expect(eligible.filter(c => c.log).length / eligible.length).toBeGreaterThanOrEqual(0.95);
    // Cross-vendor = UAL-shaped Entra records + Purview / Graph-Security file & mail ops.
    expect(cross.filter(c => c.log).length).toBeGreaterThanOrEqual(25);
  });

  it("Entra events in the Graph / Azure-Monitor shape are left to the entra module", () => {
    for (const { ce, log } of converted)
      if (/entra/i.test(ce.ev.vendor ?? "") && Object.keys(ce.ev.raw).some(k => k.startsWith("azure."))
        && !Object.keys(ce.ev.raw).some(k => k.startsWith("data.office365."))) expect(log, ce.ev.id).toBeNull();
  });

  it("evidence values survive verbatim", () => {
    let checked = 0;
    for (const { ce, log } of converted) {
      if (!log) continue;
      const ev = ce.ev;
      const hay = strings(log.record);
      const rawUser = String(ev.raw?.["data.office365.UserId"] ?? ev.raw?.UserId ?? "");
      const user = ev.user?.email ?? ev.user_email;
      // Records whose actor is an application (UserId = app id) do not name the human (story teaching point).
      if (user && !isGuid(rawUser)) expect(present(hay, user), `${ev.id} user ${user}`).toBe(true);
      // M365 is SaaS: an office-LAN client reaches it through the NAT egress, never with its private address.
      if (ev.src_ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ev.src_ip)) expect(present(hay, ev.src_ip), `${ev.id} ip`).toBe(true);
      if (ev.file?.sha256) expect(present(hay, ev.file.sha256), `${ev.id} sha`).toBe(true);
      if (ev.cloud?.api_call) expect(present(hay, ev.cloud.api_call), `${ev.id} api`).toBe(true);
      if (ev.file?.name && log.kind.startsWith("SharePoint")) expect(present(hay, ev.file.name), `${ev.id} file`).toBe(true);
      // UAL has no endpoint-host field on admin / logon records; SharePoint carries it as DeviceDisplayName.
      if (ev.hostname && !ev.hostname.includes(".") && log.kind.startsWith("SharePoint")) expect(present(hay, ev.hostname)).toBe(true);
      checked++;
    }
    expect(checked).toBeGreaterThan(50);
  });

  it("inbox-rule parameters and forwarding destinations are carried over", () => {
    for (const { ce, log } of converted) {
      if (!log || log.kind !== "ExchangeAdmin") continue;
      const rawStr = JSON.stringify(ce.ev.raw);
      const dest = /([A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[a-z]{2,})/g;
      const hay = strings(log.record);
      for (const m of rawStr.matchAll(dest)) {
        if (/nexacorp\.local/.test(m[1])) continue;
        expect(present(hay, m[1]), `${ce.ev.id} ${m[1]}`).toBe(true);
      }
    }
  });

  it("is deterministic and stable per entity", () => {
    const again = convertAll(source);
    expect(again.map(c => c.log)).toEqual(converted.map(c => c.log));
    // Same user + IP → same Exchange session / AAD session across a story.
    const harel = converted.filter(c => c.ce.ev.user_email === "d.harel@nexacorp.com" && c.log && c.log.kind.startsWith("ExchangeItem"));
    expect(new Set(harel.map(c => c.log!.record.SessionId)).size).toBe(1);
    const chen = converted.filter(c => c.log && c.log.record.UserId === "j.chen@nexacorp.com").map(c => c.log!.record.UserKey);
    expect(chen.length).toBeGreaterThan(1);
  });

  it("CreationTime / integer enums use the native format", () => {
    for (const { log } of converted) {
      if (!log) continue;
      expect(String(log.record.CreationTime)).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d$/);
      expect(typeof log.record.RecordType).toBe("number");
      expect(typeof log.record.UserType).toBe("number");
      if ("LogonType" in log.record) expect(typeof log.record.LogonType).toBe("number");
    }
  });
});

describe("m365 — use cases", () => {
  // Thresholds need bursts: build them from the card samples (S7 = one of ~600 downloads; S2 = one failed login).
  const s7 = sample("FileDownloaded");
  const burst: NativeLog[] = Array.from({ length: 60 }, (_, i) => toLog({
    ...s7, Id: `burst-${i}`, CreationTime: `2026-09-30T18:${String(10 + Math.floor(i / 10)).padStart(2, "0")}:${String((i * 7) % 60).padStart(2, "0")}`,
    ObjectId: `https://nexacorp.sharepoint.com/sites/Finance/Shared Documents/Payroll/2026/file_${i}.xlsx`,
  }));
  const s2 = sample("UserLoginFailed");
  const spray: NativeLog[] = Array.from({ length: 6 }, (_, i) => toLog({ ...s2, Id: `spray-${i}`, UserId: `user${i}@nexacorp.com`, CreationTime: `2026-09-29T07:3${i}:00` }));

  const story = converted.filter(c => c.ce.origin === "story" && c.log).map(c => c.log!);
  const attackLogs = [...sampleLogs, ...story, ...burst, ...spray];
  const noise = converted.filter(c => c.ce.origin !== "story" && c.log && !isPlanted(c.ce.ev)).map(c => c.log!);

  it("every use case fires on card samples / story events", () => {
    const counts = hitCounts(source.useCases, attackLogs);
    console.log("[m365] use-case hits (attack set):", counts);
    for (const uc of source.useCases) expect(counts[uc.id], uc.id).toBeGreaterThan(0);
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const uc of source.useCases) expect(uc.id.startsWith("m365.")).toBe(true);
  });

  it("high / critical use cases fire on < 2 % of benign/company noise", () => {
    const fired = highFired(source.useCases, noise);
    console.log(`[m365] noise: ${fired.size}/${noise.length} records hit by high/critical rules`, hitCounts(source.useCases, noise));
    expect(noise.length).toBeGreaterThan(20);
    expect(fired.size / noise.length).toBeLessThan(0.02);
  });
});
