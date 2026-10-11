import { describe, it, expect } from "vitest";
import { source, kindOf } from "./google_workspace";
import { resolveOperation } from "./m365";
import { validateNative } from "../validate";
import { cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";
import { convertAll, highFired, hitCounts, isNativeVendor, isPlanted, present, strings } from "./collab-email-testkit";

const schema = source.schema;
const toLog = (record: Record<string, unknown>): NativeLog =>
  ({ sourceId: "google_workspace", kind: kindOf(record)!, format: "json", record, timeMs: Date.parse(String((record.id as Record<string, unknown>).time)) });

// Card samples: G1–G10 (G9 = two activities) → 11 activities. SKIPPED: the §2 response-page envelope
// ({kind:"admin#reports#activities", items:[…]}) — it is the list wrapper, not an activity (kindOf → null).
const samples = cardSamples(schema.card) as Record<string, unknown>[];
const sampleLogs = samples.filter(r => kindOf(r) !== null).map(toLog);
const evName = (r: Record<string, unknown>) => ((r.events as Array<Record<string, unknown>>)[0].name as string);
const sample = (name: string) => samples.find(s => kindOf(s) && evName(s) === name)!;

const converted = convertAll(source);
const native = converted.filter(c => isNativeVendor(source, c.ce.ev));
const cross = converted.filter(c => !isNativeVendor(source, c.ce.ev));

/** Native events null BY DESIGN: Gmail filter creation (no Reports API event), mail-log search results, calendar (not in card). */
const documentedNull = (c: (typeof converted)[number]) => {
  const r = c.ce.ev.raw;
  return r["gws.eventName"] === "CREATE_GMAIL_FILTER" || r["gws.event.type"] === "email_log_search" || r["gws.eventName"] === "calendar.event.created";
};

describe("google_workspace — card samples", () => {
  it("every card activity validates with zero violations", () => {
    expect(sampleLogs.length).toBe(11);
    for (const l of sampleLogs) expect(validateNative(l, schema), evName(l.record)).toEqual([]);
  });
});

describe("google_workspace — corpus conversion", () => {
  it("validates; native coverage ≥ 95 % (excluding documented nulls); cross-vendor floor", () => {
    for (const { ce, log } of converted) if (log) expect(validateNative(log, schema), ce.ev.id).toEqual([]);
    const eligible = native.filter(c => !documentedNull(c));
    console.log(`[gws] native ${native.filter(c => c.log).length}/${native.length} (documented nulls ${native.length - eligible.length}); ` +
      `eligible ${eligible.filter(c => c.log).length}/${eligible.length}; cross-vendor (M365/Entra-authored) ${cross.filter(c => c.log).length}/${cross.length}`);
    console.log(`[gws] native nulls: ${native.filter(c => !c.log).map(c => c.ce.ev.id).join(", ")}`);
    expect(eligible.filter(c => c.log).length / eligible.length).toBeGreaterThanOrEqual(0.95);
    expect(cross.filter(c => c.log).length).toBeGreaterThanOrEqual(40);
    const byApp: Record<string, number> = {};
    for (const c of cross) if (c.log) byApp[c.log.kind] = (byApp[c.log.kind] ?? 0) + 1;
    console.log("[gws] cross-vendor by application:", byApp);
  });

  it("follows the M365 ↔ Google equivalence table", () => {
    for (const { ce, log } of cross) {
      const op = resolveOperation(ce.ev);
      if (op && /^(New-InboxRule|Set-InboxRule|UpdateInboxRules|Add-MailboxPermission|MailItemsAccessed|MailboxLogin|MessageCreatedHasLink|MessageSent|TeamsSessionStarted|CopilotInteraction)$/.test(op))
        expect(log, `${ce.ev.id} ${op} has no Google equivalent`).toBeNull();
      if (op === "UserLoggedIn" && ce.ev.user_email) expect(log?.kind, ce.ev.id).toBe("login");
      if (op === "FileDownloaded" && ce.ev.file?.name) expect((log?.record.events as Array<Record<string, unknown>>)[0].name).toBe("download");
    }
    // Native "Gmail filter" events are never faked.
    for (const { ce, log } of native) if (ce.ev.raw["gws.eventName"] === "CREATE_GMAIL_FILTER") expect(log).toBeNull();
    // Set-Mailbox out-of-domain forwarding → email_forwarding_out_of_domain.
    const fwd = cross.find(c => c.ce.ev.id === "evt_07_forward_rule")!;
    expect((fwd.log!.record.events as Array<Record<string, unknown>>)[0].name).toBe("email_forwarding_out_of_domain");
    expect(JSON.stringify(fwd.log!.record)).toContain("l.harris.backup@gmail.com");
    // Per-user OAuth consent → token authorize with Google scopes.
    const consent = cross.find(c => c.ce.ev.id === "evt_04_consent")!;
    expect(consent.log!.kind).toBe("token");
    expect(JSON.stringify(consent.log!.record)).toContain("https://mail.google.com/");
  });

  it("evidence values survive verbatim", () => {
    let n = 0;
    for (const { ce, log } of converted) {
      if (!log) continue;
      const ev = ce.ev;
      const hay = strings(log.record);
      const user = ev.user?.email ?? ev.user_email;
      if (user) expect(present(hay, user), `${ev.id} user`).toBe(true);
      // Google is SaaS: an office-LAN client reaches it through the NAT egress, never with its private address.
      if (ev.src_ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ev.src_ip)) expect(present(hay, ev.src_ip), `${ev.id} ip`).toBe(true);
      if (ev.file?.name && log.kind === "drive") expect(present(hay, ev.file.name), `${ev.id} file`).toBe(true);
      if (ev.file?.sha256) expect(present(hay, ev.file.sha256), `${ev.id} sha`).toBe(true);
      if (ev.network?.domain && log.kind === "gmail") expect(present(hay, ev.network.domain), `${ev.id} domain`).toBe(true);
      n++;
    }
    expect(n).toBeGreaterThan(50);
  });

  it("native value types: int64 strings, boolValue booleans, one value key per parameter", () => {
    for (const { log } of converted) {
      if (!log) continue;
      const r = log.record as Record<string, any>;
      expect(r.id.time).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
      expect(r.id.uniqueQualifier).toMatch(/^-?\d+$/);
      expect(typeof r.actor.profileId).toBe("string");
      for (const e of r.events) for (const p of e.parameters ?? []) {
        const keys = Object.keys(p).filter(k => k !== "name");
        expect(keys.length, JSON.stringify(p)).toBe(1);
        if ("intValue" in p) expect(typeof p.intValue).toBe("string");
        if ("boolValue" in p) expect(typeof p.boolValue).toBe("boolean");
      }
    }
  });

  it("is deterministic; actor ids stable per user", () => {
    expect(convertAll(source).map(c => c.log)).toEqual(converted.map(c => c.log));
    const amir = converted.filter(c => c.log && (c.log.record.actor as Record<string, unknown>).email === "s.amir@rocketstack.io");
    expect(new Set(amir.map(c => (c.log!.record.actor as Record<string, unknown>).profileId)).size).toBe(1);
  });
});

describe("google_workspace — use cases", () => {
  const g6 = sample("download");
  const burst = Array.from({ length: 60 }, (_, i) => toLog({ ...g6, id: { ...(g6.id as object), time: `2026-09-29T08:${String(6 + Math.floor(i / 10)).padStart(2, "0")}:${String((i * 7) % 60).padStart(2, "0")}.000Z`, uniqueQualifier: String(1000 + i) } }));
  const g1 = sample("login_success");
  const failBurst = Array.from({ length: 6 }, (_, i) => toLog({
    ...g1, id: { ...(g1.id as object), time: `2026-09-29T07:3${i}:00.000Z`, uniqueQualifier: String(2000 + i) },
    actor: { callerType: "USER", email: `user${i}@globallogis.com`, profileId: `10472938561047382915${i}` },
    events: [{ type: "login", name: "login_failure", parameters: [{ name: "login_type", value: "google_password" }] }],
  }));
  const story = converted.filter(c => c.ce.origin === "story" && c.log).map(c => c.log!);
  const attack = [...sampleLogs, ...story, ...burst, ...failBurst];
  const noise = converted.filter(c => c.ce.origin !== "story" && c.log && !isPlanted(c.ce.ev)).map(c => c.log!);

  it("every use case fires", () => {
    const counts = hitCounts(source.useCases, attack);
    console.log("[gws] use-case hits (attack set):", counts);
    for (const uc of source.useCases) expect(counts[uc.id], uc.id).toBeGreaterThan(0);
  });

  it("high / critical use cases fire on < 2 % of noise", () => {
    const fired = highFired(source.useCases, noise);
    console.log(`[gws] noise: ${fired.size}/${noise.length}`, hitCounts(source.useCases, noise));
    expect(noise.length).toBeGreaterThan(20);
    expect(fired.size / noise.length).toBeLessThan(0.02);
  });
});
