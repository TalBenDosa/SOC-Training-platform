import { describe, it, expect } from "vitest";
import { itsmNoise, ticketRecord } from "./itsmNoise";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import { nativize } from "@/lib/logs/native";
import { AI_CORE_STORIES } from "@/app/(app)/dashboard/ai-stories/core";
import type { TelemetryEvent } from "@/lib/sim/types";

/**
 * Review 2026-11-08 (Sdema exercise, K2): story tickets carried 26-45 fields and background tickets
 * 6-15, so a field count told the attack's ticket apart. A background incident and the story's
 * incident must render with the same record fields; one ticket keeps one opened_at / sys_id.
 */
const keysOf = (ev: TelemetryEvent) => {
  const log = nativize(ev, "nexacorp");
  return Object.keys((log?.record as { result: Record<string, unknown> }).result).sort();
};

describe("ServiceNow records have one shape, attack or background", () => {
  let x = 7;
  const rnd = () => { x = (x * 1103515245 + 12345) % 2 ** 31; return x / 2 ** 31; };
  const noise = itsmNoise(COMPANY_ASSETS.nexacorp, "nexacorp", 24, rnd, "2026-01-01T08:00:00.000Z").map(n => n.ev);
  const story = AI_CORE_STORIES.find(s => s.id === "ai-helpdesk-voice-reset")!.events.filter(e => /servicenow/i.test(e.vendor ?? ""));

  it("a background incident carries every field the story incident carries (bar the story's own evidence)", () => {
    const storyKeys = new Set(story.flatMap(keysOf));
    // Fields only a specific ticket has: its free text, its custom verification column, its CI and closure.
    const own = new Set(["description", "u_identity_verification", "u_verification_result", "cmdb_ci", "assigned_to", "approval", "subcategory"]);
    for (const ev of noise.filter(e => e.raw?.["servicenow.table"] === "incident")) {
      const missing = [...storyKeys].filter(k => !own.has(k) && !keysOf(ev).includes(k));
      expect(missing, `${ev.raw?.["servicenow.number"]}`).toEqual([]);
    }
  });

  it("every background ticket names who opened it and when", () => {
    for (const ev of noise) {
      const r = (nativize(ev, "nexacorp")!.record as { result: Record<string, unknown> }).result;
      expect(r.opened_at, String(r.number)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
      expect(String(r.opened_at) <= String(r.sys_updated_on)).toBe(true);
      expect(r.priority).toBeTruthy();
    }
  });

  it("one story ticket keeps one number, sys_id and opened_at across its rows", () => {
    const recs = story.map(e => (nativize(e, "nexacorp")!.record as { result: Record<string, unknown> }).result);
    expect(new Set(recs.map(r => r.number)).size).toBe(1);
    expect(new Set(recs.map(r => r.sys_id)).size).toBe(1);
    expect(new Set(recs.map(r => r.opened_at)).size).toBe(1);
  });

  it("a ticket spec renders the same fields whatever its state", () => {
    const a = ticketRecord({ table: "incident", number: "INC0040001", state: "New", short: "Printer offline", requestedFor: "a.b@nexacorp.com", group: "Service Desk" }, "nexacorp", "t1", "2026-01-01T08:00:00.000Z");
    const b = ticketRecord({ table: "incident", number: "INC0040002", state: "In Progress", short: "Printer offline", requestedFor: "a.b@nexacorp.com", group: "Service Desk" }, "nexacorp", "t2", "2026-01-01T08:00:00.000Z");
    expect(keysOf(a)).toEqual(keysOf(b));
  });
});
