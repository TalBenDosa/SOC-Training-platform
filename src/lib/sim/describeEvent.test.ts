/**
 * The scenario page must show every log with a readable, Live-SOC-style
 * description (user report 2026-09-28: rows read "email_received", a bare file
 * path or a domain). The page withholds the authored description + MITRE, so
 * the line is built from observable fields only — check it for every event of
 * every scenario, exactly as the browser receives it.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { SCENARIOS } from "./scenarios";
import { describeEvent, describeEventForRow } from "./describeEvent";
import type { TelemetryEvent } from "./types";

type Built = { slug: string; events: TelemetryEvent[] };
const built: Built[] = (SCENARIOS as unknown as { slug: string; build?: () => { events?: TelemetryEvent[] }; events?: TelemetryEvent[] }[])
  .map(s => ({ slug: s.slug, events: (typeof s.build === "function" ? s.build().events : s.events) ?? [] }));

/** What page.tsx sends to the browser (F-02): no authored description / MITRE. */
const stripped = (e: TelemetryEvent): TelemetryEvent => ({ ...e, description: undefined, mitre_technique: undefined, mitre_tactic: undefined });

describe("scenario log descriptions (Live-SOC style)", () => {
  it("every event gets a real sentence, never the raw event_type or a bare field", () => {
    const bad: string[] = [];
    for (const s of built) for (const e of s.events) {
      const d = describeEvent(stripped(e), { preferFields: true });
      const et = e.event_type.replace(/_/g, " ");
      const generic = d.toLowerCase() === et || d.toLowerCase().startsWith(`${et} on `)
        || /^(Process Create|DNS query)\.?$/.test(d);
      if (!d.trim() || generic || d === e.event_type || /^[a-z]+(_[a-z]+)+$/.test(d)) bad.push(`${s.slug}/${e.id}: ${d}`);
    }
    expect(bad).toEqual([]);
  });

  it("never reuses the authored (answer-bearing) description for attack events", () => {
    for (const s of built) for (const e of s.events) {
      if (!e.description || !e.mitre_technique) continue;
      expect(describeEvent(e)).not.toBe(e.description);
    }
  });

  it("splits the user onto its own line like the live feed", () => {
    const r = describeEventForRow({ id: "x", ts: "2026-01-01T00:00:00Z", source: "email_gateway", event_type: "email_received", user_email: "j.chen@nexacorp.com" } as TelemetryEvent);
    expect(r).toEqual({ user: "j.chen", title: undefined, action: "Received an email" });
  });
});
