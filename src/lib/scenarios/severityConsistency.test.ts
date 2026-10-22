// Scenario severity must agree with the scenario: the level an event shows is the level its
// source gives it (Tal, 2026-10-22). When the raw block records the vendor's own severity
// (Falcon SeverityName, Defender / Sentinel alert.severity, ...), the event's severity is that
// same level, and a product detection is never silent unless the vendor itself says so.
import { describe, it, expect } from "vitest";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { buildAlertIndex, effectiveSeverity } from "./eventClass";
import type { TelemetryEvent } from "@/lib/sim/types";

const VENDOR_KEYS = ["crowdstrike.SeverityName", "SeverityName", "event.severity_name", "AlertSeverity", "alert.severity", "severity"];
const norm = (v: string) => {
  const s = v.trim().toLowerCase();
  return s.startsWith("crit") ? "critical" : s === "high" ? "high" : s.startsWith("med") || s === "moderate" ? "medium" : s === "low" ? "low" : s.startsWith("info") ? "informational" : null;
};

const all = (SCENARIOS as unknown as { slug: string; build: () => { events: TelemetryEvent[] } }[])
  .map(sc => ({ slug: sc.slug, events: sc.build().events }));

describe("scenario severity matches its source", () => {
  it("the event's severity equals the vendor severity recorded in its raw log", () => {
    const bad: string[] = [];
    for (const { slug, events } of all) for (const e of events) for (const k of VENDOR_KEYS) {
      const v = e.raw?.[k];
      const n = typeof v === "string" ? norm(v) : null;
      if (n && e.severity && n !== e.severity) bad.push(`${slug} ${e.id}: ${k}=${v}, event=${e.severity}`);
    }
    expect(bad).toEqual([]);
  });

  it("a product detection is never shown as INFO unless its vendor says so", () => {
    const bad: string[] = [];
    for (const { slug, events } of all) {
      const alerts = buildAlertIndex(events);
      for (const e of events) {
        if (!alerts.has(e.id) || e.is_baseline) continue;
        const vendorSaysInfo = VENDOR_KEYS.some(k => typeof e.raw?.[k] === "string" && norm(String(e.raw?.[k])) === "informational");
        if (effectiveSeverity(e, true) === "informational" && !vendorSaysInfo) bad.push(`${slug} ${e.id}`);
      }
    }
    expect(bad).toEqual([]);
  });
});
