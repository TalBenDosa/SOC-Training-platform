import { describe, it, expect } from "vitest";
import { classifyEvent, buildAlertIndex, countAlerts, effectiveSeverity, severityLabel, severityAtLeast } from "./eventClass";
import { buildMultiHostIntrusionScenario } from "@/lib/sim/scenario-packs/multiHostIntrusion";
import type { TelemetryEvent } from "@/lib/sim/types";

const ev = (o: Partial<TelemetryEvent>): TelemetryEvent => ({
  id: o.id ?? "e", ts: "2026-01-01T00:00:00Z", source: "edr", event_type: "process_create", raw: {}, ...o,
} as TelemetryEvent);

describe("classifyEvent", () => {
  it("treats a Falcon DetectionSummaryEvent as an alert", () => {
    expect(classifyEvent(ev({ event_type: "edr_alert", raw: { "crowdstrike.event_simpleName": "DetectionSummaryEvent" } }))).toBe("alert");
    expect(classifyEvent(ev({ event_type: "av_quarantine", raw: { "crowdstrike.event_simpleName": "DetectionSummaryEvent" } }))).toBe("alert");
  });
  it("treats raw telemetry as telemetry even when flagged is_detection", () => {
    expect(classifyEvent(ev({ is_detection: true, raw: { "crowdstrike.event_simpleName": "ProcessRollup2" } }))).toBe("telemetry");
    expect(classifyEvent(ev({ event_type: "net_connection", raw: { "crowdstrike.event_simpleName": "NetworkConnectIP4" } }))).toBe("telemetry");
    expect(classifyEvent(ev({ source: "ad", event_type: "auth_success", raw: { EventID: 4624 } }))).toBe("telemetry");
    expect(classifyEvent(ev({ source: "firewall", event_type: "net_connection", raw: { type: "TRAFFIC" } }))).toBe("telemetry");
  });
  it("recognises other product detections", () => {
    for (const t of ["ids_signature", "dlp_alert", "ueba_anomaly", "waf_block", "threat_intel_match"] as const) {
      expect(classifyEvent(ev({ event_type: t }))).toBe("alert");
    }
  });
});

describe("buildAlertIndex", () => {
  it("multi-host-intrusion: exactly the Falcon detections are alerts", () => {
    const b = buildMultiHostIntrusionScenario();
    const idx = buildAlertIndex(b.events);
    const detections = b.events.filter(e => e.raw?.["crowdstrike.event_simpleName"] === "DetectionSummaryEvent");
    expect(detections.length).toBeGreaterThan(0);
    expect([...idx].sort()).toEqual(detections.map(e => e.id).sort());
    expect(countAlerts(b.events)).toBe(detections.length);
    // No ProcessRollup2 / NetworkConnect / 4624 / firewall row is shown with a severity.
    for (const e of b.events) {
      if (!idx.has(e.id)) expect(effectiveSeverity(e, false)).toBe("informational");
    }
  });
  it("falls back to is_detection rows only for an incident with no product detection", () => {
    const events = [
      ev({ id: "a", incident_id: "i1", is_detection: true }),
      ev({ id: "b", incident_id: "i1", event_type: "edr_alert", raw: { "crowdstrike.event_simpleName": "DetectionSummaryEvent" } }),
      ev({ id: "c", incident_id: "i2", source: "cloudtrail", event_type: "cloud_api_call", is_detection: true }),
      ev({ id: "d", incident_id: "i2", source: "cloudtrail", event_type: "cloud_api_call" }),
    ];
    expect([...buildAlertIndex(events)].sort()).toEqual(["b", "c"]);
  });
});

describe("effectiveSeverity / labels", () => {
  it("uses the vendor severity for alerts and INFO for telemetry", () => {
    const alert = ev({ severity: "high", raw: { "crowdstrike.SeverityName": "Critical" } });
    expect(effectiveSeverity(alert, true)).toBe("critical");
    expect(effectiveSeverity(ev({ severity: "high" }), true)).toBe("high");
    expect(effectiveSeverity(ev({ severity: "critical" }), false)).toBe("informational");
  });
  it("labels are words, never a Wazuh-looking number", () => {
    expect(severityLabel("critical")).toBe("CRIT");
    expect(severityLabel("informational")).toBe("INFO");
    expect(severityAtLeast("high", "medium")).toBe(true);
    expect(severityAtLeast("informational", "medium")).toBe(false);
  });
});
