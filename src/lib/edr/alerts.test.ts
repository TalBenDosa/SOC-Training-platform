import { describe, it, expect, afterEach } from "vitest";
import { EDR_INVESTIGATIONS } from "./investigations";
import { alertKey, readAckedAlerts, unacknowledged, writeAckedAlerts } from "./alerts";

const inv = EDR_INVESTIGATIONS[0];

describe("live EDR alerts (console cards + dashboard count)", () => {
  afterEach(() => localStorage.clear());

  it("one alert per detection; acknowledged ones drop out of the count", () => {
    expect(unacknowledged([inv], new Set())).toHaveLength(inv.detections.length);
    const acked = new Set([alertKey(inv, inv.detections[0])]);
    writeAckedAlerts(acked);
    expect(unacknowledged([inv], readAckedAlerts())).toHaveLength(inv.detections.length - 1);
  });

  it("a new incident's detections are new alerts even on the same process", () => {
    const acked = new Set(inv.detections.map(d => alertKey(inv, d)));
    const next = { ...inv, title: "Another incident" };
    expect(unacknowledged([next], acked)).toHaveLength(next.detections.length);
  });

  it("corrupt storage reads as nothing acknowledged", () => {
    localStorage.setItem("edr_ack_alerts", "{nope");
    expect(readAckedAlerts().size).toBe(0);
  });
});
