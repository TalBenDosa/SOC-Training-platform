import { describe, it, expect } from "vitest";
import { source, kindOf } from "./virustotal";
import { makeCtx } from "../ctx";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { nativize } from "../index";
import { buildKeyLeftBehindScenario } from "@/lib/sim/scenario-packs/keyLeftBehind";
import type { TelemetryEvent } from "@/lib/sim/types";

const reports = buildKeyLeftBehindScenario().events.filter(e => e.vendor === "VirusTotal");
const flagged: TelemetryEvent = {
  ...reports[1], id: "vt-flagged",
  raw: { ...reports[1].raw, "data.attributes.last_analysis_stats.malicious": 4, "data.attributes.reputation": -12 },
};

describe("virustotal, API v3 object reports", () => {
  it("renders the nested v3 response with zero violations", () => {
    expect(reports.length).toBe(2);
    for (const ev of [...reports, flagged]) {
      const log = source.fromTelemetry(ev, makeCtx("nexacorp"))!;
      expect(log, ev.id).not.toBeNull();
      expect(validateNative(log, source.schema), ev.id).toEqual([]);
      expect(kindOf(log.record)).toBe("ip_address");
      const d = (log.record as { data: { id: string; links: { self: string }; attributes: { last_analysis_stats: Record<string, number> } } }).data;
      expect(d.id).toBe(ev.raw!["data.id"]);
      expect(d.links.self).toBe(`https://www.virustotal.com/api/v3/ip_addresses/${d.id}`);
      expect(typeof d.attributes.last_analysis_stats.malicious).toBe("number");
    }
  });
  it("is the record every stack shows for a VirusTotal event; other threat-intel vendors are not taken", () => {
    expect(nativize(reports[0], "nexacorp")?.sourceId).toBe("virustotal");
    expect(nativize(reports[0], "rocketstack")?.sourceId).toBe("virustotal");
    expect(source.fromTelemetry({ ...reports[0], vendor: "Recorded Future" }, makeCtx("nexacorp"))).toBeNull();
  });
  it("use cases: engines flag the flagged copy, the clean hosting address reads as context only", () => {
    const logs = [...reports, flagged].map(e => source.fromTelemetry(e, makeCtx("nexacorp"))!);
    const hits = (id: string) => runUseCase(source.useCases.find(u => u.id === id)!, logs).flatMap(h => h.records).map(i => logs[i].record);
    expect(hits("virustotal.engines_flag_object").length).toBe(1);
    expect(hits("virustotal.hosting_address_clean").map(r => (r as { data: { id: string } }).data.id)).toEqual(["203.0.113.142"]);
  });
});
