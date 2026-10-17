// QA-EDR-1: a synthesized process only takes the event's file hash as its own image
// hash when the event is a process start / detection whose file IS the process. On a
// file write, the file is what the process wrote (chrome.exe downloading a zip).
import { describe, it, expect } from "vitest";
import { synthesizeProcessEvents } from "./fromLiveStory";
import type { TelemetryEvent } from "@/lib/sim/types";

const ZIP = "a".repeat(64);
const DROPPER = "b".repeat(64);

const ev = (o: Partial<TelemetryEvent>): TelemetryEvent => ({
  id: o.id ?? "e", ts: "2026-10-17T10:00:00Z", source: "edr", severity: "high", ...o,
} as TelemetryEvent);

describe("synthesizeProcessEvents image hash", () => {
  it("does not give the browser the hash of the zip it downloaded", () => {
    const out = synthesizeProcessEvents([ev({
      id: "w", event_type: "file_create",
      raw: { "process.name": "chrome.exe" },
      file: { path: "C:\\Users\\a\\Downloads\\invoice.zip", name: "invoice.zip", sha256: ZIP },
    })]);
    expect(out).toHaveLength(1);
    expect(out[0].process?.name).toBe("chrome.exe");
    expect(out[0].process?.hash).toBeUndefined();
  });

  it("keeps the file hash when a detection names the binary itself", () => {
    const out = synthesizeProcessEvents([ev({
      id: "d", event_type: "av_detection",
      file: { path: "C:\\Users\\a\\AppData\\Local\\Temp\\upd.exe", name: "upd.exe", sha256: DROPPER },
    })]);
    expect(out[0].process?.name).toBe("upd.exe");
    expect(out[0].process?.hash?.sha256).toBe(DROPPER);
  });

  it("does not give a detection's writer process the detected file's hash", () => {
    const out = synthesizeProcessEvents([ev({
      id: "d2", event_type: "edr_alert",
      raw: { "process.name": "outlook.exe" },
      file: { path: "C:\\Users\\a\\AppData\\Local\\Temp\\upd.exe", name: "upd.exe", sha256: DROPPER },
    })]);
    expect(out[0].process?.name).toBe("outlook.exe");
    expect(out[0].process?.hash).toBeUndefined();
  });
});
