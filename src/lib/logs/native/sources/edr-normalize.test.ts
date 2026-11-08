/**
 * One pid per process across a row (Sdema review 2026-11-08: a 7z.exe row showed raw ProcessId 7770 next
 * to process.pid 1156). syncRawPids moves every raw copy of a re-numbered pid with it, in each legacy
 * vocabulary, and leaves a raw value that names another process alone.
 */
import { describe, it, expect } from "vitest";
import type { TelemetryEvent } from "@/lib/sim/types";
import { syncRawPids, edrFacts } from "./edr-normalize";

const proc = (raw: Record<string, unknown>): TelemetryEvent => ({
  id: "p", ts: "2026-01-01T08:00:00.000Z", source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create", hostname: "LT-ENG-4408",
  process: { name: "7z.exe", pid: 7770, parent_name: "explorer.exe", parent_pid: 2400 }, raw,
} as TelemetryEvent);

describe("syncRawPids", () => {
  it("a process row: its own ProcessId and its creator's InitiatingProcessId follow the new numbers", () => {
    const ev = syncRawPids(proc({ ActionType: "ProcessCreated", ProcessId: "7770", InitiatingProcessId: "2400", "process.pid": 7770, "process.parent.pid": "2400" }),
      { pid: 7770, parentPid: 2400 }, { pid: 1156, parentPid: 5012 });
    expect(ev.raw).toMatchObject({ ProcessId: "1156", InitiatingProcessId: "5012", "process.pid": 1156, "process.parent.pid": "5012" });
  });

  it("a network row: InitiatingProcessId is the actor itself", () => {
    const ev = syncRawPids({ ...proc({ InitiatingProcessId: "7770", RemoteIP: "203.0.113.9" }), event_type: "net_connection" } as TelemetryEvent,
      { pid: 7770 }, { pid: 1156 });
    expect(ev.raw!.InitiatingProcessId).toBe("1156");
  });

  it("Sysmon hex and decimal forms, and a value naming another process is left alone", () => {
    const ev = syncRawPids({ ...proc({ "winlog.event_data.ProcessId": "7770", "winlog.event_data.ParentProcessId": "0x960", "winlog.event_data.SourceProcessId": "999" }), source: "sysmon" } as TelemetryEvent,
      { pid: 7770, parentPid: 2400 }, { pid: 1156, parentPid: 5012 });
    expect(ev.raw).toMatchObject({ "winlog.event_data.ProcessId": "1156", "winlog.event_data.ParentProcessId": "0x1394", "winlog.event_data.SourceProcessId": "999" });
  });

  it("nothing to move: the same object comes back, and the facts read the new pid afterwards", () => {
    const ev = proc({ ProcessId: "7770" });
    expect(syncRawPids(ev, { pid: 7770 }, { pid: 7770 })).toBe(ev);
    const moved = syncRawPids({ ...ev, process: { ...ev.process!, pid: 1156 } } as TelemetryEvent, { pid: 7770 }, { pid: 1156 });
    expect(edrFacts(moved).proc.pid).toBe(1156);
    expect(moved.raw!.ProcessId).toBe("1156");
  });
});
