// Field filters from an open log (Tal, 2026-10-28): ＋ keeps the logs with that value in the same
// field, − hides them; native fields when the source has a native view, else the SIEM rows.
import { describe, it, expect } from "vitest";
import { fieldRowsOf, matchesFieldFilter } from "./EventFeed";
import type { LiveEvent } from "./useLiveEvents";
import type { NativeRenderer } from "@/lib/logs/native/NativeLogContext";

const ev = (id: string, hostname: string, raw: Record<string, unknown>) =>
  ({ id, ts: "2026-10-28T10:00:00Z", source: "edr", event_type: "process_start", description: "x", severity: "high", hostname, user_email: "d.torres@corp.example", raw }) as unknown as LiveEvent;
const a = ev("1", "WS-HR-1182", { "process.name": "powershell.exe" });
const b = ev("2", "WS-SALES-1876", { "process.name": "chrome.exe" });
const rows = (e: LiveEvent, r: NativeRenderer | null = null) => () => fieldRowsOf(e, r);

describe("field filters", () => {
  it("a Basic Information row filters on the event itself", () => {
    const f = { field: "@hostname", value: "WS-HR-1182" };
    expect(matchesFieldFilter(a, f, rows(a))).toBe(true);
    expect(matchesFieldFilter(b, f, rows(b))).toBe(false);
    expect(matchesFieldFilter(b, { ...f, exclude: true }, rows(b))).toBe(true);
  });

  it("a log field matches the same field and value on other logs", () => {
    expect(matchesFieldFilter(a, { field: "host.name", value: "WS-HR-1182" }, rows(a))).toBe(true);
    expect(matchesFieldFilter(b, { field: "process.name", value: "powershell.exe" }, rows(b))).toBe(false);
    expect(matchesFieldFilter(a, { field: "process.name", value: "powershell.exe", exclude: true }, rows(a))).toBe(false);
  });

  it("native fields match across array positions", () => {
    const render: NativeRenderer = e => ({ product: "CrowdStrike Falcon", log: { record: { event_simpleName: "ProcessRollup2", ComputerName: e.hostname, children: [{ FileName: e.id === "1" ? "rundll32.exe" : "x.exe" }] } } as never });
    expect(matchesFieldFilter(a, { field: "children[3].FileName", value: "rundll32.exe" }, rows(a, render))).toBe(true);
    expect(matchesFieldFilter(b, { field: "ComputerName", value: "WS-HR-1182" }, rows(b, render))).toBe(false);
  });
});
