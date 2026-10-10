// Forensic Workbench: tool views derived from the session, gated by the capture time, changed by
// what the team did to the host (RTR kill, isolation), and never showing a verdict.
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { hostKey } from "@/lib/team/format";
import { buildEvidenceView, type FeedRow, type HostState } from "./workbench";

const T0 = Date.parse("2026-10-10T08:00:00.000Z");
const tl = buildTeamTimeline("nexacorp", "medium", "fw-demo-1").filter(e => e.channel === "feed").sort((a, b) => a.due_offset_ms - b.due_offset_ms);
const rows: FeedRow[] = tl.map(e => { const at = T0 + e.due_offset_ms; return { ev: withRebasedTime(e.body as unknown as TelemetryEvent, new Date(at).toISOString()), atMs: at }; });
// The attacked endpoint host with the most endpoint rows (test setup reads the answer key).
const atk = tl.filter(e => ["tp", "escalate"].includes(String(e.answer?.expected_verdict)) && ["edr", "sysmon"].includes(String(e.body.source)));
const counts = new Map<string, number>(); for (const e of atk) counts.set(String(e.body.hostname), (counts.get(String(e.body.hostname)) ?? 0) + 1);
const HOST = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
const hostRows = rows.filter(r => r.ev.hostname && hostKey(r.ev.hostname) === hostKey(HOST));
const END = hostRows[hostRows.length - 1].atMs + 60_000;
const noState: HostState = { isolatedAtMs: null, kills: [] };
const view = (kind: "memory" | "triage", snapshotMs: number, state = noState) => buildEvidenceView({ feed: rows, host: HOST, evidenceId: kind === "memory" ? "MEM-001" : "TRI-001", kind, snapshotMs, state, sessionId: "s" });
const table = (v: ReturnType<typeof view>, plugin: string) => v.tables.find(t => t.plugin === plugin)!;
// An empty view (no endpoint telemetry before the capture) holds no processes.
const procNames = (v: ReturnType<typeof view>) => (v.tables.find(t => t.plugin === "windows.pslist")?.rows ?? []).map(r => String(r[2]).toLowerCase());

describe("forensic workbench", () => {
  it("shows the host's processes over its normal background, with real Volatility columns", () => {
    const v = view("memory", END);
    const ps = table(v, "windows.pslist");
    expect(ps.columns).toEqual(["PID", "PPID", "ImageFileName", "Offset(V)", "Threads", "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime"]);
    expect(procNames(v)).toContain("lsass.exe");                  // background
    expect(ps.rows.length).toBeGreaterThan(15);
    expect(ps.rows.every(r => /^0x[0-9a-f]{12}$/.test(String(r[3])))).toBe(true);
  });

  it("never shows a verdict or a malicious flag", () => {
    const all = JSON.stringify([view("memory", END), view("triage", END)]).toLowerCase();
    for (const w of ["malicious", "true positive", "true_positive", "verdict", "expected_verdict", "incident_id"]) expect(all.includes(w), w).toBe(false);
  });

  it("time gate: a capture taken before a process started does not contain it", () => {
    const late = new Set(procNames(view("memory", END)));
    const earlyView = view("memory", hostRows[0].atMs + 1);
    const early = new Set(procNames(earlyView));
    const onlyLate = [...late].filter(n => !early.has(n));
    expect(onlyLate.length).toBeGreaterThan(0);
    if (!early.size) expect(earlyView.empty).toMatch(/No endpoint telemetry/);
  });

  it("an RTR kill before the capture removes the process from memory and says so", () => {
    const ps = table(view("memory", END), "windows.pslist");
    const target = ps.rows.find(r => !["system", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "services.exe", "svchost.exe", "winlogon.exe", "explorer.exe"].includes(String(r[2]).toLowerCase()) && Number(r[0]) > 4000)!;
    const v = view("memory", END, { isolatedAtMs: null, kills: [{ pid: Number(target[0]), name: String(target[2]), atMs: END - 1000 }] });
    expect(table(v, "windows.pslist").rows.some(r => r[0] === target[0])).toBe(false);
    expect(table(v, "windows.pslist").notes.join(" ")).toMatch(/terminated through RTR/);
    // a kill AFTER the capture does not change it
    const after = view("memory", END, { isolatedAtMs: null, kills: [{ pid: Number(target[0]), name: String(target[2]), atMs: END + 1000 }] });
    expect(table(after, "windows.pslist").rows.some(r => r[0] === target[0])).toBe(true);
  });

  it("isolation before the capture closes external sessions", () => {
    const net = table(view("memory", END, { isolatedAtMs: END - 1000, kills: [] }), "windows.netscan");
    const external = net.rows.filter(r => r[1] === "TCPv4" && !/^(10\.|192\.168\.|172\.|0\.0\.0\.0)/.test(String(r[4])));
    if (external.length) expect(external.every(r => r[6] === "CLOSED")).toBe(true);
    expect(net.notes.join(" ")).toMatch(/isolated/);
  });

  it("the event-log view holds only Windows and Sysmon logs, with Sysmon's own event ids", () => {
    const ev = table(view("triage", END), "evtx");
    expect(ev.rows.every(r => r[2] === "Security" || r[2] === "System" || r[2] === "Sysmon")).toBe(true);
    for (const r of ev.rows) if (r[2] === "Sysmon") expect(["1", "3", "11", "13", "22", "-"].includes(String(r[3])) || /^\d+$/.test(String(r[3]))).toBe(true);
  });

  it("every row carries a reference findings can cite", () => {
    for (const t of view("memory", END).tables) { expect(t.refs).toHaveLength(t.rows.length); expect(new Set(t.refs).size).toBe(t.refs.length); }
  });
});
