/**
 * One story, every console (LOG-REALISM-STANDARD R3, R4, R6). Stories of every company go through
 * the Live Feed path and the Team Training path, and what each console prints is compared with the
 * feed rows of the same story:
 *  - Live Feed: instantiate, label for the stack (canonical pids), re-time per phase, enrich, render
 *    the native record (what the feed shows) and build the EDR case from the same injected rows (what
 *    "Investigate in EDR" opens), exactly as dashboard/page.tsx and useLiveEvents.ts do.
 *  - Team Training: the session timeline, every row re-timed to its release, then the XDR workspace,
 *    the per-host EDR cases and the forensic workbench's memory image, from those same rows.
 * Checked: the clock of every process (console = feed), the host and its address, and the pid,
 * command line and SHA-256 of every process the console takes from a feed row.
 *
 * Disagreements that come from the shared native modules (a record that prints another pid than the
 * row, two invocations of one image given one canonical pid) are counted against KNOWN_SHARED below:
 * those numbers may only go down (the fixes are listed in the consoles report, "Shared changes needed").
 */
import { describe, expect, it } from "vitest";
import { instantiateStory, storiesForCompany } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { enrichEvent } from "@/app/(app)/dashboard/liveEventEnrich";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { applyStack, nativeView } from "@/lib/logs/native";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import { buildWorkspace } from "@/lib/sentinel/workspace";
import { buildEvidenceView } from "@/lib/forensics/workbench";
import { buildInvestigationFromStory } from "./fromLiveStory";
import { buildTeamEdrCases } from "./teamCases";
import { runRtrCommand } from "./rtr";
import { compareEdrToFeed, feedClock, isEndpoint, seenProcesses, type Disagreement } from "./consoleAgreement.testkit";

function seeded(n: number) { let s = n >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; }; }
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;

/** "pid sophos/detection", "cmdline", "time" ... */
const category = (d: Disagreement) => {
  const kind = d.what.split(":")[0];
  const rec = d.what.match(/feed record (\S+?)\//)?.[1];
  return kind === "pid" && rec ? `pid ${rec}` : kind;
};
function tally(ds: Disagreement[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const d of ds) out[category(d)] = (out[category(d)] ?? 0) + 1;
  return out;
}

/**
 * Shared-module disagreements still open (2026-11-09), per category, summed over both paths. Each
 * number may only go down. pid sophos / sysmon / linux_auditd / mde: the record derives its pid
 * again on the re-timed row instead of printing the row's canonical pid (procPid shownPid not passed).
 * cmdline: two invocations of one image in one incident share one canonical pid (procKey has no
 * per-invocation instance). hash: the record prints the thread's hash of another row of the story.
 */
const KNOWN_SHARED: Record<string, number> = {
  // 2026-11-09 (realism phase 2): Sophos / Sysmon / auditd / MDE pids, the reg.exe and cmd.exe
  // instances and the sideload hash all agree now. Left: RocketStack's noise pool runs python3 twice
  // on LAP-007 the same day (migration script, load test), one canonical pid outside any incident.
  cmdline: 1,
};

// ── Live Feed → EDR console ─────────────────────────────────────────────────
const live: Disagreement[] = [];
const liveHosts: string[] = [];
let liveCases = 0;
for (const c of COMPANY_PROFILES) {
  const pool = c.id === "nexacorp" ? BENIGN_EVENTS : (COMPANY_EVENTS[c.id] ?? BENIGN_EVENTS);
  const edr = (c.architecture as { edr?: string } | undefined)?.edr;
  for (const base of storiesForCompany(c.id)) {
    const s = instantiateStory(base, pool, edr, c.id, seeded(base.id.length * 31 + c.id.length));
    const t0 = Date.parse("2026-11-09T10:00:00Z");
    // Labelled for the stack, then re-timed by the scheduler in story order (useLiveEvents injectNextPhase).
    const injected = s.events.map(e => applyStack(e, c.id, {}))
      .map((e, i) => ({ ...withRebasedTime(e, new Date(t0 + i * 37_000).toISOString(), { storyClock: "local" }), id: `atk_${e.id}_${i}` }));
    const inv = buildInvestigationFromStory({ id: s.id, title: s.title, events: injected });
    if (!inv) continue;
    liveCases++;
    const feed = injected.map((e, i) => { const row = enrichEvent(e, i) as TelemetryEvent; return { ev: row, log: nativeView(row, c.id, {})?.log ?? null }; });
    live.push(...compareEdrToFeed(inv, feed, `live ${c.id}/${s.id}`));
    if (inv.host.ip !== "-" && !PRIVATE.test(inv.host.ip)) liveHosts.push(`${c.id}/${s.id}: host ${inv.host.name} shows address ${inv.host.ip}`);
    // RTR ps prints the tree's own pids for the processes the feed shows.
    const ps = runRtrCommand("ps", { inv, killed: new Set(), isolated: false })!.out;
    for (const p of seenProcesses(inv)) if (!new RegExp(`^${p.pid}\\s.*\\s${p.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m").test(ps))
      live.push({ where: `live ${c.id}/${s.id}`, what: `rtr: ps does not list ${p.name}(${p.pid})` });
  }
}

describe("Live Feed and the EDR console show one story", () => {
  it("covers every company", () => {
    expect(liveCases).toBeGreaterThan(40);
  });
  it("R4: a process starts in the console at the time the feed shows its first row", () => {
    expect(live.filter(d => category(d) === "time").map(d => `${d.where}: ${d.what}`)).toEqual([]);
  });
  it("R3: the console's host is a feed host, its address the host's own internal one, its users in the feed's realm", () => {
    expect(live.filter(d => ["host", "user"].includes(category(d))).map(d => `${d.where}: ${d.what}`)).toEqual([]);
    expect(liveHosts).toEqual([]);
  });
  it("R6: RTR ps lists every process of the tree under its pid", () => {
    expect(live.filter(d => category(d) === "rtr").map(d => `${d.where}: ${d.what}`)).toEqual([]);
  });
});

// ── Team Training → XDR, EDR, workbench ─────────────────────────────────────
const ROSTER = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
const T0 = Date.parse("2026-11-09T08:00:00Z");
const team: Disagreement[] = [];
let teamCases = 0, xdrChecked = 0, wbChecked = 0;
for (const [company, seed] of [["nexacorp", "agree-1"], ["medcore", "agree-2"], ["globallogis", "agree-3"], ["rocketstack", "agree-4"], ["quantumbank", "agree-5"]] as const) {
  const tl = buildTeamTimeline(company, "hard", seed, null, teamLoad("hard", ROSTER), {}).filter(t => t.channel === "feed");
  // What the team page and the XDR window build from: every payload re-timed to its release.
  const evs = tl.map(t => withRebasedTime(t.body as unknown as TelemetryEvent, new Date(T0 + t.due_offset_ms).toISOString()));
  const feed = evs.map((e, i) => { const row = enrichEvent(e, i) as TelemetryEvent; return { ev: row, log: nativeView(row, company, {})?.log ?? null }; });
  const ws = buildWorkspace(evs, { companyId: company, baseline: false });
  const dpe = ws.tables.DeviceProcessEvents?.rows ?? [];
  const hosts = [...new Set(evs.filter(e => isEndpoint(e) && e.process?.pid != null && e.hostname).map(e => e.hostname!))];
  for (const h of hosts) {
    const [inv] = buildTeamEdrCases(evs, { sessionId: "s", hosts: [h] });
    if (!inv) continue;
    teamCases++;
    team.push(...compareEdrToFeed(inv, feed, `team ${company}/${h}`));
    // XDR: the DeviceProcessEvents row of a process carries the console's pid, image, command line, hash and time.
    for (const p of seenProcesses(inv)) {
      const rows = dpe.filter(r => String(r.DeviceName ?? "").split(".")[0].toLowerCase() === h.split(".")[0].toLowerCase() && Number(r.ProcessId) === p.pid);
      for (const r of rows) {
        xdrChecked++;
        if (String(r.FileName ?? "").toLowerCase() !== p.name.toLowerCase()) team.push({ where: `xdr ${company}/${h}`, what: `xdr-image: console ${p.name}(${p.pid}), DeviceProcessEvents FileName ${r.FileName}` });
        if (p.sha256 && r.SHA256 && String(r.SHA256).toLowerCase() !== p.sha256.toLowerCase()) team.push({ where: `xdr ${company}/${h}`, what: `hash: console ${p.name}(${p.pid}) ${p.sha256.slice(0, 12)}, DeviceProcessEvents ${String(r.SHA256).slice(0, 12)}` });
      }
      const first = rows.map(r => String(r.Timestamp ?? r.TimeGenerated)).sort()[0];
      if (first && p.startedMs !== undefined && Math.abs(Date.parse(first) - p.startedMs) > 1000)
        team.push({ where: `xdr ${company}/${h}`, what: `time: console ${p.name}(${p.pid}) started ${new Date(p.startedMs).toISOString()}, DeviceProcessEvents ${first}` });
    }
    // Workbench: the memory image taken at the end of the shift lists the same processes, parents and start instants.
    const end = T0 + Math.max(...tl.map(t => t.due_offset_ms)) + 60_000;
    const feedRows = evs.map(ev => ({ ev, atMs: Date.parse(ev.ts) }));
    const view = buildEvidenceView({ feed: feedRows, host: h, evidenceId: "MEM-1", kind: "memory", snapshotMs: end, state: { isolatedAtMs: null, kills: [] }, sessionId: "s" });
    const pslist = view.tables.find(t => t.plugin === "windows.pslist");
    if (!pslist) continue;
    const wbInv = pslist;
    for (const p of seenProcesses(inv)) {
      const row = wbInv.rows.find(r => r[0] === p.pid);
      wbChecked++;
      if (!row) { team.push({ where: `workbench ${company}/${h}`, what: `workbench: pslist has no ${p.name}(${p.pid})` }); continue; }
      if (row[1] !== p.ppid || row[2] !== p.name) team.push({ where: `workbench ${company}/${h}`, what: `workbench: pslist ${row[2]}(${row[0]}) ppid ${row[1]}, console ${p.name} ppid ${p.ppid}` });
      if (p.startedMs !== undefined && row[8] !== `${new Date(p.startedMs).toISOString().replace("T", " ").slice(0, 19)}.000000 UTC`)
        team.push({ where: `workbench ${company}/${h}`, what: `time: pslist CreateTime ${row[8]}, console started ${feedClock(new Date(p.startedMs).toISOString())}` });
    }
  }
}

describe("Team Training: XDR, EDR and the workbench show one story", () => {
  it("covers the companies' endpoint hosts", () => {
    expect(teamCases).toBeGreaterThan(5);
    expect(wbChecked).toBeGreaterThan(5);
  });
  it("R4: every console prints the instant the feed shows", () => {
    expect(team.filter(d => category(d) === "time").map(d => `${d.where}: ${d.what}`)).toEqual([]);
  });
  it("R6: XDR's DeviceProcessEvents and the workbench name each process as the EDR console does", () => {
    expect(team.filter(d => ["xdr-image", "workbench", "host", "user"].includes(category(d))).map(d => `${d.where}: ${d.what}`)).toEqual([]);
    expect(xdrChecked).toBeGreaterThan(0);
  });
});

describe("shared-module disagreements only go down", () => {
  it("pid, command line and hash disagreements stay within the reviewed baseline", () => {
    const all = tally([...live, ...team]);
    const over = Object.entries(all).filter(([k]) => !["time", "host", "user", "rtr", "xdr-image", "workbench"].includes(k))
      .filter(([k, n]) => n > (KNOWN_SHARED[k] ?? 0)).map(([k, n]) => `${k}: ${n} > ${KNOWN_SHARED[k] ?? 0}`);
    expect(over, JSON.stringify(all)).toEqual([]);
  });
});

describe("R3: the console's account realm is the company's own", () => {
  it("a MedCore user reads MEDCORE\\user (medcorehealth.org), not MEDCOREHEALTH\\user", () => {
    const ev = (o: Partial<TelemetryEvent>): TelemetryEvent => ({
      id: o.id ?? "e", ts: "2026-11-09T10:00:00Z", source: "edr", event_type: "process_create", severity: "medium",
      hostname: "WS-NURS-044", user_email: "m.verhoeven@medcorehealth.org", ...o,
    } as TelemetryEvent);
    const inv = buildInvestigationFromStory({ id: "realm", title: "realm", events: [
      ev({ id: "a", process: { pid: 4100, name: "winword.exe", user: "m.verhoeven", cmdline: "WINWORD.EXE" } as TelemetryEvent["process"] }),
      ev({ id: "b", ts: "2026-11-09T10:01:00Z", process: { pid: 4200, parent_pid: 4100, parent_name: "winword.exe", name: "powershell.exe", user: "m.verhoeven", cmdline: "powershell.exe -nop" } as TelemetryEvent["process"] }),
    ] })!;
    expect(inv.processes.find(p => p.pid === 4200)?.user).toBe("MEDCORE\\m.verhoeven");
  });
});
