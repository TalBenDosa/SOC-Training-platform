import { describe, it, expect } from "vitest";
import { runRtrCommand, hostProcesses } from "./rtr";
import { buildInvestigationFromStory, buildInvestigationsFromScenario } from "./fromLiveStory";
import { EDR_INVESTIGATIONS, type EdrInvestigation } from "./investigations";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildMultiHostIntrusionScenario } from "@/lib/sim/scenario-packs/multiHostIntrusion";
import { buildScheduledTaskPersistenceScenario } from "@/lib/sim/scenario-packs/scheduledTaskPersistence";
import { buildTrojanizedInstallerKeyloggerScenario } from "@/lib/sim/scenario-packs/trojanizedInstallerKeylogger";

const run = (inv: EdrInvestigation, cmd: string, killed: Set<number> = new Set(), isolated = false) =>
  runRtrCommand(cmd, { inv, killed, isolated })!;

const mhi = buildInvestigationsFromScenario({ title: "mhi", events: buildMultiHostIntrusionScenario().events });
const fs = mhi.find(i => i.host.name === "FS-SRV-03")!;
const ws = mhi.find(i => i.host.name === "FIN-WS-08")!;

describe("RTR ps — normal background processes (#24)", () => {
  it("lists the Windows session-0 system processes and several svchost next to the case's processes", () => {
    const out = run(fs, "ps").out;
    for (const name of ["System", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "spoolsv.exe", "CSFalconService.exe"])
      expect(out, name).toMatch(new RegExp(`\\s${name.replace(".", "\\.")}$`, "m"));
    expect((out.match(/\ssvchost\.exe$/gm) ?? []).length).toBeGreaterThanOrEqual(5);
    for (const p of fs.processes) expect(out).toMatch(new RegExp(`^${p.pid}\\s`, "m"));
  });

  it("is deterministic and uses Windows-style PIDs", () => {
    expect(run(fs, "ps").out).toBe(run(fs, "ps").out);
    const procs = hostProcesses(fs, new Set());
    const background = procs.filter(p => !fs.processes.some(x => x.pid === p.pid));
    expect(background.every(p => p.pid % 4 === 0)).toBe(true);
    expect(new Set(procs.map(p => p.pid)).size).toBe(procs.length);
  });

  it("prints the lsass.exe PID the LSASS-dump event targeted", () => {
    // Falcon's handle-op record names the target image only; the story keeps the target pid as a fact.
    const tpid = buildMultiHostIntrusionScenario().events.find(e => e.raw?.["crowdstrike.TargetProcessImageFileName"] === "lsass.exe")?.process?.target?.pid;
    expect(tpid).toBeTruthy();
    expect(run(fs, "ps").out).toMatch(new RegExp(`^${tpid}\\s.*lsass\\.exe$`, "m"));
  });

  it("a workstation has no server-only services; a server does", () => {
    expect(run(ws, "ps").out).not.toMatch(/dfssvc\.exe/);
    expect(run(fs, "ps").out).toMatch(/dfssvc\.exe/);
  });

  it("refuses to kill a critical system process, but kills the payload", () => {
    const lsass = hostProcesses(fs, new Set()).find(p => p.name === "lsass.exe")!;
    expect(run(fs, `kill ${lsass.pid}`).kill).toBeUndefined();
    expect(run(fs, `kill ${fs.answer.pid}`).kill).toBe(fs.answer.pid);
    expect(run(fs, "ps", new Set([fs.answer.pid])).out).not.toMatch(new RegExp(`^${fs.answer.pid}\\s`, "m"));
  });
});

describe("RTR persistence checks (#24)", () => {
  it("reg query Run shows the benign baseline when the story has no Run-key persistence", () => {
    const out = run(fs, "reg query Run").out;
    expect(out).toMatch(/HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/);
    expect(out).toMatch(/SecurityHealth/);
  });

  it("reg query Run reflects the story's Run-key persistence alongside the benign entries", () => {
    const s = buildTrojanizedInstallerKeyloggerScenario();
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    const runEv = s.events.find(e => e.registry?.path && /\\Run$/i.test(e.registry.path))!;
    expect(runEv).toBeDefined();
    const out = run(inv, "reg query Run").out;
    expect(out).toContain(runEv.registry!.key!);
    expect(out).toContain(runEv.registry!.value!);
    expect(out).toMatch(/OneDrive|SecurityHealth/);            // benign neighbours
    // hive filter
    expect(run(inv, "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run").out).not.toContain(runEv.registry!.key!);
  });

  it("schtasks /query lists the story's malicious task among the built-in Microsoft tasks", () => {
    const s = buildScheduledTaskPersistenceScenario();
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    const out = run(inv, "schtasks /query").out;
    expect(out).toMatch(/\\NetFixOptimizer/);
    expect(out).toMatch(/\\Microsoft\\Windows\\/);
    expect(run(inv, "schtasks /query /v").out).toMatch(/Task To Run:\s+C:\\Users\\.*netfix_agent\.exe/);
  });

  it("sc query / sc qc show the PsExec service installed by the lateral move", () => {
    expect(run(fs, "sc query").out).toMatch(/SERVICE_NAME: PSEXESVC/);
    expect(run(fs, "sc query").out).toMatch(/SERVICE_NAME: CSFalconService/);
    expect(run(fs, "sc qc PSEXESVC").out).toMatch(/BINARY_PATH_NAME\s+: %SystemRoot%\\PSEXESVC\.exe/);
    expect(run(fs, "sc qc NoSuchSvc").out).toMatch(/1060/);
  });

  it("the WMI check shows only the built-in SCM filter — and a planted subscription when the story has one", () => {
    expect(run(fs, "wmi").out).toMatch(/SCM Event Log Filter/);
    expect(run(fs, "wmi").out).toMatch(/1 event filter/);
    const story = { id: "wmi", title: "wmi", events: [
      { id: "w1", ts: "2026-09-01T10:00:00Z", source: "edr", vendor: "CrowdStrike Falcon", hostname: "WS-9", event_type: "process_create", severity: "high",
        process: { pid: 5000, name: "powershell.exe", parent_pid: 4000, parent_name: "explorer.exe",
          cmdline: "powershell Set-WmiInstance -Class __EventFilter -Arguments @{Name='Updater';Query='SELECT * FROM __InstanceModificationEvent WITHIN 60'}; CommandLineEventConsumer CommandLineTemplate='C:\\ProgramData\\u.exe'" },
        raw: {} },
    ] as TelemetryEvent[] };
    const inv = buildInvestigationFromStory(story)!;
    const out = run(inv, "wmi").out;
    expect(out).toMatch(/Updater/);
    expect(out).toMatch(/C:\\ProgramData\\u\.exe/);
    expect(out).toMatch(/2 event filter/);
  });
});

describe("RTR basics stay intact", () => {
  it("netstat shows the case's connections plus normal listeners, and nothing once contained", () => {
    const out = run(ws, "netstat").out;
    expect(out).toMatch(/LISTENING\s+System\(4\)/);
    expect(out).toMatch(/powershell\.exe\(\d+\) ->/);
    expect(run(ws, "netstat", new Set(), true).out).toMatch(/network-contained/);
  });

  it("works for the built-in practice cases (no background stored on them)", () => {
    for (const inv of EDR_INVESTIGATIONS) {
      expect(run(inv, "ps").out.split("\n").length).toBeGreaterThan(inv.processes.length + 5);
      expect(run(inv, "help").out).toMatch(/schtasks/);
    }
    const linux = EDR_INVESTIGATIONS.find(i => /ubuntu|linux/i.test(i.host.os))!;
    expect(run(linux, "schtasks /query").out).toMatch(/Linux host/);
    expect(run(linux, "ps").out).toMatch(/\ssystemd$/m);
  });

  it("contain / clear / unknown", () => {
    expect(run(ws, "contain").contain).toBe(true);
    expect(run(ws, "contain", new Set(), true).contain).toBeUndefined();
    expect(run(ws, "clear").clear).toBe(true);
    expect(run(ws, "frobnicate").out).toMatch(/unknown command/);
    expect(runRtrCommand("   ", { inv: ws, killed: new Set(), isolated: false })).toBeNull();
  });
});
