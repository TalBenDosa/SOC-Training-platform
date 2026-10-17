import { describe, it, expect } from "vitest";
import { runRtrCommand } from "./rtr";
import { buildInvestigationsFromScenario } from "./fromLiveStory";
import { EDR_INVESTIGATIONS, type EdrInvestigation } from "./investigations";
import { buildMultiHostIntrusionScenario } from "@/lib/sim/scenario-packs/multiHostIntrusion";

const run = (inv: EdrInvestigation, cmd: string, killed: Set<number> = new Set(), isolated = false) =>
  runRtrCommand(cmd, { inv, killed, isolated })!.out;

const mhi = buildInvestigationsFromScenario({ title: "mhi", events: buildMultiHostIntrusionScenario().events });
const ws = mhi.find(i => i.host.name === "FIN-WS-08")!;
const fin = EDR_INVESTIGATIONS.find(i => i.host.name === "FIN-WS-07")!;
const nix = EDR_INVESTIGATIONS.find(i => /ubuntu/i.test(i.host.os))!;

describe("netstat with switches prints the real Windows table", () => {
  it("netstat -ano: header, listeners with PIDs, the case's connection with its PID, no image names", () => {
    const out = run(fin, "netstat -ano");
    const lines = out.split("\n");
    expect(lines.slice(0, 4)).toEqual(["", "Active Connections", "",
      "  Proto  Local Address          Foreign Address        State           PID"]);
    expect(out).toMatch(/^ {2}TCP {4}0\.0\.0\.0:445 {12}0\.0\.0\.0:0 {14}LISTENING {7}4$/m);
    expect(out).toMatch(/^ {2}TCP {4}0\.0\.0\.0:135 +0\.0\.0\.0:0 +LISTENING +\d+$/m);
    const c2 = fin.processes.find(p => p.network?.some(c => c.remote_ip === "45.137.22.19" && c.remote_port === 443))!;
    expect(out).toMatch(new RegExp(`^  TCP    10\\.20\\.4\\.71:\\d{5} +45\\.137\\.22\\.19:443 +ESTABLISHED +${c2.pid}$`, "m"));
    expect(out).not.toMatch(/\.exe/);
    // one row per endpoint: three TLS beacons to the same server are one socket
    expect(out.match(/45\.137\.22\.19:443/g)!.length).toBe(1);
    expect(out).toBe(run(fin, "netstat -ano"));   // deterministic ephemeral ports
  });

  it("switches behave like Windows: -a adds listeners, -o the PID, -b the image, no -n resolves names", () => {
    expect(run(fin, "netstat -n")).not.toMatch(/LISTENING|UDP/);
    expect(run(fin, "netstat -an")).not.toMatch(/PID/);
    const named = run(fin, "netstat -a");
    expect(named).toMatch(/cdn-msupdate\.info:https\s+ESTABLISHED/);
    expect(named).toMatch(/0\.0\.0\.0:445\s+FIN-WS-07:0\s+LISTENING/);
    const b = run(fin, "netstat -anob");
    expect(b).toMatch(/LISTENING\s+4\n Can not obtain ownership information/);
    expect(b).toMatch(/ESTABLISHED\s+\d+\n \[[^\]]+\.exe\]/);
    expect(run(fin, "netstat -ano -p udp")).not.toMatch(/TCP/);
    expect(run(fin, "netstat /ano")).toMatch(/Active Connections/);
  });

  it("killed processes and a contained host drop their connections; listeners stay", () => {
    const c2 = fin.processes.find(p => p.network?.some(c => c.remote_ip === "45.137.22.19" && c.remote_port === 443))!;
    expect(run(fin, "netstat -ano", new Set([c2.pid]))).not.toMatch(new RegExp(`ESTABLISHED +${c2.pid}$`, "m"));
    const contained = run(fin, "netstat -ano", new Set(), true);
    expect(contained).not.toMatch(/ESTABLISHED/);
    expect(contained).toMatch(/LISTENING/);
  });

  it("works for every scenario-built Windows host and for unknown switches", () => {
    expect(run(ws, "netstat -ano")).toMatch(/^ {2}TCP +\d+\.\d+\.\d+\.\d+:\d+ +\d+\.\d+\.\d+\.\d+:\d+ +ESTABLISHED +\d+$/m);
    expect(run(fin, "netstat -r")).toMatch(/supports -a, -n, -o, -b/);
    expect(run(fin, "netstat")).toMatch(/LISTENING\s+System\(4\)/);   // bare netstat: the summary view
  });
});

describe("netstat with switches prints the real Linux table on Linux hosts", () => {
  it("netstat -tulpn: net-tools header, sshd listener, the outbound connection with PID/Program name", () => {
    const out = run(nix, "netstat -tulpn");
    const lines = out.split("\n");
    expect(lines[0]).toBe("Active Internet connections (only servers)");
    expect(lines[1]).toBe("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name");
    expect(out).toMatch(/^tcp {8}0 {6}0 0\.0\.0\.0:22 {14}0\.0\.0\.0:\* {15}LISTEN {6}\d+\/sshd$/m);
    expect(out).not.toMatch(/ESTABLISHED/);
    const est = run(nix, "netstat -antp");
    expect(est).toMatch(/^tcp +0 +0 10\.30\.2\.15:\d+ +91\.215\.85\.17:443 +ESTABLISHED +\d+\/\S+$/m);
    expect(run(nix, "netstat -ant")).not.toMatch(/PID\/Program name/);
    expect(run(nix, "netstat -ano")).toMatch(/supports -a, -t, -u, -l, -n and -p/);
  });
});
