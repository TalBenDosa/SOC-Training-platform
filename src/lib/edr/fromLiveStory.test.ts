import { describe, it, expect } from "vitest";
import { buildInvestigationFromStory, buildInvestigationsFromScenario } from "./fromLiveStory";
import { buildProcessTree, incidentScore } from "./investigations";
import { buildHostBaseline } from "./hostBaseline";
import { buildMultiHostIntrusionScenario } from "@/lib/sim/scenario-packs/multiHostIntrusion";
import { lookupHash } from "@/lib/sim/hashDatabase";
import type { TelemetryEvent } from "@/lib/sim/types";
import { isConclusionRawKey } from "@/lib/scenarios/withheld";
import {
  buildPhishingMalwareScenario, buildMaliciousMacroScenario, buildCrackedSoftwareScenario,
  buildUsbMalwareScenario, buildImpossibleTravelScenario, buildOAuthScenario,
} from "@/lib/sim/scenarios";

const hasProcess = (events: TelemetryEvent[]) =>
  events.some(e => e.process?.name && typeof e.process.pid === "number");

// Real live-feed attack stories, exactly as the dashboard would hand them over.
const ENDPOINT_STORIES = [
  ["phishing-malware", buildPhishingMalwareScenario()],
  ["malicious-macro", buildMaliciousMacroScenario()],
  ["cracked-software", buildCrackedSoftwareScenario()],
  ["usb-malware", buildUsbMalwareScenario()],
] as const;

const IDENTITY_STORIES = [
  ["impossible-travel", buildImpossibleTravelScenario()],
  ["oauth", buildOAuthScenario()],
] as const;

describe("buildInvestigationFromStory", () => {
  it.each(ENDPOINT_STORIES.map(([id, b]) => [id, b] as const))(
    "builds a valid endpoint investigation from the live story: %s",
    (id, bundle) => {
      const inv = buildInvestigationFromStory({ id, title: bundle.title, events: bundle.events });

      // These stories carry endpoint process telemetry, so a tree must exist.
      if (!hasProcess(bundle.events)) return; // guarded: some builders may not
      expect(inv).not.toBeNull();
      if (!inv) return;

      const pids = new Set(inv.processes.map(p => p.pid));
      expect(inv.processes.length).toBeGreaterThan(0);
      expect(inv.timeline.length).toBeGreaterThan(0);

      // Every detection points at a process that exists in the tree.
      for (const d of inv.detections) expect(pids.has(d.pid)).toBe(true);

      // The payload is either "false positive" (-1) or a real process.
      expect(inv.answer.pid === -1 || pids.has(inv.answer.pid)).toBe(true);

      // The tree is well-formed (at least one root, no dangling children).
      const { roots } = buildProcessTree(inv.processes);
      expect(roots.length).toBeGreaterThan(0);

      // KEY correctness property: if any process carries a known-bad hash, the
      // flagged payload must be one of those malicious-hash processes.
      const malPids = inv.processes.filter(p => p.sha256 && lookupHash(p.sha256)?.malicious).map(p => p.pid);
      if (malPids.length > 0) {
        expect(malPids).toContain(inv.answer.pid);
        expect(inv.processes.find(p => p.pid === inv.answer.pid)!.verdict).toBe("malicious");
      }
    },
  );

  it.each(IDENTITY_STORIES.map(([id, b]) => [id, b] as const))(
    "returns null for identity/cloud stories with no process tree: %s",
    (id, bundle) => {
      // Only assert null when the story genuinely has no endpoint process events.
      if (hasProcess(bundle.events)) return;
      expect(buildInvestigationFromStory({ id, title: bundle.title, events: bundle.events })).toBeNull();
    },
  );

  it("returns null on an empty story", () => {
    expect(buildInvestigationFromStory({ id: "x", title: "x", events: [] })).toBeNull();
  });

  // The EDR is an investigation tool — its ATTACK content MUST be tied to the case the
  // student saw in the feed. Every attack entity it shows (host, the payload and any
  // flagged process, hashes, C2 domains) has to come from the story's own telemetry,
  // never invented. Two classes of node are LEGITIMATELY synthetic and exempt from the
  // name check: (1) benign tree-root parents (explorer.exe / services.exe / bash) added
  // so a child process isn't shown at PID 0, and (2) benign "look-twice" distractors
  // seeded into a thin tree so flagging the payload is a decision — both are always
  // verdict:"benign", carry no hash and no network, and are never the answer. Hashes and
  // C2 domains are checked for EVERY node, so no invented IOC can slip through.
  it("keeps the EDR strictly tied to the log — no invented attack entities", () => {
    // process/parent names can live in the structured field OR the vendor raw block
    // (a detection whose process was only in crowdstrike.process_name, recovered by R-11).
    const RAW_NAME_KEYS = ["process.name", "process.image", "crowdstrike.process_name",
      "crowdstrike.ImageFileName", "s1.process_name", "Image", "InitiatingProcessFileName",
      "proc.name", "ProcessName", "crowdstrike.parent_basefilename", "ParentImage"];
    const base = (v: string) => v.split(/[\\/]/).pop() ?? v;
    for (const [id, b] of ENDPOINT_STORIES) {
      const inv = buildInvestigationFromStory({ id, title: b.title, events: b.events });
      if (!inv) continue;
      const log = new Set<string>();
      for (const e of b.events) {
        [e.hostname, e.src_ip, e.dst_ip, e.process?.name, e.process?.parent_name,
         e.process?.hash?.sha256, e.network?.domain].forEach(v => { if (v) log.add(v); });
        for (const k of RAW_NAME_KEYS) { const v = e.raw?.[k]; if (typeof v === "string" && v) log.add(base(v)); }
      }
      // Host, and every FLAGGED (non-benign) process name, must be from the log.
      if (inv.host.name !== "endpoint") expect(log.has(inv.host.name)).toBe(true);
      for (const p of inv.processes) {
        if (p.verdict !== "benign") expect(log.has(p.name)).toBe(true);
        if (p.sha256) expect(log.has(p.sha256)).toBe(true);   // no invented hash, ever
        for (const c of p.network ?? []) if (c.domain) expect(log.has(c.domain)).toBe(true); // no invented C2
      }
    }
  });

  // Guards the guards: prove the meaningful (non-null) path actually exercised —
  // at least one real endpoint story must yield a tree WITH detections, and at
  // least one must produce a real (non -1) malicious payload.
  it("actually generates real investigations from the live stories", () => {
    const invs = ENDPOINT_STORIES
      .map(([id, b]) => buildInvestigationFromStory({ id, title: b.title, events: b.events }))
      .filter(Boolean);
    expect(invs.length).toBeGreaterThan(0);
    expect(invs.some(inv => inv!.detections.length > 0)).toBe(true);
    expect(invs.some(inv => inv!.answer.pid > 0)).toBe(true);
  });
});

// ─── Exercise-report fixes (#8 lineage, #9 network attribution, #23 header, log-audit timeline) ───

// The client-side projection the scenario page ships (F-02): no description, no MITRE
// mapping, no expected verdict — the EDR console is built from THIS in the browser.
const project = (events: TelemetryEvent[]): TelemetryEvent[] => events.map(e => {
  const raw: Record<string, unknown> = { ...(e.raw ?? {}) };
  for (const k of Object.keys(raw)) if (isConclusionRawKey(k)) delete raw[k];
  return { ...e, description: undefined, mitre_technique: undefined, mitre_tactic: undefined, expected_verdict: undefined, raw };
});

const mhi = buildMultiHostIntrusionScenario();
type Inv = ReturnType<typeof buildInvestigationsFromScenario>[number];
const VIEWS: [string, Inv[]][] = [
  ["server (full events)", buildInvestigationsFromScenario({ title: mhi.title, events: mhi.events })],
  ["client (F-02 projection)", buildInvestigationsFromScenario({ title: mhi.title, events: project(mhi.events) })],
];
const byHost = (invs: Inv[], host: string) => invs.find(i => i.host.name === host)!;
const firstTsOfPid = (pid: number, host: string) =>
  mhi.events.filter(e => e.hostname === host && e.process?.pid === pid).map(e => e.ts).sort()[0];
const PERIMETER = new Set(["firewall", "proxy", "dns", "ids", "waf", "vpn", "nac", "email_gateway", "dhcp"]);

describe.each(VIEWS)("multi-host intrusion EDR cases — %s", (_label, invs) => {
  it("builds one isolated case per host", () => {
    expect(invs.map(i => i.host.name).sort()).toEqual(["BKP-SRV-02", "FIN-WS-08", "FS-SRV-03"]);
  });

  it("#8: no synthetic explorer.exe (PID 90000 / PPID 0) on any host", () => {
    for (const inv of invs) {
      expect(inv.processes.some(p => p.pid >= 90000)).toBe(false);
      // an explorer.exe may only appear when the telemetry names one
      const logged = mhi.events.some(e => e.hostname === inv.host.name &&
        (e.process?.name?.toLowerCase() === "explorer.exe" || e.process?.parent_name?.toLowerCase() === "explorer.exe"));
      if (!logged) expect(inv.processes.some(p => p.name.toLowerCase() === "explorer.exe")).toBe(false);
    }
  });

  it("#8: PSEXESVC runs as SYSTEM under services.exe, and ps prints that same services.exe", () => {
    const fs = byHost(invs, "FS-SRV-03");
    const psexe = fs.processes.find(p => p.name.toLowerCase() === "psexesvc.exe")!;
    expect(psexe).toBeDefined();
    const parent = fs.processes.find(p => p.pid === psexe.ppid);
    expect(parent?.name).toBe("services.exe");
    expect(psexe.user).toBe("NT AUTHORITY\\SYSTEM");
    expect(fs.host.os).toMatch(/Server/);
    // one services.exe across tree + RTR background
    const all = [...fs.processes, ...buildHostBaseline(fs)];
    expect(all.filter(p => p.name.toLowerCase() === "services.exe").map(p => p.pid)).toEqual([parent!.pid]);
  });

  it("#9: the C2 belongs to powershell (the beacon), not cmd.exe, and no connection predates its process", () => {
    const ws = byHost(invs, "FIN-WS-08");
    const ps = ws.processes.find(p => p.name.toLowerCase() === "powershell.exe")!;
    const cmd = ws.processes.find(p => p.name.toLowerCase() === "cmd.exe")!;
    expect(ps.network!.length).toBeGreaterThan(0);
    expect(cmd.network ?? []).toEqual([]);
    for (const inv of invs) for (const p of inv.processes) for (const c of p.network ?? []) {
      const start = firstTsOfPid(p.pid, inv.host.name);
      if (start) expect(c.ts >= start.slice(11, 19), `${p.name}(${p.pid}) conn ${c.ts} before start ${start}`).toBe(true);
    }
  });

  it("log audit: firewall lines stay out of the EDR timeline — one connection is shown once", () => {
    for (const inv of invs) {
      const endpointEvents = mhi.events.filter(e => e.incident_id === inv.id && !PERIMETER.has(e.source)).length;
      expect(inv.timeline.length).toBe(Math.min(20, endpointEvents));
      // netstat never lists the same remote endpoint twice
      const conns = inv.processes.flatMap(p => (p.network ?? []).map(c => `${c.remote_ip}:${c.remote_port}`)).filter(k => !k.startsWith("resolver"));
      expect(new Set(conns).size).toBe(conns.length);
      // timeline text is factual even when the description is stripped
      expect(inv.timeline.every(t => t.text.length > 12)).toBe(true);
    }
  });

  it("#23: the header derives from the detections — Critical, with the ATT&CK technique", () => {
    const want: Record<string, string> = { "FIN-WS-08": "T1059.001", "FS-SRV-03": "T1003.001", "BKP-SRV-02": "T1567.002" };
    for (const inv of invs) {
      const s = incidentScore(inv.detections);
      expect(s.band).toBe("Critical");
      expect(s.score).toBeGreaterThanOrEqual(90);
      expect(s.techniques).toContain(want[inv.host.name]);
    }
  });

  it("grading: every case has a real payload — 'resolve as benign' is never the right answer here", () => {
    for (const inv of invs) {
      expect(inv.answer.pid).toBeGreaterThan(0);
      expect(inv.processes.some(p => p.pid === inv.answer.pid)).toBe(true);
    }
  });

  it("#23: the renamed rclone carries its PE OriginalFileName into the process panel", () => {
    const bkp = byHost(invs, "BKP-SRV-02");
    expect(bkp.processes.filter(p => p.name === "svchost-update.exe").some(p => p.originalFileName === "rclone.exe")).toBe(true);
  });
});

describe("network attribution rules (#9) on a minimal story", () => {
  const base = { vendor: "CrowdStrike Falcon", hostname: "WS-1", src_ip: "10.0.0.5", raw: {} };
  const story = {
    id: "attr", title: "attr",
    events: [
      // a perimeter line BEFORE any process existed — must not be pinned on anything
      { ...base, id: "fw0", ts: "2026-09-01T10:00:00Z", source: "firewall", event_type: "net_connection", dst_ip: "203.0.113.10", dst_port: 443, network: { domain: "early.example" } },
      { ...base, id: "p1", ts: "2026-09-01T10:01:00Z", source: "edr", event_type: "process_create", severity: "low", process: { pid: 4100, name: "cmd.exe", parent_pid: 3000, parent_name: "explorer.exe", cmdline: "cmd /c x" } },
      { ...base, id: "p2", ts: "2026-09-01T10:01:05Z", source: "edr", event_type: "process_create", severity: "critical", is_detection: true, process: { pid: 4200, name: "powershell.exe", parent_pid: 4100, parent_name: "cmd.exe", cmdline: "powershell -enc AAA" } },
      // the sensor's connection names its process
      { ...base, id: "n1", ts: "2026-09-01T10:02:00Z", source: "edr", event_type: "net_connection", dst_ip: "203.0.113.20", dst_port: 443, process: { pid: 4200, name: "powershell.exe" }, network: { domain: "c2.example" } },
      // the firewall's view of the SAME connection — a duplicate, not a second row
      { ...base, id: "fw1", ts: "2026-09-01T10:02:10Z", source: "firewall", event_type: "net_connection", dst_ip: "203.0.113.20", dst_port: 443, network: { domain: "c2.example" } },
    ] as TelemetryEvent[],
  };
  const inv = buildInvestigationFromStory(story)!;

  it("attributes the sensor connection to the PID it names, once", () => {
    expect(inv.processes.find(p => p.pid === 4200)!.network!.map(c => c.remote_ip)).toEqual(["203.0.113.20"]);
    expect(inv.processes.find(p => p.pid === 4100)!.network).toEqual([]);
  });
  it("never gives a process traffic from before it existed", () => {
    expect(inv.processes.flatMap(p => p.network ?? []).some(c => c.remote_ip === "203.0.113.10")).toBe(false);
  });
  it("keeps the real explorer.exe as the user-app root (no invented PID)", () => {
    expect(inv.processes.find(p => p.pid === 3000)?.name).toBe("explorer.exe");
    expect(inv.processes.some(p => p.pid >= 90000)).toBe(false);
  });
  it("keeps firewall lines out of the endpoint timeline", () => {
    expect(inv.timeline.length).toBe(3);
  });
  it("does not mutate the caller's event array", () => {
    expect(story.events.length).toBe(5);
  });
});
