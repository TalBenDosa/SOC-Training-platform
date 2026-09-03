import { describe, it, expect } from "vitest";
import { buildInvestigationFromStory } from "./fromLiveStory";
import { buildProcessTree } from "./investigations";
import { lookupHash } from "@/lib/sim/hashDatabase";
import type { TelemetryEvent } from "@/lib/sim/types";
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
