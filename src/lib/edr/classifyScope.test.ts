import { describe, it, expect } from "vitest";
import { classifyScope, isEdrInvestigable, isHostObservable, isControlPlane } from "./classifyScope";
import type { TelemetryEvent } from "@/lib/sim/types";

const ev = (e: Partial<TelemetryEvent>): TelemetryEvent =>
  ({ id: "e", ts: "2026-08-26T10:00:00Z", source: "edr", event_type: "process_create", ...e } as TelemetryEvent);

describe("classifyScope — three-way EDR triage", () => {
  it("endpoint-only malware (process tree) → edr", () => {
    const events = [
      ev({ source: "edr", event_type: "process_create", process: { name: "powershell.exe", pid: 1000 } }),
      ev({ source: "edr", event_type: "file_create", file: { path: "C:/x/p.exe" } }),
    ];
    expect(classifyScope(events)).toBe("edr");
    expect(isEdrInvestigable(classifyScope(events))).toBe(true);
  });

  it("brute force / spray AGAINST a server (host 4625) → edr, not non_edr", () => {
    // The user's correction: RDP/SSH/SMB spray on an endpoint is host-observable.
    const events = [
      ev({ source: "windows_security", event_type: "auth_failure", hostname: "SRV-FS-01" }),
      ev({ source: "windows_security", event_type: "auth_failure", hostname: "SRV-FS-01" }),
      ev({ source: "windows_security", event_type: "account_create", hostname: "SRV-FS-01" }), // side-effect: new local admin
    ];
    expect(classifyScope(events)).toBe("edr");
  });

  it("password spray against a CLOUD IdP (no host) → non_edr", () => {
    const events = [
      ev({ source: "o365", event_type: "auth_failure", user_email: "a@corp.com" }),
      ev({ source: "o365", event_type: "auth_failure", user_email: "b@corp.com" }),
    ];
    expect(classifyScope(events)).toBe("non_edr");
    expect(isEdrInvestigable(classifyScope(events))).toBe(false);
  });

  it("Kerberoasting: DC auth (ad) + tool process on a host → hybrid", () => {
    const events = [
      ev({ source: "ad", event_type: "kerberos_tgs", hostname: "DC-01" }),
      ev({ source: "edr", event_type: "process_create", process: { name: "Rubeus.exe", pid: 4321 }, hostname: "WKS-07" }),
    ];
    expect(classifyScope(events)).toBe("hybrid");
  });

  it("C2: a PASSIVE firewall beacon log + host process → edr (transport is not a second plane)", () => {
    const events = [
      ev({ source: "firewall", event_type: "net_connection", dst_ip: "185.1.2.3" }),
      ev({ source: "edr", event_type: "process_create", process: { name: "svchost.exe", pid: 900 } }),
    ];
    expect(classifyScope(events)).toBe("edr");
  });

  it("C2: an ACTIVE network detection (IDS signature / block) + host process → hybrid", () => {
    const events = [
      ev({ source: "ids", event_type: "ids_signature", dst_ip: "185.1.2.3" }),
      ev({ source: "edr", event_type: "process_create", process: { name: "svchost.exe", pid: 900 } }),
    ];
    expect(classifyScope(events)).toBe("hybrid");
  });

  it("impossible travel (cloud sign-in only) → non_edr", () => {
    expect(classifyScope([ev({ source: "o365", event_type: "auth_success", user_email: "x@corp.com" })])).toBe("non_edr");
  });

  it("web drive-by (browser process + redirect network) → edr", () => {
    const events = [
      ev({ source: "edr", event_type: "process_create", process: { name: "chrome.exe", pid: 4821 } }),
      ev({ source: "edr", event_type: "http_request", network: { domain: "adnet-tracker.xyz", status: 302 } }),
    ];
    expect(classifyScope(events)).toBe("edr");
  });

  it("field-level helpers: a cloud sign-in is control-plane, a process event is host", () => {
    expect(isHostObservable(ev({ source: "o365", event_type: "auth_failure" }))).toBe(false);
    expect(isControlPlane(ev({ source: "o365", event_type: "auth_failure" }))).toBe(true);
    expect(isHostObservable(ev({ source: "edr", event_type: "process_create", process: { name: "p", pid: 1 } }))).toBe(true);
  });
});

// The derived classification must agree with the edr_scope the Phase-1b pilot
// packs authored explicitly on their detection — a guard against the classifier
// and the hand-annotated packs drifting apart.
describe("classifyScope agrees with the authored pilot packs", () => {
  it("trojanizedInstallerKeylogger (endpoint keylogger) → edr", async () => {
    const { buildTrojanizedInstallerKeyloggerScenario } = await import("@/lib/sim/scenario-packs/trojanizedInstallerKeylogger");
    expect(classifyScope(buildTrojanizedInstallerKeyloggerScenario().events)).toBe("edr");
  });
  it("seoPoisonedInstaller (web-redirect infostealer) → edr", async () => {
    const { buildSeoPoisonedInstallerScenario } = await import("@/lib/sim/scenario-packs/seoPoisonedInstaller");
    expect(classifyScope(buildSeoPoisonedInstallerScenario().events)).toBe("edr");
  });
  it("infostealerSessionTheft (host theft + identity replay) → hybrid", async () => {
    const { buildInfostealerSessionTheftScenario } = await import("@/lib/sim/scenario-packs/infostealerSessionTheft");
    expect(classifyScope(buildInfostealerSessionTheftScenario().events)).toBe("hybrid");
  });
});

// Phase 4 functional guard: for EVERY annotated scenario, the authored edr_scope
// must agree with what buildInvestigationsFromScenario can actually produce — an
// edr/hybrid incident must yield at least one walkable EDR case (a process tree),
// and a non_edr-only scenario must yield none. Catches an incident marked edr/hybrid
// that has no process telemetry to investigate (the button would never work).
describe("Phase 4 — authored edr_scope matches buildable EDR investigations", () => {
  it("holds across the whole scenario registry", async () => {
    const { SCENARIOS } = await import("@/lib/sim/scenarios");
    const { buildInvestigationsFromScenario } = await import("./fromLiveStory");
    const problems: string[] = [];
    for (const s of SCENARIOS as ReadonlyArray<{ slug: string; build: () => { events: TelemetryEvent[] } }>) {
      const bundle = s.build();
      const scopes = new Set(bundle.events.map(e => e.edr_scope).filter(Boolean));
      if (scopes.size === 0) continue; // un-annotated legacy scenario — skip
      const invs = buildInvestigationsFromScenario(bundle);
      const wantsEdr = scopes.has("edr") || scopes.has("hybrid");
      if (wantsEdr) {
        if (invs.length === 0) problems.push(`${s.slug}: scope ${[...scopes]} but 0 EDR investigations built`);
        else if (!invs.every(i => i.processes.length > 0)) problems.push(`${s.slug}: an EDR investigation has no process tree`);
      } else {
        if (invs.length !== 0) problems.push(`${s.slug}: non_edr only, yet ${invs.length} EDR investigation(s) built`);
      }
    }
    expect(problems, problems.join("\n")).toEqual([]);
  });
});

// Exercise-report guards (#8 / #9 / #23), across EVERY scenario and both the server
// build and the client-side F-02 projection (description / MITRE / verdict stripped):
// no invented explorer.exe root, service binaries under services.exe, no connection
// attributed to a process before it existed, every detection on a real tree node.
describe("EDR integrity — lineage and network attribution hold registry-wide", () => {
  it("holds for every buildable scenario case", async () => {
    const { SCENARIOS } = await import("@/lib/sim/scenarios");
    const { buildInvestigationsFromScenario } = await import("./fromLiveStory");
    const project = (events: TelemetryEvent[]) => events.map(e => ({ ...e, description: undefined, mitre_technique: undefined, mitre_tactic: undefined, expected_verdict: undefined }));
    const problems: string[] = [];
    let cases = 0;
    for (const s of SCENARIOS as ReadonlyArray<{ slug: string; build: () => { title?: string; events: TelemetryEvent[] } }>) {
      const bundle = s.build();
      for (const events of [bundle.events, project(bundle.events)]) {
        for (const inv of buildInvestigationsFromScenario({ title: bundle.title, events })) {
          cases++;
          const pids = new Set(inv.processes.map(p => p.pid));
          const hostEvents = bundle.events.filter(e => e.incident_id === inv.id);
          const loggedExplorer = hostEvents.some(e => /^explorer\.exe$/i.test(e.process?.name ?? "") || /^explorer\.exe$/i.test(e.process?.parent_name ?? ""));
          for (const p of inv.processes) {
            if (p.pid >= 90000) problems.push(`${s.slug}/${inv.id}: synthetic pid ${p.pid} (${p.name})`);
            if (/^explorer\.exe$/i.test(p.name) && !loggedExplorer) problems.push(`${s.slug}/${inv.id}: invented explorer.exe ${p.pid}`);
            if (/^psexesvc\.exe$/i.test(p.name)) {
              const parent = inv.processes.find(x => x.pid === p.ppid);
              if (parent && !/^services\.exe$/i.test(parent.name)) problems.push(`${s.slug}/${inv.id}: PSEXESVC under ${parent.name}`);
            }
            const first = hostEvents.filter(e => e.process?.pid === p.pid && e.hostname === inv.host.name).map(e => e.ts).sort()[0];
            for (const c of p.network ?? []) {
              if (first && c.ts < first.slice(11, 19)) problems.push(`${s.slug}/${inv.id}: ${p.name}(${p.pid}) owns ${c.remote_ip} at ${c.ts}, before it started ${first.slice(11, 19)}`);
            }
          }
          for (const d of inv.detections) if (!pids.has(d.pid)) problems.push(`${s.slug}/${inv.id}: detection on missing pid ${d.pid}`);
          if (inv.answer.pid !== -1 && !pids.has(inv.answer.pid)) problems.push(`${s.slug}/${inv.id}: answer pid ${inv.answer.pid} not in tree`);
        }
      }
    }
    expect(cases).toBeGreaterThan(10);
    expect(problems, problems.join("\n")).toEqual([]);
  });
});
