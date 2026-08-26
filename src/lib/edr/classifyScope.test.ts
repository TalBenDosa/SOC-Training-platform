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
