// QA report 2026-11-12, section 4 ("the other data sources"): each finding pinned at the module level, so every
// company and story that renders through these modules keeps the fix.
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { ATTACK_STORIES, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { nativeView, applyStack } from "@/lib/logs/native";
import { makeCtx } from "./ctx";
import { source as mde, mdeRegistryKey } from "./sources/mde";
import { source as sentinel } from "./sources/sentinel_alert";
import { source as paloalto } from "./sources/paloalto";
import { source as sysmon } from "./sources/sysmon";
import { source as entra } from "./sources/entra";
import { scriptCommands } from "@/lib/sim/scriptCommands";
import { sameBrowserVersion } from "./sources/_identity-common";
import type { TelemetryEvent } from "@/lib/sim/types";

type Rec = Record<string, unknown>;
const props = (r: unknown) => ((r as { properties?: Rec }).properties ?? {}) as Rec;

describe("MDE (Defender for Endpoint)", () => {
  const story = instantiateStory(ATTACK_STORIES.find(s => s.id === "clickfix-fake-captcha")!, BENIGN_EVENTS, "Microsoft Defender for Endpoint", "nexacorp", () => 0.4);
  const view = (id: string) => { const e = story.events.find(x => x.id === id)!; return nativeView(applyStack(e, "nexacorp", {}), "nexacorp", {}); };

  it("a scanned script is DeviceEvents PowerShellCommand, never a foreign GeneralEvent record", () => {
    for (const id of ["evt_cfc_03d_script_stager", "evt_cfc_05a_script_child"]) {
      const v = view(id)!;
      expect(v.log.sourceId).toBe("mde");
      expect(v.log.kind).toBe("DeviceEvents");
      expect(props(v.log.record).ActionType).toBe("PowerShellCommand");
      expect(JSON.parse(String(props(v.log.record).AdditionalFields)).Command).toBeTruthy();
      expect(JSON.stringify(v.log.record)).not.toMatch(/GeneralEvent|observer\.vendor|Security event detected/);
    }
    expect(scriptCommands("(New-Object Net.WebClient).DownloadFile('x','y'); Start-Process y")).toEqual(["Start-Process", "New-Object"]);
  });

  it("each process has one parent: a child PowerShell's actions name the PowerShell that started it", () => {
    const stager = props(view("evt_cfc_03_paste_run")!.log.record), child = props(view("evt_cfc_05_encoded_child")!.log.record);
    expect(child.InitiatingProcessId).toBe(stager.ProcessId);
    for (const id of ["evt_cfc_05a_script_child", "evt_cfc_05c_dns_stealer", "evt_cfc_06_stealer_written"]) {
      const p = props(view(id)!.log.record);
      expect(p.InitiatingProcessId, id).toBe(child.ProcessId);
      expect(p.InitiatingProcessParentId, id).toBe(stager.ProcessId);
    }
    // The stealer's creator is the child PowerShell, whose own parent is the stager (not a guessed Explorer).
    const stealer = props(view("evt_cfc_07_stealer_execute")!.log.record);
    expect(stealer.InitiatingProcessId).toBe(child.ProcessId);
    expect(stealer.InitiatingProcessParentId).toBe(stager.ProcessId);
  });

  it("no empty or bare command line on an initiating process", () => {
    for (const id of ["evt_cfc_03b_dns_stager", "evt_cfc_05c_dns_stealer", "evt_cfc_07b_dns_c2"]) {
      const cmd = String(props(view(id)!.log.record).InitiatingProcessCommandLine ?? "");
      expect(cmd.length, id).toBeGreaterThan("powershell.exe".length);
    }
  });

  it("RegistryKey is written with full hive names and the user's SID", () => {
    expect(props(view("evt_cfc_02b_runmru")!.log.record).RegistryKey).toMatch(/^HKEY_CURRENT_USER\\S-1-5-21-[\d-]+\\Software\\/);
    expect(mdeRegistryKey("HKLM\\SOFTWARE\\Run", null)).toBe("HKEY_LOCAL_MACHINE\\SOFTWARE\\Run");
  });

  it("an alert lists the techniques it maps to, and its title is a sentence", () => {
    const a = props(view("evt_cfc_09_edr_alert")!.log.record);
    expect(JSON.parse(String(a.AttackTechniques)).length).toBeGreaterThan(0);
    expect(String(a.Title)).toMatch(/\s/);
  });

  it("Defender's engine runs from the platform folder", () => {
    const e = BENIGN_EVENTS.find(x => x.id === "b_edr_03")!;
    const l = mde.fromTelemetry(e, makeCtx("nexacorp"))!;
    expect(JSON.stringify(l.record)).toContain("\\\\ProgramData\\\\Microsoft\\\\Windows Defender\\\\Platform\\\\");
  });
});

describe("Sentinel SecurityAlert", () => {
  const ev = {
    id: "qa-sa-1", ts: "2026-11-12T10:00:00Z", source: "siem", vendor: "Microsoft Sentinel", event_type: "edr_alert", severity: "medium", hostname: "WS-OPS-2214",
    raw: { AlertName: "CrowdStrike Falcon endpoint detection on WS-OPS-2214", ProviderName: "ASI Scheduled Alerts", ProductName: "Azure Sentinel", SystemAlertId: "x",
      AlertType: "CrowdStrikeFalconendpointdetectiononWSOPS2214", "ExtendedProperties.Source EDR Vendor": "CrowdStrike Falcon", "ExtendedProperties.Original Detection": "cmd started powershell" },
  } as unknown as TelemetryEvent;
  const r = sentinel.fromTelemetry(ev, makeCtx("nexacorp"))!.record;

  it("a scheduled analytic's AlertType is <workspace id>_<rule id>, never its name run together", () => {
    expect(String(r.AlertType)).toMatch(/^[0-9a-f-]{36}_[0-9a-f-]{36}$/);
    const ext = JSON.parse(String(r.ExtendedProperties));
    expect(JSON.parse(ext["Analytic Rule Ids"])[0]).toBe(String(r.AlertType).split("_")[1]);
  });

  it("ExtendedProperties holds the rule's own keys; the rule's surfaced fields are Custom Details", () => {
    const ext = JSON.parse(String(r.ExtendedProperties));
    expect(Object.keys(ext)).not.toContain("Source EDR Vendor");
    expect(JSON.parse(ext["Custom Details"])).toEqual({ SourceEDRVendor: ["CrowdStrike Falcon"], OriginalDetection: ["cmd started powershell"] });
    expect(ext["Query Period"]).toBeTruthy();
  });
});

describe("PAN-OS", () => {
  const base = {
    id: "qa-pan-1", ts: "2026-11-12T10:00:00Z", source: "firewall", vendor: "Palo Alto Networks", event_type: "http_request", severity: "low",
    hostname: "WS-FIN-2847", src_ip: "10.10.20.47", dst_ip: "198.51.100.77", dst_port: 443, user_email: "j.chen@nexacorp.com",
    network: { domain: "files.example", url: "https://files.example/a/b.zip", user_agent: "Mozilla/5.0" }, raw: {},
  } as unknown as TelemetryEvent;
  it("a public destination has a GeoIP country", () => {
    expect(paloalto.fromTelemetry(base, makeCtx("nexacorp"))!.record.dstloc).toBeTruthy();
  });
  it("a URL path, User-Agent or Referer on 443 comes with the decrypted-session flag", () => {
    const withPath = Number(paloalto.fromTelemetry(base, makeCtx("nexacorp"))!.record.flags);
    expect(withPath & 0x01000000).toBe(0x01000000);
    const sniOnly = { ...base, id: "qa-pan-2", network: { domain: "files.example", url: "https://files.example/" } } as unknown as TelemetryEvent;
    expect(Number(paloalto.fromTelemetry(sniOnly, makeCtx("nexacorp"))!.record.flags) & 0x01000000).toBe(0);
  });
});

describe("Sysmon", () => {
  it("Event 3 prints svchost.exe's full path, and Event 22 names the account", () => {
    const net = { id: "qa-sm-3", ts: "2026-11-12T10:00:00Z", source: "sysmon", vendor: "Microsoft Sysmon", event_type: "net_connection", severity: "informational",
      hostname: "WS-FIN-2847", src_ip: "10.10.20.47", dst_ip: "198.51.100.40", dst_port: 443, raw: { "winlog.event_id": "3", "winlog.event_data.Image": "svchost.exe" } } as unknown as TelemetryEvent;
    const l3 = sysmon.fromTelemetry(net, makeCtx("nexacorp"));
    if (l3) expect(JSON.stringify(l3.record)).toContain("C:\\\\Windows\\\\System32\\\\svchost.exe");
    const dns = { id: "qa-sm-22", ts: "2026-11-12T10:00:00Z", source: "sysmon", vendor: "Microsoft Sysmon", event_type: "dns_query", severity: "informational",
      hostname: "WS-FIN-2847", dns: { query: "example.org" }, raw: { "winlog.event_id": "22", "winlog.event_data.Image": "C:\\Windows\\System32\\svchost.exe" } } as unknown as TelemetryEvent;
    const l22 = sysmon.fromTelemetry(dns, makeCtx("nexacorp"));
    if (l22) expect(JSON.stringify(l22.record)).not.toMatch(/"User":"-"/);
    expect(!!l3 || !!l22).toBe(true);
  });
});

describe("Entra ID", () => {
  it("an Office desktop app signs in as a desktop client, not a browser", () => {
    const ev = { id: "qa-en-1", ts: "2026-11-12T10:00:00Z", source: "o365", vendor: "Microsoft Entra ID", event_type: "auth_success", severity: "informational",
      user_email: "j.chen@nexacorp.com", src_ip: "192.0.2.150", raw: { "azure.client_app": "Microsoft Office", "azure.signinlogs.properties.appDisplayName": "Microsoft Office" } } as unknown as TelemetryEvent;
    const l = entra.fromTelemetry(ev, makeCtx("nexacorp"));
    if (l) expect(l.record.clientAppUsed).toBe("Mobile Apps and Desktop clients");
  });
  it("one person, one browser version on their ordinary sign-ins", () => {
    const ua = (v: number) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`;
    expect(sameBrowserVersion(ua(120), "j.chen@nexacorp.com")).toBe(sameBrowserVersion(ua(131), "j.chen@nexacorp.com"));
  });
});
