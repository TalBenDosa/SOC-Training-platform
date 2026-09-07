import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { buildClipboardClipperScenario } from "./clipboardClipper";
import { buildTrojanizedInstallerKeyloggerScenario } from "./trojanizedInstallerKeylogger";
import { buildSeoPoisonedInstallerScenario } from "./seoPoisonedInstaller";
import { buildDriveByBrowserMinerScenario } from "./driveByBrowserMiner";
import { buildBruteForceSingleAccountScenario } from "./bruteForceSingleAccount";
import { buildOktaPasswordBurstScenario } from "./oktaPasswordBurst";
import { buildUebaCompromisedAccountScenario } from "./uebaCompromisedAccount";
import { buildScheduledTaskPersistenceScenario } from "./scheduledTaskPersistence";
import { buildBundledCryptominerScenario } from "./bundledCryptominer";
import { buildInvestigationsFromScenario } from "@/lib/edr/fromLiveStory";

// Packs that have been fully converted to the vendor emitters. Each MUST stay 100%
// emitter-authored — no hand-typed `raw: { … }` block may creep back in, because that
// is exactly the drift the emitter layer exists to prevent (a hand-typed field can be
// wrong; an emitter-rendered one is registry-correct by construction).
const FULLY_EMITTER_AUTHORED = [
  "clipboardClipper.ts", "trojanizedInstallerKeylogger.ts", "seoPoisonedInstaller.ts",
  "fakeBrowserUpdate.ts", "clickFixFakeCaptcha.ts", "driveByBrowserMiner.ts",
  "bruteForceSingleAccount.ts", "oktaPasswordBurst.ts", "uebaCompromisedAccount.ts",
  "scheduledTaskPersistence.ts", "bundledCryptominer.ts",
];

describe("emitter-authored scenario packs", () => {
  it.each(FULLY_EMITTER_AUTHORED)("%s contains no hand-authored raw blocks", (file) => {
    const src = fs.readFileSync(path.resolve("src/lib/sim/scenario-packs", file), "utf-8");
    // Any `raw: {` literal in the source is a hand-typed vendor block — forbidden here.
    const handRaw = (src.match(/\braw:\s*\{/g) ?? []).length;
    expect(handRaw, `${file} has ${handRaw} hand-authored raw block(s); use the emitters`).toBe(0);
  });

  it("clipboardClipper still builds a coherent, correct incident from emitters only", () => {
    const s = buildClipboardClipperScenario();
    expect(s.events.length).toBe(8);
    // the whole chain lands on one company host, correctly correlated
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-5528");
    expect(inv.processes.some(p => p.name === "cmd.exe" && p.ppid === 6214)).toBe(true);
    expect(inv.processes.some(p => p.name === "clipsvc_helper.exe" && p.ppid === 6214)).toBe(true);
    expect(inv.detections.map(d => d.technique).sort()).toEqual(["T1059.003", "T1115", "T1204.002"]);
    const payload = inv.processes.find(p => p.pid === inv.answer.pid);
    expect(payload?.name).toBe("clipsvc_helper.exe");
    // one hash → one file across the whole pack
    const byHash = new Map<string, Set<string>>();
    for (const e of s.events) {
      const h = e.process?.hash?.sha256 ?? e.file?.sha256;
      const nm = e.process?.name ?? e.file?.name;
      if (h && nm) { const set = byHash.get(h) ?? new Set(); set.add(nm); byHash.set(h, set); }
    }
    expect([...byHash.values()].every(n => n.size === 1)).toBe(true);
  });

  it("trojanizedInstallerKeylogger still builds a coherent incident from emitters only (CrowdStrike + PAN + Sentinel)", () => {
    const s = buildTrojanizedInstallerKeyloggerScenario();
    expect(s.events.length).toBe(10);
    // three vendors, all emitter-authored
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "CrowdStrike Falcon", "Palo Alto Networks PAN-OS", "Microsoft Sentinel",
    ]));
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-2290");
    // the exact delivery tree: explorer -> SwiftPDF_Setup(7120) -> winupd_helper(7688)
    expect(inv.processes.some(p => p.name === "winupd_helper.exe" && p.ppid === 7120)).toBe(true);
    const payload = inv.processes.find(p => p.pid === inv.answer.pid);
    expect(payload?.name).toBe("winupd_helper.exe");
    // the Sentinel enrichment carries its ExtendedProperties arrays intact
    const ctx = s.events.find(e => e.id === "evt_tik_10_siem_context");
    expect(ctx?.raw?.["ExtendedProperties.Local Admin Rights"]).toBe("false");
    expect(ctx?.raw?.["AlertName"]).toBe("EndpointSoftwareChange_UnsignedPersistence");
  });

  it("seoPoisonedInstaller still builds a coherent incident from emitters only (MDE + PAN)", () => {
    const s = buildSeoPoisonedInstallerScenario();
    expect(s.events.length).toBe(10);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "Microsoft Defender for Endpoint", "Palo Alto Networks PAN-OS",
    ]));
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-3312");
    // exact loader tree: explorer -> PuTTY-0.83-installer(7744) -> upd_helper(7801)
    expect(inv.processes.some(p => p.name === "upd_helper.exe" && p.ppid === 7744)).toBe(true);
    // the "Login Data" credential copy keeps no hash + its technique + is a feed alert
    const cred = s.events.find(e => e.id === "evt_spi_08_cred_copy");
    expect(cred?.file?.sha256).toBeUndefined();
    expect(cred?.mitre_technique).toBe("T1555.003");
    // the Defender incident alert carries its rich fields and no process node
    const alert = s.events.find(e => e.id === "evt_spi_10_alert");
    expect(alert?.raw?.["malware.name"]).toBe("Trojan:Win32/Rhadesta.SP!MTB");
    expect(alert?.raw?.["remediation.action"]).toBe("Quarantine");
    expect(alert?.process).toBeUndefined();
    // the PAN exfil is an outbound POST to the C2
    const exfil = s.events.find(e => e.id === "evt_spi_09_exfil");
    expect(exfil?.raw?.["pan.http_method"]).toBe("POST");
    expect(exfil?.raw?.["url.domain"]).toBe("cdn-assets-relay92.net");
  });

  it("driveByBrowserMiner still builds a coherent incident from emitters only (CS + PAN, csAlert + panConnection)", () => {
    const s = buildDriveByBrowserMinerScenario();
    expect(s.events.length).toBe(8);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "CrowdStrike Falcon", "Palo Alto Networks PAN-OS",
    ]));
    // the WebSocket tunnel is a net_connection with app=websocket (panConnection)
    const ws = s.events.find(e => e.id === "evt_dbm_05_ws_open");
    expect(ws?.event_type).toBe("net_connection");
    expect(ws?.raw?.["pan.app"]).toBe("websocket");
    // the traffic-end summary carries the duration (panConnection end)
    const wsClose = s.events.find(e => e.id === "evt_dbm_07_ws_close");
    expect(wsClose?.raw?.["pan.elapsed_time"]).toBe("1440");
    // the Falcon alert is a behavioural summary with no process node (csAlert)
    const alert = s.events.find(e => e.id === "evt_dbm_08_edr_alert");
    expect(alert?.raw?.["malware.category"]).toBe("cryptominer");
    expect(alert?.process).toBeUndefined();
    // the renderer process is present and the console opens on the right host
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-6690");
    expect(inv.processes.some(p => p.name === "chrome.exe" && p.pid === 8842)).toBe(true);
  });

  it("bruteForceSingleAccount builds a coherent AD incident from emitters only (Windows Security + CrowdStrike + PAN + Sentinel)", () => {
    const s = buildBruteForceSingleAccountScenario();
    expect(s.events.length).toBe(10);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "Palo Alto Networks PAN-OS", "Windows Security", "CrowdStrike Falcon", "Microsoft Sentinel",
    ]));
    // the two SubStatus codes that carry the whole lesson (no-user vs bad-password)
    const wrongUser = s.events.find(e => e.id === "evt_bf_02_fail_wrong_user");
    expect(wrongUser?.raw?.["winlog.event_data.SubStatus"]).toBe("0xC0000064");
    expect(wrongUser?.user_email).toBeUndefined();      // the account never existed → no mailbox
    const burst = s.events.find(e => e.id === "evt_bf_03_fail_burst");
    expect(burst?.raw?.["winlog.event_data.SubStatus"]).toBe("0xC000006A");
    // the 4624 success is the incident
    const success = s.events.find(e => e.id === "evt_bf_05_auth_success");
    expect(success?.event_type).toBe("auth_success");
    expect(success?.raw?.["winlog.event_id"]).toBe("4624");
    // the net.exe lateral-movement detection is alert-grade and lives in the EDR console
    const netUse = s.events.find(e => e.id === "evt_bf_07_net_use");
    expect(netUse?.is_detection).toBe(true);
    expect(netUse?.edr_scope).toBe("edr");
    expect(netUse?.process?.name).toBe("net.exe");
    // the Sentinel enrichment keeps its 90-day share baseline
    const ctx = s.events.find(e => e.id === "evt_bf_10_siem_context");
    expect(ctx?.raw?.["AlertName"]).toBe("ExternalAuthenticationBurst_SingleAccount");
    expect(ctx?.raw?.["ExtendedProperties.Lockout Policy Applied"]).toBe("false");
    // one host, correlated: the EDR console opens on the RDP server
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("SRV-RDS-02");
  });

  it("oktaPasswordBurst builds a coherent identity incident from emitters only (Okta + Sentinel)", () => {
    const s = buildOktaPasswordBurstScenario();
    expect(s.events.length).toBe(10);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set(["Okta", "Microsoft Sentinel"]));
    // THE lesson: authenticationStep flips 0 → 1 and reason flips to MFA_REQUIRED
    // on the event where the PASSWORD was finally accepted.
    const burst = s.events.find(e => e.id === "evt_okb_03_fail_burst");
    expect(burst?.raw?.["okta.outcome.reason"]).toBe("INVALID_CREDENTIALS");
    expect(burst?.raw?.["okta.authenticationContext.authenticationStep"]).toBe("0");
    const accepted = s.events.find(e => e.id === "evt_okb_05_password_accepted");
    expect(accepted?.raw?.["okta.outcome.reason"]).toBe("MFA_REQUIRED");
    expect(accepted?.raw?.["okta.authenticationContext.authenticationStep"]).toBe("1");
    // the push was rejected (fatigue defence held)
    const denied = s.events.find(e => e.id === "evt_okb_07_factor_denied");
    expect(denied?.event_type).toBe("mfa_denied");
    expect(denied?.raw?.["okta.outcome.reason"]).toBe("USER_REJECTED_PUSH");
    // the asOrg tell separates attacker (FlokiNET) from the user's real ISP
    expect(burst?.raw?.["okta.securityContext.asOrg"]).toBe("FlokiNET ehf");
    const baseline = s.events.find(e => e.id === "evt_okb_09_user_normal_login");
    expect(baseline?.raw?.["okta.securityContext.asOrg"]).toBe("Hot-Net internet services Ltd.");
    expect(baseline?.is_baseline).toBe(true);
    // the Sentinel correlation keeps the zero-sessions fact
    const ctx = s.events.find(e => e.id === "evt_okb_10_siem_context");
    expect(ctx?.raw?.["ExtendedProperties.Sessions Created In Window"]).toBe("0");
  });

  it("uebaCompromisedAccount builds a coherent anomaly-led hunt from emitters only (Sentinel UEBA + Entra + M365)", () => {
    const s = buildUebaCompromisedAccountScenario();
    expect(s.events.length).toBe(8);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "Microsoft Sentinel", "Microsoft Entra ID", "Microsoft 365 Unified Audit Log",
    ]));
    // baseline vs atypical: the token-replay tell separates them
    const atypical = s.events.find(e => e.id === "evt_uca_02_atypical_signin");
    expect(atypical?.raw?.["azure.signinlogs.properties.incomingTokenType"]).toBe("primaryRefreshToken");
    expect(atypical?.raw?.["azure.signinlogs.properties.authenticationRequirement"]).toBe("singleFactorAuthentication");
    expect(atypical?.raw?.["azure.signinlogs.properties.deviceDetail.isManaged"]).toBe("false");
    // the benign control resolves fp (a high score is not a verdict)
    const benign = s.events.find(e => e.id === "evt_uca_00_benign_impossible_travel");
    expect(benign?.expected_verdict).toBe("fp");
    expect(benign?.raw?.["ImpossibleTravelActivity"]).toBe("true");
    expect(benign?.raw?.["risk.state"]).toBe("dismissed");
    // the mass download + forwarding rule are the acted-on collection
    const dl = s.events.find(e => e.id === "evt_uca_05_mass_download");
    expect(dl?.event_type).toBe("cloud_storage_access");
    expect(dl?.raw?.["data.office365.Operation"]).toBe("FileSyncDownloadedFull");
    const rule = s.events.find(e => e.id === "evt_uca_06_inbox_rule");
    expect(rule?.raw?.["data.office365.Operation"]).toBe("New-InboxRule");
    expect(rule?.raw?.["data.office365.Parameters.ForwardAsAttachmentTo"]).toBe("acct.archive.9y@gmail.com");
    // the case-opening entity risk score rolls the four indicators together
    const score = s.events.find(e => e.id === "evt_uca_07_entity_risk_score");
    expect(score?.is_detection).toBe(true);
    expect(score?.edr_scope).toBe("non_edr");
    expect(score?.raw?.["RiskyUser"]).toBe("true");
    expect(score?.raw?.["behavior.name"]).toBe("account_takeover_pattern");
  });

  it("scheduledTaskPersistence builds a coherent persistence incident from emitters only (Sysmon + PAN + Sentinel)", () => {
    const s = buildScheduledTaskPersistenceScenario();
    expect(s.events.length).toBe(9);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "Microsoft Sysmon", "Palo Alto Networks PAN-OS", "Microsoft Sentinel",
    ]));
    // the schtasks registration is the alert-grade persistence crux
    const task = s.events.find(e => e.id === "evt_stp_04_scheduled_task");
    expect(task?.event_type).toBe("scheduled_task");
    expect(task?.is_detection).toBe(true);
    expect(task?.edr_scope).toBe("edr");
    expect(task?.raw?.["winlog.event_data.ProcessGuid"]).toBeTruthy();
    // the relaunch at logon proves the task fired — parent is the Schedule svchost
    const relaunch = s.events.find(e => e.id === "evt_stp_07_relaunch_at_logon");
    expect(String(relaunch?.raw?.["winlog.event_data.ParentCommandLine"])).toContain("-s Schedule");
    expect(relaunch?.process?.hash?.sha256).toBe(task && s.events.find(e => e.id === "evt_stp_03_payload_written")?.file?.sha256);
    // the ProcessGuid join key is present on the SIEM correlation
    const det = s.events.find(e => e.id === "evt_stp_08_detection");
    expect(det?.raw?.["ExtendedProperties.Query"]).toContain("ParentProcessGuid");
    // one host, correlated: the EDR console opens on WS-7742 with the schtasks tree
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("WS-7742");
    expect(inv.processes.some(p => p.name === "schtasks.exe")).toBe(true);
  });

  it("bundledCryptominer builds a coherent coinminer incident from emitters only (CS + PAN + Sentinel)", () => {
    const s = buildBundledCryptominerScenario();
    expect(s.events.length).toBe(9);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "CrowdStrike Falcon", "Palo Alto Networks PAN-OS", "Microsoft Sentinel",
    ]));
    // the miner's identity is in its command line (stratum + wallet)
    const miner = s.events.find(e => e.id === "evt_bcm_05_miner_start");
    expect(miner?.process?.cmdline).toContain("stratum+tcp://");
    expect(miner?.is_detection).toBe(true);
    // persistence: schtasks WinHostSync at logon
    const task = s.events.find(e => e.id === "evt_bcm_04_scheduled_task");
    expect(task?.event_type).toBe("scheduled_task");
    expect(String(task?.process?.cmdline)).toContain("WinHostSync");
    // long-lived unknown-tcp pool session
    const pool = s.events.find(e => e.id === "evt_bcm_06_pool_connection");
    expect(pool?.raw?.["pan.app"]).toBe("unknown-tcp");
    expect(pool?.raw?.["pan.elapsed_time"]).toBe("39602");
    // the ticket-opener is the second Falcon detection; the precursor is not
    expect(s.events.find(e => e.id === "evt_bcm_07_perf_telemetry")?.is_detection).toBe(false);
    const alert = s.events.find(e => e.id === "evt_bcm_08_edr_alert");
    expect(alert?.is_detection).toBe(true);
    expect(alert?.edr_scope).toBe("edr");
    // one host, correlated: EDR console opens on LAP-1806 with the miner tree
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-1806");
    expect(inv.processes.some(p => p.name === "svchost_helper.exe")).toBe(true);
  });
});
