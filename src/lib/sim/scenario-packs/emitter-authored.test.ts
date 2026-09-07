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
import { buildLateralMovementPthScenario } from "./lateralMovementPth";
import { buildWindowsPrivescTokenScenario } from "./windowsPrivescToken";
import { buildMultiHostIntrusionScenario } from "./multiHostIntrusion";
import { buildIsoContainerSmugglingScenario } from "./isoContainerSmuggling";
import { buildDestructiveWiperScenario } from "./destructiveWiper";
import { buildEdgeVpnCveExploitScenario } from "./edgeVpnCveExploit";
import { buildInvestigationsFromScenario } from "@/lib/edr/fromLiveStory";

// Packs that have been fully converted to the vendor emitters. Each MUST stay 100%
// emitter-authored — no hand-typed `raw: { … }` block may creep back in, because that
// is exactly the drift the emitter layer exists to prevent (a hand-typed field can be
// wrong; an emitter-rendered one is registry-correct by construction).
const FULLY_EMITTER_AUTHORED = [
  "clipboardClipper.ts", "trojanizedInstallerKeylogger.ts", "seoPoisonedInstaller.ts",
  "fakeBrowserUpdate.ts", "clickFixFakeCaptcha.ts", "driveByBrowserMiner.ts",
  "bruteForceSingleAccount.ts", "oktaPasswordBurst.ts", "uebaCompromisedAccount.ts",
  "scheduledTaskPersistence.ts", "bundledCryptominer.ts", "lateralMovementPth.ts",
  "windowsPrivescToken.ts", "multiHostIntrusion.ts", "isoContainerSmuggling.ts",
  "destructiveWiper.ts", "edgeVpnCveExploit.ts",
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

  it("lateralMovementPth builds a coherent PtH intrusion from emitters only (WinSec + Sysmon + CS + Sentinel)", () => {
    const s = buildLateralMovementPthScenario();
    expect(s.events.length).toBe(12);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "Windows Security", "Microsoft Sysmon", "CrowdStrike Falcon", "Microsoft Sentinel",
    ]));
    // benign control: Kerberos + fp explanation; attack landing: NTLM
    const benign = s.events.find(e => e.id === "evt_lm_00_benign_logon");
    expect(benign?.raw?.["winlog.event_data.AuthenticationPackageName"]).toBe("Kerberos");
    expect(benign?.fp_explanation).toBeTruthy();
    const pth = s.events.find(e => e.id === "evt_lm_02_pth_logon");
    expect(pth?.raw?.["winlog.event_data.AuthenticationPackageName"]).toBe("NTLM");
    // the LSASS dump is the origin of the hash (Sysmon 10)
    const lsass = s.events.find(e => e.id === "evt_lm_01_lsass_access");
    expect(lsass?.event_type).toBe("process_access");
    expect(lsass?.raw?.["winlog.event_data.GrantedAccess"]).toBe("0x1410");
    // 4672 privesc + 7045 service install
    expect(s.events.find(e => e.id === "evt_lm_03_special_privs")?.raw?.["winlog.event_id"]).toBe("4672");
    expect(s.events.find(e => e.id === "evt_lm_05_service_install")?.raw?.["winlog.event_data.ServiceName"]).toBe("WinSvcUpdate");
    // the service binary runs as SYSTEM
    const svc = s.events.find(e => e.id === "evt_lm_06_service_exec");
    expect(svc?.process?.user).toBe("NT AUTHORITY\\SYSTEM");
    // the second hop reaches the DC
    const dcLogon = s.events.find(e => e.id === "evt_lm_10_dc_logon");
    expect(dcLogon?.hostname).toBe("DC-NEXA-01");
    expect(dcLogon?.raw?.["winlog.event_data.AuthenticationPackageName"]).toBe("NTLM");
    // one incident, correlated: EDR console opens on the file server
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("SRV-FILE-03");
  });

  it("windowsPrivescToken builds a coherent SeImpersonate privesc from emitters only (WinSec + Sysmon + MDE + Sentinel)", () => {
    const s = buildWindowsPrivescTokenScenario();
    expect(s.events.length).toBe(10);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "Windows Security", "Microsoft Sysmon", "Microsoft Defender for Endpoint", "Microsoft Sentinel",
    ]));
    // the precondition: 4672 enumerates SeImpersonatePrivilege on the svc-web session
    const privs = s.events.find(e => e.id === "evt_wpe_02_special_privs");
    expect(privs?.raw?.["winlog.event_id"]).toBe("4672");
    expect(String(privs?.raw?.["winlog.event_data.PrivilegeList"])).toContain("SeImpersonatePrivilege");
    // the coercion + token theft: spoolsv on the pipe (18), spf opens spoolsv 0x1410 (10)
    const pipe = s.events.find(e => e.id === "evt_wpe_05_pipe_connect");
    expect(pipe?.raw?.["winlog.event_data.PipeName"]).toBe("\\spoolss");
    const pa = s.events.find(e => e.id === "evt_wpe_06_process_access");
    expect(pa?.event_type).toBe("process_access");
    expect(pa?.raw?.["winlog.event_data.GrantedAccess"]).toBe("0x1410");
    // 4673 sensitive-privilege use by the tool
    const spu = s.events.find(e => e.id === "evt_wpe_07_sensitive_priv_use");
    expect(spu?.raw?.["winlog.event_id"]).toBe("4673");
    // escalation succeeds: 4688 SYSTEM cmd with a full token
    const sys = s.events.find(e => e.id === "evt_wpe_08_system_shell");
    expect(sys?.raw?.["winlog.event_id"]).toBe("4688");
    expect(sys?.raw?.["winlog.event_data.TokenElevationType"]).toBe("%%1937");
    // the payoff: reg.exe SAM export is the MDE detection
    const sam = s.events.find(e => e.id === "evt_wpe_09_sam_dump");
    expect(sam?.is_detection).toBe(true);
    expect(sam?.edr_scope).toBe("edr");
    expect(sam?.mitre_technique).toBe("T1003.002");
    // one host, correlated: the EDR console opens on the web server
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("WEB-APP-04");
  });

  it("multiHostIntrusion builds a coherent 3-host campaign from emitters only (PAN + CrowdStrike + WinSec)", () => {
    const s = buildMultiHostIntrusionScenario();
    expect(s.events.length).toBe(13);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "Palo Alto Networks PAN-OS", "CrowdStrike Falcon", "Windows Security",
    ]));
    // the foothold crux: encoded PowerShell beacon under Office, one stable tree
    const beacon = s.events.find(e => e.id === "evt_mhi_ws3_beacon");
    expect(beacon?.is_detection).toBe(true);
    expect(beacon?.process?.hash?.sha256).toBeTruthy();
    expect(beacon?.process?.parent_pid).toBe(6112);
    // the C2 heartbeat is an aggregated TLS session (repeat_count), not a bare GET
    const c2 = s.events.find(e => e.id === "evt_mhi_ws4_c2");
    expect(c2?.event_type).toBe("net_connection");
    expect(c2?.raw?.["pan.app"]).toBe("ssl");
    expect(c2?.raw?.["pan.repeat_count"]).toBe("14");
    // the lateral hop lands as a Type-3 NTLM logon from the foothold host
    const logon = s.events.find(e => e.id === "evt_mhi_fs1_logon");
    expect(logon?.raw?.["winlog.event_data.LogonType"]).toBe("3");
    expect(logon?.raw?.["winlog.event_data.AuthenticationPackageName"]).toBe("NTLM");
    expect(logon?.raw?.["winlog.event_data.IpAddress"]).toBe("10.20.6.28");
    // the credential-theft crux: LSASS full-access read (0x1FFFFF)
    const lsass = s.events.find(e => e.id === "evt_mhi_fs3_lsass");
    expect(lsass?.event_type).toBe("process_access");
    expect(lsass?.raw?.["crowdstrike.GrantedAccess"]).toBe("0x1FFFFF");
    expect(lsass?.raw?.["crowdstrike.CrossProcessTargetName"]).toBe("lsass.exe");
    // the rename tell: OriginalFileName rclone.exe on an unsigned ProgramData binary
    const stage = s.events.find(e => e.id === "evt_mhi_bk1_stage");
    expect(stage?.raw?.["process.original_file_name"]).toBe("rclone.exe");
    expect(stage?.raw?.["process.code_signature.status"]).toBe("unsigned");
    // the exfil crux: the same binary pushing to the cloud-storage host
    const exfil = s.events.find(e => e.id === "evt_mhi_bk2_exfil_proc");
    expect(exfil?.is_detection).toBe(true);
    expect(exfil?.process?.name).toBe("svchost-update.exe");
    expect(exfil?.raw?.["destination.domain"]).toBe("store.filedrop-transfer.net");
    // the three summary alerts carry their scoping hints
    expect(s.events.find(e => e.id === "evt_mhi_ws5_alert")?.edr_scope).toBe("edr");
    expect(s.events.find(e => e.id === "evt_mhi_fs4_alert")?.edr_scope).toBe("hybrid");
    expect(s.events.find(e => e.id === "evt_mhi_bk4_alert")?.edr_scope).toBe("edr");
    // three hosts → three isolated EDR incidents, all correlated by the campaign
    const invs = buildInvestigationsFromScenario({ title: s.title, events: s.events });
    const hosts = new Set(invs.map(i => i.host.name));
    expect(hosts).toEqual(new Set(["FIN-WS-08", "FS-SRV-03", "BKP-SRV-02"]));
  });

  it("isoContainerSmuggling builds a coherent MotW-bypass chain from emitters only (FortiGate + CrowdStrike)", () => {
    const s = buildIsoContainerSmugglingScenario();
    expect(s.events.length).toBe(8);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set(["FortiGate", "CrowdStrike Falcon"]));
    // the download is a FortiGate file-filter log-only record (not a block), carrying the .iso
    const dl = s.events.find(e => e.id === "evt_ics_01_download");
    expect(dl?.event_type).toBe("http_request");
    expect(dl?.raw?.["data.subtype"]).toBe("filefilter");
    expect(dl?.raw?.["data.filetype"]).toBe("iso");
    // the mount is a file-open by explorer (the parent of the shortcut's cmd)
    const mount = s.events.find(e => e.id === "evt_ics_03_mount");
    expect(mount?.event_type).toBe("file_access");
    expect(mount?.raw?.["crowdstrike.event_simpleName"]).toBe("FileOpenInfo");
    expect(mount?.process?.pid).toBe(3184);
    // the MotW-bypass crux: cmd launched from the mounted volume by explorer
    const lnk = s.events.find(e => e.id === "evt_ics_04_lnk_cmd");
    expect(lnk?.mitre_technique).toBe("T1553.005");
    expect(lnk?.process?.parent_pid).toBe(3184);
    // the encoded PowerShell is the alert-grade behaviour
    const ps = s.events.find(e => e.id === "evt_ics_05_powershell");
    expect(ps?.is_detection).toBe(true);
    expect(ps?.process?.parent_pid).toBe(6620);
    // the payload fetch is a FortiGate web-filter passthrough of an uncategorised URL
    const fetch = s.events.find(e => e.id === "evt_ics_06_payload_fetch");
    expect(fetch?.raw?.["data.subtype"]).toBe("webfilter");
    expect(fetch?.raw?.["data.catdesc"]).toBe("Uncategorized");
    // the payload landed before the kill (state after detection)
    const write = s.events.find(e => e.id === "evt_ics_07_payload_write");
    expect(write?.raw?.["file.signature.status"]).toBe("unsigned");
    // the Falcon alert opens the ticket and scopes to the EDR console
    const alert = s.events.find(e => e.id === "evt_ics_08_edr_alert");
    expect(alert?.is_detection).toBe(true);
    expect(alert?.edr_scope).toBe("edr");
    // one host, correlated
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-5528");
  });

  it("destructiveWiper builds a coherent wiper chain from emitters only (CrowdStrike + Sysmon + MDE)", () => {
    const s = buildDestructiveWiperScenario();
    expect(s.events.length).toBe(10);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "CrowdStrike Falcon", "Microsoft Sysmon", "Microsoft Defender for Endpoint",
    ]));
    // benign control: signed sdelete, high integrity, resolves fp
    const benign = s.events.find(e => e.id === "dw_00_benign_secure_wipe");
    expect(benign?.expected_verdict).toBe("fp");
    expect(benign?.raw?.["process.code_signature.subject_name"]).toBe("Microsoft Corporation");
    // the wiper runs as SYSTEM off the SCM
    const exec = s.events.find(e => e.id === "dw_01_wiper_exec");
    expect(exec?.process?.user).toBe("NT AUTHORITY\\SYSTEM");
    expect(exec?.raw?.["process.integrity_level"]).toBe("System");
    // BYOVD: Sysmon Event 6 driver load, validly signed 3rd-party driver
    const drv = s.events.find(e => e.id === "dw_02_driver_load");
    expect(drv?.raw?.["winlog.event_id"]).toBe("6");
    expect(drv?.raw?.["winlog.event_data.ImageLoaded"]).toContain("epmntdrv.sys");
    expect(drv?.raw?.["winlog.event_data.Signed"]).toBe("true");
    // shadow-copy deletion: Sysmon 1 vssadmin under the wiper
    const vss = s.events.find(e => e.id === "dw_03_vssadmin_delete");
    expect(vss?.raw?.["winlog.event_id"]).toBe("1");
    expect(String(vss?.raw?.["winlog.event_data.ParentImage"])).toContain("cl64.exe");
    // MDE corroboration ties the same initiating payload SHA256
    const mde = s.events.find(e => e.id === "dw_08_mde_corroboration");
    expect(mde?.raw?.["ActionType"]).toBe("ProcessCreated");
    expect(mde?.raw?.["InitiatingProcessSHA256"]).toBe(exec?.process?.hash?.sha256);
    // the disk-structure wipe is a RawDiskAccess to PhysicalDrive0
    const raw = s.events.find(e => e.id === "dw_06_raw_disk_write");
    expect(raw?.raw?.["crowdstrike.event_simpleName"]).toBe("RawDiskAccess");
    expect(String(raw?.raw?.["crowdstrike.TargetDevice"])).toContain("PhysicalDrive0");
    // the detection attributes the deploying account in the company netbios realm
    const alert = s.events.find(e => e.id === "dw_09_edr_detection");
    expect(alert?.is_detection).toBe(true);
    expect(alert?.edr_scope).toBe("edr");
    expect(alert?.raw?.["crowdstrike.UserName"]).toBe("VANTAGE\\a.novak");
    // one host, correlated
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("VNT-WKS-27");
  });

  it("edgeVpnCveExploit builds a coherent edge-appliance→internal chain from emitters only (FortiGate + SSL-VPN + CrowdStrike + Sentinel)", () => {
    const s = buildEdgeVpnCveExploitScenario();
    expect(s.events.length).toBe(8);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "FortiGate", "FortiGate SSL-VPN", "CrowdStrike Falcon", "Microsoft Sentinel",
    ]));
    // initial access: pre-auth admin API hit, blank data.user, 200
    const exploit = s.events.find(e => e.id === "evt_01_preauth_exploit");
    expect(exploit?.raw?.["data.user"]).toBe("");
    expect(exploit?.raw?.["http.response.status_code"]).toBe("200");
    // persistence: portal web-shell written via the WAF PUT
    const shell = s.events.find(e => e.id === "evt_02_webshell_write");
    expect(shell?.event_type).toBe("file_create");
    expect(shell?.file?.name).toBe("healthcheck.cgi");
    // the pivot: SSL-VPN login under its own product vendor + source
    const vpn = s.events.find(e => e.id === "evt_04_vpn_session");
    expect(vpn?.vendor).toBe("FortiGate SSL-VPN");
    expect(vpn?.event_type).toBe("vpn_login");
    expect(vpn?.raw?.["data.user"]).toBe("j.alvarez");
    // discovery: remote-WMI parented cmd (not an interactive shell)
    const disc = s.events.find(e => e.id === "evt_05_internal_discovery");
    expect(disc?.process?.parent_name).toBe("WmiPrvSE.exe");
    // the crux: SAM-hive dump is the ticket-opening EDR detection
    const sam = s.events.find(e => e.id === "evt_06_credential_access_sam");
    expect(sam?.is_detection).toBe(true);
    expect(sam?.edr_scope).toBe("edr");
    expect(String(sam?.process?.cmdline)).toContain("save hklm\\sam");
    // lateral: SMB to the file server, process-attributed
    const smb = s.events.find(e => e.id === "evt_07_lateral_smb");
    expect(smb?.event_type).toBe("net_connection");
    expect(smb?.dst_port).toBe(445);
    expect(smb?.process?.name).toBe("net.exe");
    // the correlation joins the three planes by the external IP
    const corr = s.events.find(e => e.id === "evt_08_siem_correlation");
    expect(corr?.event_type).toBe("ioc_hit");
    expect(corr?.raw?.["ExtendedProperties.Linked Event IDs"]).toEqual(["evt_01_preauth_exploit", "evt_04_vpn_session", "evt_05_internal_discovery"]);
    // the internal foothold is where the EDR console opens
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("SRV-JUMP-03");
  });
});
