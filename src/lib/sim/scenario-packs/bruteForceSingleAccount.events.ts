/**
 * Events-only half of the ./bruteForceSingleAccount.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./bruteForceSingleAccount.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { winFailedLogon, winLogon, winObjectAccess, winCredentialValidation, winShareAccess, winDetailedShareAccess } from "@/lib/sim/emitters/windowsSecurity";
import { csProcess, csFile } from "@/lib/sim/emitters/crowdstrike";
import { panConnection } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { winKerberos, winTerminalServices } from "./nativeRecords.events";

/** Telemetry half of `buildBruteForceSingleAccountScenario`: the events and the story title, no answer key. */
export function bruteForceSingleAccountScenarioEvents() {
  const B = new Date("2026-06-04T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  // The internet-published Remote Desktop server and the file server behind it.
  const rds = { hostname: "SRV-RDS-02", fqdn: "SRV-RDS-02.nexacorp.com", ip: "10.30.9.20", nat: "193.34.145.27" };
  const fileServer = { hostname: "SRV-FS-02", fqdn: "SRV-FS-02.nexacorp.com", ip: "10.30.9.55" };
  const dc = { hostname: "DC01", fqdn: "DC01.nexacorp.com", ip: "10.30.4.10" };

  // The single targeted account. Accounts Payable clerk, no HR entitlement.
  const victim = { sam: "s.wolfe", email: "s.wolfe@nexacorp.com" };
  const victimSid = "S-1-5-21-3421479547-3897544621-1789562108-4419";

  // The attacker's first guess at the username format; this account never existed.
  const wrongFormat = "swolfe";

  // A hosting-provider address used only by this storyline, and the machine name its
  // RDP client announces in every NTLM exchange.
  const attackerIp = "194.26.192.77";
  const attackerWs = "DESKTOP-4NJ1B8K";

  // Signed Microsoft binaries: the tools are ordinary, the context is not.
  const netExeHash = makeSha256("windows_system32_net_exe_signed_microsoft");
  const cmdExeHash = makeSha256("windows_system32_cmd_exe_signed_microsoft");
  const explorerHash = makeSha256("windows_explorer_exe_signed_microsoft");

  // EDR↔scenario integration (Phase 4): one incident. Host-primary brute force
  // against the published RDP server (Windows 4625/4624 + EDR on the server) →
  // edr_scope "edr". The successful 4624 and share reads are Windows Security
  // pivot telemetry; the EDR net.exe lateral-movement detection is alert-grade.
  const INCIDENT = "inc:bf:1";

  const RU = { country: "Russia", city: "Moscow" };
  const RU_GEO = { ...RU, latitude: 55.75, longitude: 37.62 };
  const cx = { companyId: "nexacorp" as const };

  // One firewall session record for the published RDP rule. The edge firewall sees the
  // public NAT address as destination and translates it to the RDS server; the source
  // port is the same ephemeral port the server later logs as IpPort.
  const fwSession = (id: string, ts: string, sport: string, o: { end: boolean; sec?: number; bytesOut?: number; bytesIn?: number; description: string }): TelemetryEvent => {
    const e = panConnection({
      ...cx, id, ts, host: rds.hostname, user: null,
      srcIp: attackerIp, dstIp: rds.nat, remotePort: 3389, app: "ms-rdp", transport: "tcp",
      action: "allow", end: o.end, ...(o.end ? { elapsedSec: o.sec ?? 1, bytesOut: o.bytesOut, bytesIn: o.bytesIn } : {}),
      mitre: "T1133", tactic: "Initial Access", severity: "low",
      description: o.description,
    });
    e.geo = RU_GEO;
    Object.assign(e.raw, {
      "pan.rule": "RDS-PUBLISHED-INBOUND", "pan.from_zone": "untrust", "pan.to_zone": "dmz",
      "pan.sport": sport, "pan.natdst": rds.ip, "pan.natdport": "3389",
    });
    return e;
  };

  const events: TelemetryEvent[] = [
    // 1. First contact: inbound RDP from the internet, allowed by policy.
    fwSession("evt_bf_01_fw_inbound", T(0), "44019", {
      end: true, sec: 9, bytesOut: 9840, bytesIn: 26112,
      description: "An address in Russia opened an inbound TCP/3389 session to the published Remote Desktop server SRV-RDS-02, allowed by the rule RDS-PUBLISHED-INBOUND.",
    }),

    // 2. First failure: the username itself is wrong (0xC0000064). The domain controller
    //    validates the NTLM credential first (4776), then the server writes the 4625.
    winCredentialValidation({
      ...cx, id: "evt_bf_02a_dc_validate", ts: T(2 * MIN - 1_000), host: dc.hostname, fqdn: dc.fqdn,
      targetUser: wrongFormat, userEmail: null, workstation: attackerWs, status: "0xC0000064", recordId: "17702214",
      severity: "low",
      description: "DC01 logged a 4776 for the account name swolfe with status 0xC0000064, workstation DESKTOP-4NJ1B8K.",
    }),
    winFailedLogon({
      ...cx, id: "evt_bf_02_fail_wrong_user", ts: T(2 * MIN), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: wrongFormat, userEmail: null, srcIp: attackerIp, subStatus: "0xC0000064",
      logonType: 3, workstation: attackerWs, srcPort: "49712", recordId: "3310442",
      severity: "low", mitre: "T1110.001", tactic: "Credential Access", geo: RU,
      description:
        "The first logon failure on SRV-RDS-02 was a 4625 for the account name swolfe, over NTLM from 194.26.192.77.",
    }),
    fwSession("evt_bf_02b_fw_session", T(2 * MIN + 2_000), "49712", {
      end: true, sec: 2, bytesOut: 3180, bytesIn: 4966,
      description: "The 2-second inbound TCP/3389 session from source port 49712 to SRV-RDS-02 closed, allowed by RDS-PUBLISHED-INBOUND.",
    }),

    // 3. The burst proper: correct account name, wrong password (0xC000006A).
    winCredentialValidation({
      ...cx, id: "evt_bf_03a_dc_validate", ts: T(3 * MIN - 1_000), host: dc.hostname, fqdn: dc.fqdn,
      targetUser: victim.sam, workstation: attackerWs, status: "0xC000006A", recordId: "17702301",
      severity: "low",
      description: "DC01 logged a 4776 for s.wolfe with status 0xC000006A, workstation DESKTOP-4NJ1B8K.",
    }),
    winFailedLogon({
      ...cx, id: "evt_bf_03_fail_burst", ts: T(3 * MIN), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, srcIp: attackerIp, subStatus: "0xC000006A",
      logonType: 3, workstation: attackerWs, srcPort: "49883", recordId: "3310519",
      severity: "medium", mitre: "T1110.001", tactic: "Credential Access", geo: RU,
      description:
        "One minute later the failures switch to the account name s.wolfe: a representative 4625 of the burst (SubStatus 0xC000006A), from 194.26.192.77 over NTLM.",
    }),
    fwSession("evt_bf_03b_fw_session", T(3 * MIN + 2_000), "49883", {
      end: true, sec: 2, bytesOut: 3210, bytesIn: 4988,
      description: "The 2-second inbound TCP/3389 session from source port 49883 to SRV-RDS-02 closed, allowed by RDS-PUBLISHED-INBOUND.",
    }),

    // 4. Last failure of the burst, 40 seconds before the success.
    winCredentialValidation({
      ...cx, id: "evt_bf_04a_dc_validate", ts: T(19 * MIN + 19_000), host: dc.hostname, fqdn: dc.fqdn,
      targetUser: victim.sam, workstation: attackerWs, status: "0xC000006A", recordId: "17709044",
      severity: "low",
      description: "DC01 logged the last 4776 of the burst at 09:19:19 for s.wolfe with status 0xC000006A, workstation DESKTOP-4NJ1B8K.",
    }),
    winFailedLogon({
      ...cx, id: "evt_bf_04_fail_last", ts: T(19 * MIN + 20_000), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, srcIp: attackerIp, subStatus: "0xC000006A",
      logonType: 3, workstation: attackerWs, srcPort: "51204", recordId: "3312088",
      severity: "medium", mitre: "T1110.001", tactic: "Credential Access", geo: RU,
      description:
        "The final 4625 of the burst, written at 09:19:20 for s.wolfe on SRV-RDS-02 from 194.26.192.77 over NTLM.",
    }),
    fwSession("evt_bf_04b_fw_session", T(19 * MIN + 22_000), "51204", {
      end: true, sec: 2, bytesOut: 3205, bytesIn: 4979,
      description: "The 2-second inbound TCP/3389 session from source port 51204 to SRV-RDS-02 closed, allowed by RDS-PUBLISHED-INBOUND.",
    }),

    // 5. THE EVENT THAT MATTERS: 4624 success, same account, same address. The firewall
    //    opens the session (still open at 09:26, so no end record yet) and the DC validates it.
    fwSession("evt_bf_05a_fw_session", T(20 * MIN - 1_500), "51377", {
      end: false,
      description: "An inbound TCP/3389 session from source port 51377 to SRV-RDS-02 was opened, allowed by RDS-PUBLISHED-INBOUND.",
    }),
    winCredentialValidation({
      ...cx, id: "evt_bf_05b_dc_validate", ts: T(20 * MIN - 1_000), host: dc.hostname, fqdn: dc.fqdn,
      targetUser: victim.sam, workstation: attackerWs, status: "0x0", recordId: "17709107",
      severity: "low",
      description: "DC01 logged a 4776 for s.wolfe with status 0x0, workstation DESKTOP-4NJ1B8K.",
    }),
    winLogon({
      ...cx, id: "evt_bf_05_auth_success", ts: T(20 * MIN), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: attackerIp, logonType: 3,
      workstation: attackerWs, logonId: "0x2F91A44", srcPort: "51377", recordId: "3312194",
      severity: "high", mitre: "T1078", tactic: "Initial Access", geo: RU_GEO,
      description:
        "A successful 4624 network logon for s.wolfe on SRV-RDS-02 at 09:20:00, LogonType 3 over NTLM, from 194.26.192.77.",
    }),
    winTerminalServices({ host: rds.hostname, account: victim.sam, accountEmail: victim.email, clientIp: attackerIp, geo: RU_GEO,
      id: "evt_bf_05c_rdp_auth", ts: T(20 * MIN + 1_000), code: "1149",
      description: "SRV-RDS-02 recorded Remote Desktop Services event 1149 for s.wolfe from 194.26.192.77: user authentication succeeded.",
    }),

    // 6. The interactive desktop the network logon unlocked (LogonType 10). The RDS server
    //    obtains a TGT for the user when the session is created.
    winKerberos({ dc, account: victim.sam, accountEmail: victim.email, accountSid: victimSid, clientIp: rds.ip,
      id: "evt_bf_06a_dc_tgt", ts: T(20 * MIN + 7_000), recordId: "17709118", eventId: "4768",
      clientPort: "50188", service: "krbtgt", serviceSid: "S-1-5-21-3421479547-3897544621-1789562108-502",
      description: "DC01 logged a 4768 Kerberos TGT request for s.wolfe from 10.30.9.20 (SRV-RDS-02).",
    }),
    winLogon({
      ...cx, id: "evt_bf_06_rdp_session", ts: T(20 * MIN + 8_000), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: attackerIp, logonType: 10,
      authPackage: "Negotiate", logonProcess: "User32 ", subjectSid: "S-1-5-18", subjectUser: "SRV-RDS-02$",
      logonId: "0x2F92B71", srcPort: "51377", workstation: rds.hostname, recordId: "3312203",
      processName: "C:\\Windows\\System32\\svchost.exe",
      severity: "high", mitre: "T1021.001", tactic: "Lateral Movement", geo: RU_GEO,
      description:
        "Eight seconds later a second 4624 on SRV-RDS-02 records LogonType 10 (RemoteInteractive) for s.wolfe from the same address, over Negotiate.",
    }),
    winTerminalServices({ host: rds.hostname, account: victim.sam, accountEmail: victim.email, clientIp: attackerIp, geo: RU_GEO,
      id: "evt_bf_06b_rdp_session_logon", ts: T(20 * MIN + 9_000), code: "21",
      description: "SRV-RDS-02 recorded Remote Desktop Services event 21 for NEXACORP\\s.wolfe: session 2 logon succeeded, source 194.26.192.77.",
    }),

    // 6c. What the desktop session starts: the shell, then a command prompt.
    csProcess({
      ...cx, id: "evt_bf_06c_explorer", ts: T(20 * MIN + 20_000), host: rds.hostname, user: victim.email, srcIp: rds.ip,
      processName: "explorer.exe", processPath: "C:\\Windows\\explorer.exe", cmdline: "C:\\Windows\\Explorer.EXE",
      parentName: "userinit.exe", parentPid: 5760, pid: 5832, sha256: explorerHash, signed: true,
      integrity: "medium", severity: "low",
      description: "explorer.exe started in session 2 on SRV-RDS-02 as NEXACORP\\s.wolfe, parent userinit.exe.",
    }),
    csProcess({
      ...cx, id: "evt_bf_06d_cmd", ts: T(21 * MIN + 40_000), host: rds.hostname, user: victim.email, srcIp: rds.ip,
      processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "\"C:\\Windows\\System32\\cmd.exe\"",
      parentName: "explorer.exe", parentPid: 5832, pid: 6112, sha256: cmdExeHash, signed: true,
      integrity: "medium", severity: "low",
      description: "cmd.exe started in session 2 on SRV-RDS-02 as NEXACORP\\s.wolfe, parent explorer.exe.",
    }),

    // 7. Ordinary-looking command, wrong share for this account (EDR detection).
    {
      ...csProcess({
        ...cx, id: "evt_bf_07_net_use", ts: T(22 * MIN), host: rds.hostname, user: victim.email, srcIp: rds.ip,
        processName: "net.exe", processPath: "C:\\Windows\\System32\\net.exe",
        cmdline: "net use Z: \\\\SRV-FS-02\\HR-Confidential", parentName: "cmd.exe",
        pid: 6248, parentPid: 6112, sha256: netExeHash, signed: true, integrity: "medium",
        mitre: "T1021.002", tactic: "Lateral Movement", severity: "medium", isDetection: true,
        description:
          "Inside the new desktop session cmd.exe spawned the signed net.exe, running: net use Z: \\\\SRV-FS-02\\HR-Confidential as NEXACORP\\s.wolfe.",
      }),
      edr_scope: "edr",
    },

    // 8. The file server's side of the mapping: a Kerberos service ticket for cifs/SRV-FS-02,
    //    then a network logon (4624, LogonType 3) from the RDS server's address. Its
    //    TargetLogonId is the session the 5140 and 4663 below read under.
    winKerberos({ dc, account: victim.sam, accountEmail: victim.email, accountSid: victimSid, clientIp: rds.ip,
      id: "evt_bf_08a_dc_tgs", ts: T(22 * MIN + 19_000), recordId: "17709433", eventId: "4769",
      clientPort: "50201", service: "SRV-FS-02$", serviceSid: "S-1-5-21-3421479547-3897544621-1789562108-2208",
      description: "DC01 logged a 4769 service-ticket request by s.wolfe for SRV-FS-02 (cifs) from 10.30.9.20 (SRV-RDS-02).",
    }),
    winLogon({
      ...cx, id: "evt_bf_08_share_access", ts: T(22 * MIN + 20_000), host: fileServer.hostname, fqdn: fileServer.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: rds.ip, logonType: 3,
      authPackage: "Kerberos", workstation: "-", logonId: "0x74C2E19", srcPort: "50214", recordId: "8874120",
      severity: "medium", mitre: "T1021.002", tactic: "Lateral Movement",
      description:
        "SRV-FS-02 recorded a 4624 network logon (LogonType 3, Kerberos) for s.wolfe from 10.30.9.20, TargetLogonId 0x74C2E19.",
    }),
    winShareAccess({
      ...cx, id: "evt_bf_08b_share_5140", ts: T(22 * MIN + 21_000), host: fileServer.hostname, fqdn: fileServer.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: rds.ip, subjectLogonId: "0x74C2E19", recordId: "8874127",
      shareName: "\\\\*\\HR-Confidential", shareLocalPath: "\\??\\E:\\Shares\\HR-Confidential",
      severity: "medium", mitre: "T1021.002", tactic: "Lateral Movement",
      description:
        "SRV-FS-02 recorded a 5140: s.wolfe connected to the HR-Confidential share from 10.30.9.20 under logon session 0x74C2E19.",
    }),

    // 9. Collection: the workbook is copied into the user's profile on the RDS server, which
    //    reads it across the mapped drive. The file server's 5145 and 4663 are the read side.
    csProcess({
      ...cx, id: "evt_bf_09a_copy", ts: T(22 * MIN + 58_000), host: rds.hostname, user: victim.email, srcIp: rds.ip,
      processName: "cmd.exe", processPath: "C:\\Windows\\System32\\cmd.exe",
      cmdline: "cmd.exe /c copy Z:\\Payroll\\2026\\salary_bands_2026.xlsx C:\\Users\\s.wolfe\\AppData\\Local\\Temp\\sb.xlsx",
      parentName: "cmd.exe", parentPid: 6112, pid: 6420, sha256: cmdExeHash, signed: true, integrity: "medium",
      mitre: "T1039", tactic: "Collection", severity: "medium",
      description: "cmd.exe (pid 6420), child of the session's cmd.exe, ran a copy of Z:\\Payroll\\2026\\salary_bands_2026.xlsx to C:\\Users\\s.wolfe\\AppData\\Local\\Temp\\sb.xlsx.",
    }),
    winDetailedShareAccess({
      ...cx, id: "evt_bf_09b_share_5145", ts: T(22 * MIN + 59_500), host: fileServer.hostname, fqdn: fileServer.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: rds.ip, srcPort: "50214", subjectLogonId: "0x74C2E19", recordId: "8874229",
      shareName: "\\\\*\\HR-Confidential", shareLocalPath: "\\??\\E:\\Shares\\HR-Confidential",
      relativeTargetName: "Payroll\\2026\\salary_bands_2026.xlsx", accessMask: "0x1", accessList: "%%4416",
      severity: "medium", mitre: "T1039", tactic: "Collection",
      description:
        "SRV-FS-02 recorded a 5145: s.wolfe opened Payroll\\2026\\salary_bands_2026.xlsx on the HR-Confidential share with ReadData.",
    }),
    {
      ...winObjectAccess({
        ...cx, id: "evt_bf_09_file_read", ts: T(23 * MIN), host: fileServer.hostname, fqdn: fileServer.fqdn,
        targetUser: victim.sam, targetSid: victimSid, srcIp: rds.ip, processName: "System",
        objectName: "E:\\Shares\\HR-Confidential\\Payroll\\2026\\salary_bands_2026.xlsx",
        fileName: "salary_bands_2026.xlsx", subjectLogonId: "0x74C2E19", recordId: "8874233",
          severity: "high", mitre: "T1039", tactic: "Collection",
        description:
          "An object-access record from SRV-FS-02 showing a payroll workbook on the HR-Confidential share being opened with read access under the s.wolfe logon session.",
      }),
      file: {
        path: "E:\\Shares\\HR-Confidential\\Payroll\\2026\\salary_bands_2026.xlsx",
        name: "salary_bands_2026.xlsx", extension: "xlsx", size: 842_240,
      },
    },
    csFile({
      ...cx, id: "evt_bf_09c_copy_written", ts: T(23 * MIN + 4_000), host: rds.hostname, user: victim.email, srcIp: rds.ip,
      path: "C:\\Users\\s.wolfe\\AppData\\Local\\Temp\\sb.xlsx", sha256: null, size: 842_240, action: "file_create",
      actorProcess: "cmd.exe", actorPid: 6420, actorPath: "C:\\Windows\\System32\\cmd.exe", actorParentName: "cmd.exe", actorParentPid: 6112,
      actorSha256: cmdExeHash, actorIntegrity: "medium", runAsUser: "NEXACORP\\s.wolfe",
      mitre: "T1074.001", tactic: "Collection", severity: "medium",
      description: "sb.xlsx (842,240 bytes) was written to C:\\Users\\s.wolfe\\AppData\\Local\\Temp on SRV-RDS-02 by cmd.exe pid 6420.",
    }),

    // 10. The correlation that opened the ticket, plus the account's context.
    (sentinelAlert({
      ...cx, id: "evt_bf_10_siem_context", ts: T(26 * MIN), host: rds.hostname, srcIp: attackerIp, user: victim.email,
      alertName: "ExternalAuthenticationBurst_SingleAccount", ruleId: "SEN-IDENT-0117", severity: "high",
      fullName: "Sara Wolfe", department: "Accounts Payable", title: "Accounts Payable Clerk",
      extendedProperties: {
        "Window Start": T(2 * MIN),
        "Window End": T(20 * MIN),
        "Failed Logons In Window": "214",
        "Failure SubStatus Seen": ["0xC0000064", "0xC000006A"],
        "Successful Logons After Failures": "1",
        "First Success": T(20 * MIN),
        "Shares Connected (Prior 90d)": ["\\\\SRV-FS-02\\AP-Invoices", "\\\\SRV-FS-02\\Scans", "\\\\SRV-FS-02\\Finance-Reports"],
        "Source Addresses In Window": [attackerIp],
        "Lockout Policy Applied": "false",
        "Group Memberships": ["Domain Users", "AP-Clerks", "Finance-Readers"],
      },
      description:
        "Sentinel raised the alert for s.wolfe on SRV-RDS-02: 214 failed logons from 194.26.192.77 in the window, then 1 success, with the account's group memberships and 90-day share history attached.",
    })),
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;
  // The Sentinel alert's host entity is the RDS server; the external address is its own
  // entity (Source Addresses In Window), never the server's host.ip.
  const siem = events.find(e => e.id === "evt_bf_10_siem_context");
  if (siem?.raw) siem.raw["host.ip"] = rds.ip;

  return { title: "Logon failures on the published Remote Desktop server", events, T, MIN, rds, fileServer, dc, victim, attackerIp, attackerWs };
}
