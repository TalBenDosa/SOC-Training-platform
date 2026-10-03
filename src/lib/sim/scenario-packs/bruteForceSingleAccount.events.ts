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
import { winFailedLogon, winLogon, winObjectAccess } from "@/lib/sim/emitters/windowsSecurity";
import { csProcess } from "@/lib/sim/emitters/crowdstrike";
import { panConnection } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of `buildBruteForceSingleAccountScenario`: the events and the story title, no answer key. */
export function bruteForceSingleAccountScenarioEvents() {
  const B = new Date("2026-06-04T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  // The internet-published Remote Desktop server and the file server behind it.
  const rds = { hostname: "SRV-RDS-02", fqdn: "SRV-RDS-02.nexacorp.com", ip: "10.30.9.20", nat: "193.34.145.27" };
  const fileServer = { hostname: "SRV-FS-02", fqdn: "SRV-FS-02.nexacorp.com", ip: "10.30.9.55" };

  // The single targeted account. Accounts Payable clerk — no HR entitlement.
  const victim = { sam: "s.wolfe", email: "s.wolfe@nexacorp.com" };
  const victimSid = "S-1-5-21-3421479547-3897544621-1789562108-4419";

  // The attacker's first guess at the username format — this account never existed.
  const wrongFormat = "swolfe";

  // A hosting-provider address used only by this storyline.
  const attackerIp = "194.26.192.77";

  // Signed Microsoft binary — the tool is ordinary, the context is not.
  const netExeHash = makeSha256("windows_system32_net_exe_signed_microsoft");

  // EDR↔scenario integration (Phase 4): one incident. Host-primary brute force
  // against the published RDP server (Windows 4625/4624 + EDR on the server) →
  // edr_scope "edr". The successful 4624 and share reads are Windows Security
  // pivot telemetry; the EDR net.exe lateral-movement detection is alert-grade.
  const INCIDENT = "inc:bf:1";

  const RU = { country: "Russia", city: "Moscow" };
  const RU_GEO = { ...RU, latitude: 55.75, longitude: 37.62 };
  const cx = { companyId: "nexacorp" as const };

  const events: TelemetryEvent[] = [
    // 1. First contact — inbound RDP from the internet, allowed by policy.
    {
      ...(panConnection({
        ...cx, id: "evt_bf_01_fw_inbound", ts: T(0), host: rds.hostname, user: null,
        srcIp: attackerIp, dstIp: rds.ip, remotePort: 3389, app: "ms-rdp", transport: "tcp",
        action: "allow", end: true, bytesOut: 9840, bytesIn: 26112,
        mitre: "T1133", tactic: "Initial Access", severity: "medium",
        description:
          "An address in Russia opened an inbound TCP/3389 session to the published Remote Desktop server SRV-RDS-02, allowed by the rule RDS-PUBLISHED-INBOUND.",
      })),
      geo: RU_GEO,  // pan.rule set to RDS-PUBLISHED-INBOUND in the post-pass below
    },

    // 2. First failure — the username itself is wrong (0xC0000064).
    winFailedLogon({
      ...cx, id: "evt_bf_02_fail_wrong_user", ts: T(2 * MIN), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: wrongFormat, userEmail: null, srcIp: attackerIp, subStatus: "0xC0000064",
      logonType: 3, workstation: "WORKSTATION", srcPort: "49712", recordId: "3310442",
      severity: "low", mitre: "T1110.001", tactic: "Credential Access", geo: RU,
      description:
        "The first logon failure on SRV-RDS-02 was a 4625 for the account name swolfe, over NTLM from 194.26.192.77.",
    }),

    // 3. The burst proper — correct account name, wrong password (0xC000006A).
    winFailedLogon({
      ...cx, id: "evt_bf_03_fail_burst", ts: T(3 * MIN), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, srcIp: attackerIp, subStatus: "0xC000006A",
      logonType: 3, workstation: "WORKSTATION", srcPort: "49883", recordId: "3310519",
      severity: "medium", mitre: "T1110.001", tactic: "Credential Access", geo: RU,
      description:
        "One minute later the failures switch to the account name s.wolfe — a representative 4625 of the burst (SubStatus 0xC000006A), from 194.26.192.77 over NTLM.",
    }),

    // 4. Last failure of the burst — 40 seconds before the ticket's answer.
    winFailedLogon({
      ...cx, id: "evt_bf_04_fail_last", ts: T(19 * MIN + 20_000), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, srcIp: attackerIp, subStatus: "0xC000006A",
      logonType: 3, workstation: "WORKSTATION", srcPort: "51204", recordId: "3312088",
      severity: "medium", mitre: "T1110.001", tactic: "Credential Access", geo: RU,
      description:
        "The final 4625 of the burst, written at 09:19:20 for s.wolfe on SRV-RDS-02 from 194.26.192.77 over NTLM.",
    }),

    // 5. THE EVENT THAT MATTERS — 4624 success, same account, same address.
    winLogon({
      ...cx, id: "evt_bf_05_auth_success", ts: T(20 * MIN), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: attackerIp, logonType: 3,
      logonId: "0x2F91A44", srcPort: "51377", recordId: "3312194",
      severity: "high", mitre: "T1078", tactic: "Initial Access", geo: RU_GEO,
      description:
        "A successful 4624 network logon for s.wolfe on SRV-RDS-02 at 09:20:00, LogonType 3 over NTLM, from 194.26.192.77.",
    }),

    // 6. The interactive desktop the network logon unlocked (LogonType 10).
    winLogon({
      ...cx, id: "evt_bf_06_rdp_session", ts: T(20 * MIN + 8_000), host: rds.hostname, fqdn: rds.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: attackerIp, logonType: 10,
      authPackage: "Negotiate", logonProcess: "User32 ", subjectSid: "S-1-5-18", subjectUser: "SRV-RDS-02$",
      logonId: "0x2F92B71", srcPort: "51377", workstation: rds.hostname, recordId: "3312203",
      processName: "C:\\Windows\\System32\\svchost.exe",
      severity: "high", mitre: "T1021.001", tactic: "Lateral Movement", geo: RU_GEO,
      description:
        "Eight seconds later a second 4624 on SRV-RDS-02 records LogonType 10 — RemoteInteractive — for s.wolfe from the same address, over Negotiate.",
    }),

    // 7. Ordinary-looking command, wrong share for this account (EDR detection).
    {
      ...csProcess({
        ...cx, id: "evt_bf_07_net_use", ts: T(22 * MIN), host: rds.hostname, user: victim.email, srcIp: rds.ip,
        processName: "net.exe", processPath: "C:\\Windows\\System32\\net.exe",
        cmdline: "net use Z: \\\\SRV-FS-02\\HR-Confidential", parentName: "cmd.exe",
        pid: 6248, parentPid: 6112, sha256: netExeHash, signed: true,
        mitre: "T1021.002", tactic: "Lateral Movement", severity: "medium", isDetection: true,
        description:
          "Inside the new desktop session cmd.exe spawned the signed net.exe, running: net use Z: \\\\SRV-FS-02\\HR-Confidential as NEXACORP\\s.wolfe.",
      }),
      edr_scope: "edr",
    },

    // 8. The file server's side of the mapping: a Kerberos network logon (4624, LogonType 3)
    //    from the RDS server's address. Its TargetLogonId is the session the 4663 below reads under.
    winLogon({
      ...cx, id: "evt_bf_08_share_access", ts: T(22 * MIN + 20_000), host: fileServer.hostname, fqdn: fileServer.fqdn,
      targetUser: victim.sam, targetSid: victimSid, srcIp: rds.ip, logonType: 3,
      authPackage: "Kerberos", logonId: "0x74C2E19", srcPort: "50214", recordId: "8874120",
      severity: "medium", mitre: "T1021.002", tactic: "Lateral Movement",
      description:
        "SRV-FS-02 recorded a 4624 network logon (LogonType 3, Kerberos) for s.wolfe from 10.30.9.20 — TargetLogonId 0x74C2E19.",
    }),

    // 9. A file is actually read off the share (4663).
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
  // The published-RDP rule is its own inbound rule, not the outbound web rule the emitter defaults to.
  const fw = events.find(e => e.id === "evt_bf_01_fw_inbound");
  if (fw?.raw) fw.raw["pan.rule"] = "RDS-PUBLISHED-INBOUND";
  // The Sentinel alert's host entity is the RDS server; the external address is its own
  // entity (Source Addresses In Window), never the server's host.ip.
  const siem = events.find(e => e.id === "evt_bf_10_siem_context");
  if (siem?.raw) siem.raw["host.ip"] = rds.ip;

  return { title: "Logon Failure Burst — Published Remote Desktop Server", events, T, MIN, rds, fileServer, victim, attackerIp };
}
