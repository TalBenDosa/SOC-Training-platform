/**
 * Events-only half of the ./rogueAdminAccount.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./rogueAdminAccount.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { winAccountCreate, winGroupMemberAdd, winLogon, winSpecialPrivileges } from "@/lib/sim/emitters/windowsSecurity";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { mdeProcess, mdeFile } from "@/lib/sim/emitters/mde";
import { winKerberos, winExplicitCredentials, winAccountChange } from "./nativeRecords.events";

/** Telemetry half of `buildRogueAdminAccountScenario`: the events and the story title, no answer key. */
export function rogueAdminAccountScenarioEvents() {
  const B = new Date("2026-06-11T14:10:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const SEC = 1_000;
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // The out-of-hours activity begins 8h37m after the daytime control event.
  const N = 8 * HOUR + 37 * MIN;

  const dc = { hostname: "DC01", fqdn: "DC01.nexacorp.com", ip: "10.30.4.10" };
  const adminServer = { hostname: "SRV-ADM-07", fqdn: "SRV-ADM-07.nexacorp.com", ip: "10.30.4.18" };

  // The workstation the late-night sessions are driven from. Engineering, not Service Desk.
  const originHost = { hostname: "WS-ENG-2208", fqdn: "WS-ENG-2208.nexacorp.com", ip: "10.10.44.61" };
  const originUser = { sam: "y.dagan", email: "y.dagan@nexacorp.com", sid: "S-1-5-21-3421479547-3897544621-1789562108-3320" };

  // A real Service Desk administrator. The account is legitimate; tonight's use of it is the question.
  const admin = { sam: "t.aharoni", email: "t.aharoni@nexacorp.com" };
  const adminSid = "S-1-5-21-3421479547-3897544621-1789562108-2288";

  // The CONTROL: a genuine new hire created earlier the same day against a ticket.
  const newHire = { sam: "n.peretz", email: "n.peretz@nexacorp.com" };
  const newHireSid = "S-1-5-21-3421479547-3897544621-1789562108-5107";
  const onboardingTicket = "RITM0092416";

  // The account created at 22:51.
  const rogue = { sam: "s.katz", email: "s.katz@nexacorp.com" };
  const rogueSid = "S-1-5-21-3421479547-3897544621-1789562108-5108";

  // Signed Microsoft binaries seen in the sessions below (one hash per file).
  const hashes = {
    mstsc: makeSha256("windows_system32_mstsc_exe_signed_microsoft"),
    explorer: makeSha256("windows_explorer_exe_signed_microsoft"),
    cmd: makeSha256("windows_system32_cmd_exe_signed_microsoft"),
    powershell: makeSha256("windows_system32_powershell_exe_signed_microsoft"),
    net: makeSha256("windows_system32_net_exe_signed_microsoft"),
    nltest: makeSha256("windows_system32_nltest_exe_signed_microsoft"),
    rundll32: makeSha256("windows_system32_rundll32_exe_signed_microsoft"),
  };
  const sys = "C:\\Windows\\System32\\";

  // EDR↔scenario integration (Phase 4): one incident. Host-observable identity
  // abuse on the domain controller / admin server → edr_scope "edr". The other
  // 4720/4624/4672 records and the Sentinel correlation are pivot evidence; the
  // rogue account landing in Domain Admins is the alert-grade behavioural crux.
  const INCIDENT = "inc:ra:1";

  const cx = "nexacorp" as const;

  // An interactive Defender process row on SRV-ADM-07 inside one Remote Desktop session.
  const adm = (id: string, ts: string, who: { sam: string; email: string }, p: {
    name: string; path: string; cmdline: string; parent: string; parentPid: number; pid: number; sha: string;
    mitre?: string; tactic?: string; severity?: "low" | "medium" | "high"; det?: boolean; description: string;
  }) => mdeProcess({
    companyId: cx, id, ts, host: adminServer.hostname, srcIp: adminServer.ip, user: who.email,
    processName: p.name, processPath: p.path, cmdline: p.cmdline, parentName: p.parent, parentPid: p.parentPid, pid: p.pid,
    sha256: p.sha, integrity: "High", signed: true, runAsUser: `NEXACORP\\${who.sam}`, accountName: who.sam, accountDomain: "nexacorp",
    mitre: p.mitre, tactic: p.tactic, severity: p.severity ?? "low", isDetection: p.det,
    extra: { "FolderPath": p.path, "ProcessTokenElevation": "TokenElevationTypeFull", "InitiatingProcessAccountName": who.sam },
    description: p.description,
  });

  const events: TelemetryEvent[] = [
    // 1. CONTROL part 1: an authorised onboarding request.
    {
      ...serviceNowRecord({
      companyId: cx, id: "evt_ra_01_ticket", ts: T(0), table: "sc_req_item", number: onboardingTicket, state: "Work in Progress",
      shortDescription: "New hire onboarding, standard user account", severity: "informational",
      extra: {
        "servicenow.catalog_item": "Employee Onboarding - Account Provisioning", "servicenow.approval": "Approved",
        "servicenow.requested_for": newHire.email, "servicenow.approved_by": "HR Operations", "servicenow.assignment_group": "Service Desk",
        "servicenow.assigned_to": admin.email, "servicenow.opened_at": "2026-06-11 09:42:00", "servicenow.sys_updated_on": "2026-06-11 14:10:00",
      },
      description: "New-hire onboarding request RITM0092416 was approved by HR Operations and assigned to the Service Desk queue, requested for n.peretz@nexacorp.com and assigned to t.aharoni.",
      }),
      // The control: an authorised request, legitimate activity inside the incident's story.
      is_baseline: true,
    },

    // 2. CONTROL part 2: the 4720 the ticket authorised, in daylight (confirmed), with the
    //    password reset and enable that follow every account creation.
    (() => {
      const e: TelemetryEvent = {
        ...winAccountCreate({
          companyId: cx, id: "evt_ra_02_create_n_peretz", ts: T(6 * MIN), host: dc.hostname, fqdn: dc.fqdn, userEmail: admin.email,
          subjectUser: admin.sam, subjectSid: adminSid, subjectLogonId: "0x8A31C05", targetUser: newHire.sam, targetSid: newHireSid,
          samAccountName: newHire.sam, displayName: "Noa Peretz", upn: newHire.email, primaryGroupId: "513", uac: "%%2080\n\t\t%%2082\n\t\t%%2084",
          recordId: "5540118", severity: "informational",
          description: "t.aharoni created the domain account n.peretz on DC01 (Event 4720) after the onboarding request reached the Service Desk queue.",
        }),
        is_baseline: true,
        it_verify_result: "confirmed",
        it_verify_message: "Service Desk confirms this account was provisioned under approved onboarding request RITM0092416.",
      };
      Object.assign(e.raw, { "winlog.event_data.PasswordLastSet": "<never>", "winlog.event_data.AccountExpires": "<never>", "winlog.event_data.OldUacValue": "0x0", "winlog.event_data.NewUacValue": "0x15", "winlog.event_data.SidHistory": "-", "winlog.event_data.LogonHours": "<value not set>", "winlog.event_data.PrivilegeList": "-" });
      return e;
    })(),
    {
      ...winAccountChange({
        id: "evt_ra_02a_reset_n_peretz", ts: T(6 * MIN + 30 * SEC), eventId: "4724", dc, subjectUser: admin.sam, subjectSid: adminSid,
        subjectLogonId: "0x8A31C05", targetUser: newHire.sam, targetSid: newHireSid, userEmail: admin.email, recordId: "5540131", severity: "informational",
        description: "t.aharoni reset the password of n.peretz on DC01 (Event 4724).",
      }),
      is_baseline: true,
    },
    {
      ...winAccountChange({
        id: "evt_ra_02b_enable_n_peretz", ts: T(6 * MIN + 40 * SEC), eventId: "4722", dc, subjectUser: admin.sam, subjectSid: adminSid,
        subjectLogonId: "0x8A31C05", targetUser: newHire.sam, targetSid: newHireSid, userEmail: admin.email, recordId: "5540133", severity: "informational",
        description: "t.aharoni enabled the account n.peretz on DC01 (Event 4722).",
      }),
      is_baseline: true,
    },

    // 2c. Earlier that afternoon the Service Desk used the Engineering workstation for remote support,
    //     which leaves the administrator's credential in the memory of WS-ENG-2208.
    {
      ...winLogon({
        companyId: cx, id: "evt_ra_02c_helpdesk_visit", ts: T(165 * MIN), host: originHost.hostname, fqdn: originHost.fqdn, userEmail: admin.email,
        targetUser: admin.sam, targetSid: adminSid, srcIp: "10.10.20.40", logonType: 10, authPackage: "Negotiate", logonProcess: "User32 ",
        workstation: "WS-ITS-1140", logonId: "0x6E21A90", srcPort: "50931", subjectUser: "WS-ENG-2208$", subjectSid: "S-1-5-18",
        processName: "C:\\Windows\\System32\\svchost.exe", recordId: "881177", severity: "informational",
        description: "t.aharoni logged on to WS-ENG-2208 with LogonType 10 from WS-ITS-1140 (10.10.20.40), a remote-support session for the workstation's user.",
      }),
      is_baseline: true,
    },

    // 2d. Later that evening a command prompt in the Engineering user's own session reads the memory of
    //     lsass.exe into a file (the credential the afternoon's support session left behind).
    mdeProcess({
      companyId: cx, id: "evt_ra_02d_cmd_origin", ts: T(499 * MIN + 40_000), host: originHost.hostname, srcIp: originHost.ip, user: originUser.email,
      processName: "cmd.exe", processPath: `${sys}cmd.exe`, cmdline: "\"C:\\Windows\\System32\\cmd.exe\"",
      parentName: "explorer.exe", parentPid: 3984, pid: 8712, sha256: hashes.cmd, integrity: "High", signed: true,
      runAsUser: `NEXACORP\\${originUser.sam}`, accountName: originUser.sam, accountDomain: "nexacorp", severity: "low",
      extra: { "FolderPath": `${sys}cmd.exe`, "ProcessTokenElevation": "TokenElevationTypeFull", "InitiatingProcessAccountName": originUser.sam },
      description: "cmd.exe started on WS-ENG-2208 in the session of NEXACORP\\y.dagan, parent explorer.exe.",
    }),
    mdeProcess({
      companyId: cx, id: "evt_ra_02e_rundll32_run", ts: T(500 * MIN + 5_000), host: originHost.hostname, srcIp: originHost.ip, user: originUser.email,
      processName: "rundll32.exe", processPath: `${sys}rundll32.exe`, cmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 780 C:\\Windows\\Temp\\dmp.bin full",
      parentName: "cmd.exe", parentPid: 8712, pid: 8756, sha256: hashes.rundll32, integrity: "High", signed: true,
      runAsUser: `NEXACORP\\${originUser.sam}`, accountName: originUser.sam, accountDomain: "nexacorp", mitre: "T1003.001", tactic: "Credential Access", severity: "high", isDetection: true,
      extra: { "FolderPath": `${sys}rundll32.exe`, "ProcessTokenElevation": "TokenElevationTypeFull", "InitiatingProcessAccountName": originUser.sam },
      description: "rundll32.exe (pid 8756) on WS-ENG-2208 ran comsvcs.dll MiniDump against process 780 (lsass.exe) and wrote C:\\Windows\\Temp\\dmp.bin, parent cmd.exe.",
    }),
    mdeFile({
      companyId: cx, id: "evt_ra_02f_file_written", ts: T(500 * MIN + 8_000), host: originHost.hostname, srcIp: originHost.ip, user: originUser.email,
      path: "C:\\Windows\\Temp\\dmp.bin", sha256: null, size: 58_720_256, action: "file_create", initiatingProcess: "rundll32.exe",
      initiatingCmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 780 C:\\Windows\\Temp\\dmp.bin full", severity: "medium",
      mitre: "T1003.001", tactic: "Credential Access",
      extra: { "FolderPath": "C:\\Windows\\Temp\\dmp.bin", "InitiatingProcessFolderPath": `${sys}rundll32.exe`, "InitiatingProcessId": "8756", "InitiatingProcessAccountName": originUser.sam },
      description: "dmp.bin (58,720,256 bytes) was written to C:\\Windows\\Temp on WS-ENG-2208 by rundll32.exe.",
    }),

    // 3a. The credential is first used from WS-ENG-2208: a Remote Desktop client is started in the
    //     Engineering user's session, explicit credentials are supplied for t.aharoni, and the
    //     Kerberos tickets for the jump server are requested from that workstation.
    mdeProcess({
      companyId: cx, id: "evt_ra_03a_mstsc", ts: T(N - 40 * SEC), host: originHost.hostname, srcIp: originHost.ip, user: originUser.email,
      processName: "mstsc.exe", processPath: `${sys}mstsc.exe`, cmdline: "mstsc.exe /v:SRV-ADM-07",
      parentName: "explorer.exe", parentPid: 3984, pid: 9120, sha256: hashes.mstsc, integrity: "Medium", signed: true,
      runAsUser: `NEXACORP\\${originUser.sam}`, accountName: originUser.sam, accountDomain: "nexacorp", mitre: "T1021.001", tactic: "Lateral Movement", severity: "low",
      extra: { "FolderPath": `${sys}mstsc.exe`, "ProcessTokenElevation": "TokenElevationTypeDefault", "InitiatingProcessAccountName": originUser.sam },
      description: "mstsc.exe /v:SRV-ADM-07 was started on WS-ENG-2208 in the session of NEXACORP\\y.dagan, parent explorer.exe.",
    }),
    winExplicitCredentials({
      id: "evt_ra_03b_explicit_creds", ts: T(N - 15 * SEC), host: originHost.hostname, fqdn: originHost.fqdn,
      subjectUser: originUser.sam, subjectSid: originUser.sid, subjectLogonId: "0x5C1E209", userEmail: originUser.email,
      targetUser: admin.sam, targetServer: adminServer.hostname, processName: `${sys}mstsc.exe`, processId: "0x23a0",
      clientIp: originHost.ip, recordId: "881402",
      description: "WS-ENG-2208 logged a 4648 in the session of y.dagan: mstsc.exe supplied explicit credentials for t.aharoni to SRV-ADM-07.",
    }),
    winKerberos({
      id: "evt_ra_03c_tgt", ts: T(N - 10 * SEC), eventId: "4768", dc, account: admin.sam, accountEmail: admin.email, accountSid: adminSid,
      clientIp: originHost.ip, clientPort: "52210", service: "krbtgt", serviceSid: "S-1-5-21-3421479547-3897544621-1789562108-502",
      recordId: "5548801",
      description: "DC01 logged a 4768 Kerberos TGT request for t.aharoni from 10.10.44.61 (WS-ENG-2208).",
    }),
    winKerberos({
      id: "evt_ra_03d_tgs", ts: T(N - 5 * SEC), eventId: "4769", dc, account: admin.sam, accountEmail: admin.email,
      clientIp: originHost.ip, clientPort: "52214", service: "SRV-ADM-07$", serviceSid: "S-1-5-21-3421479547-3897544621-1789562108-2301",
      recordId: "5548806",
      description: "DC01 logged a 4769 service-ticket request by t.aharoni for SRV-ADM-07 from 10.10.44.61 (WS-ENG-2208).",
    }),

    // 3. The administrator's session opens from an unexpected place (T1021.001 over a valid account).
    winLogon({
      companyId: cx, id: "evt_ra_03_admin_logon", ts: T(N), host: adminServer.hostname, fqdn: adminServer.fqdn, userEmail: admin.email,
      targetUser: admin.sam, targetSid: adminSid, subjectUser: "SRV-ADM-07$", subjectSid: "S-1-5-18", logonId: "0xB17C440",
      logonType: 10, authPackage: "Negotiate", logonProcess: "User32 ", workstation: originHost.hostname, srcIp: originHost.ip, srcPort: "58114",
      processName: "C:\\Windows\\System32\\svchost.exe", recordId: "2214905", severity: "medium", mitre: "T1021.001", tactic: "Lateral Movement",
      description: "The t.aharoni account opened a LogonType 10 Remote Desktop session on the administrative server SRV-ADM-07, WorkstationName WS-ENG-2208, IpAddress 10.10.44.61.",
    }),

    // 4. The privilege set the admin session is issued (4672), written in the same second as the logon.
    {
    it_context: { result: "unverified", message: "The Service Desk has no task, change or call logged for this administrator at this hour. Their shift ended in the early evening, and nobody asked them to sign in to the admin server tonight." },
    ...winSpecialPrivileges({
      companyId: cx, id: "evt_ra_04_admin_privs", ts: T(N + SEC), host: adminServer.hostname, fqdn: adminServer.fqdn, userEmail: admin.email,
      targetUser: admin.sam, targetSid: adminSid, logonId: "0xB17C440",
      privilegeList: "SeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeSystemtimePrivilege\n\t\t\tSeRemoteShutdownPrivilege",
      recordId: "2214906", severity: "low",
      description: "The t.aharoni logon session on SRV-ADM-07 was issued its privilege set (Event 4672), including SeSecurityPrivilege, SeTakeOwnershipPrivilege and SeLoadDriverPrivilege.",
    }),
    },

    // 4a. What the session does: shell, command prompt, then the account is built from PowerShell.
    adm("evt_ra_04a_explorer", T(N + 12 * SEC), admin, {
      name: "explorer.exe", path: "C:\\Windows\\explorer.exe", cmdline: "C:\\Windows\\Explorer.EXE", parent: "userinit.exe", parentPid: 4388, pid: 4412,
      sha: hashes.explorer, description: "explorer.exe started in the Remote Desktop session of t.aharoni on SRV-ADM-07, parent userinit.exe.",
    }),
    adm("evt_ra_04b_cmd", T(N + 3 * MIN + 25 * SEC), admin, {
      name: "cmd.exe", path: `${sys}cmd.exe`, cmdline: "\"C:\\Windows\\System32\\cmd.exe\"", parent: "explorer.exe", parentPid: 4412, pid: 7240,
      sha: hashes.cmd, description: "cmd.exe started in the session of t.aharoni on SRV-ADM-07, parent explorer.exe.",
    }),
    adm("evt_ra_04c_new_aduser", T(N + 3 * MIN + 40 * SEC), admin, {
      name: "powershell.exe", path: `${sys}WindowsPowerShell\\v1.0\\powershell.exe`,
      cmdline: "powershell.exe -NoProfile -Command \"New-ADUser -SamAccountName s.katz -Name 'S. Katz' -UserPrincipalName s.katz@nexacorp.com -Path 'OU=Users,OU=Corp,DC=nexacorp,DC=com'\"",
      parent: "cmd.exe", parentPid: 7240, pid: 7312, sha: hashes.powershell, mitre: "T1136.002", tactic: "Persistence", severity: "high", det: true,
      description: "powershell.exe ran New-ADUser for the account s.katz in the session of t.aharoni on SRV-ADM-07, parent cmd.exe.",
    }),
    winLogon({
      companyId: cx, id: "evt_ra_04d_dc_session", ts: T(N + 3 * MIN + 50 * SEC), host: dc.hostname, fqdn: dc.fqdn, userEmail: admin.email,
      targetUser: admin.sam, targetSid: adminSid, srcIp: adminServer.ip, logonType: 3, authPackage: "Kerberos", workstation: "-",
      logonId: "0x9C2F5B1", srcPort: "50772", recordId: "5548890", severity: "low",
      description: "DC01 recorded a 4624 network logon (LogonType 3, Kerberos) for t.aharoni from 10.30.4.18 (SRV-ADM-07), TargetLogonId 0x9C2F5B1.",
    }),

    // 5. 22:51 the account at the centre of the ticket is created (unverified) (T1136.002).
    (() => {
      const e: TelemetryEvent = {
        ...winAccountCreate({
          companyId: cx, id: "evt_ra_05_acct_create", ts: T(N + 4 * MIN), host: dc.hostname, fqdn: dc.fqdn, userEmail: admin.email,
          subjectUser: admin.sam, subjectSid: adminSid, subjectLogonId: "0x9C2F5B1", targetUser: rogue.sam, targetSid: rogueSid,
          samAccountName: rogue.sam, displayName: "S. Katz", upn: rogue.email, primaryGroupId: "513", uac: "%%2080\n\t\t%%2082\n\t\t%%2084",
          recordId: "5548907", severity: "high", mitre: "T1136.002", tactic: "Persistence",
          description: "t.aharoni created the domain user s.katz on DC01, Event 4720, the same creator and the same directory as the n.peretz record created earlier under RITM0092416.",
        }),
        it_verify_result: "unverified",
        it_verify_message: "Service Desk searched the request and change queues for the last 30 days and found no record referencing this account name.",
      };
      Object.assign(e.raw, { "winlog.event_data.PasswordLastSet": "<never>", "winlog.event_data.AccountExpires": "<never>", "winlog.event_data.OldUacValue": "0x0", "winlog.event_data.NewUacValue": "0x15", "winlog.event_data.SidHistory": "-", "winlog.event_data.LogonHours": "<value not set>", "winlog.event_data.PrivilegeList": "-" });
      return e;
    })(),
    winAccountChange({
      id: "evt_ra_05a_reset_s_katz", ts: T(N + 4 * MIN + 30 * SEC), eventId: "4724", dc, subjectUser: admin.sam, subjectSid: adminSid,
      subjectLogonId: "0x9C2F5B1", targetUser: rogue.sam, targetSid: rogueSid, userEmail: admin.email, recordId: "5548915", severity: "medium",
      description: "t.aharoni reset the password of s.katz on DC01 (Event 4724).",
    }),
    winAccountChange({
      id: "evt_ra_05b_enable_s_katz", ts: T(N + 4 * MIN + 40 * SEC), eventId: "4722", dc, subjectUser: admin.sam, subjectSid: adminSid,
      subjectLogonId: "0x9C2F5B1", targetUser: rogue.sam, targetSid: rogueSid, userEmail: admin.email, recordId: "5548917", severity: "medium",
      description: "t.aharoni enabled the account s.katz on DC01 (Event 4722).",
    }),

    // 5c. The group additions are typed in the same session shortly before they are logged.
    adm("evt_ra_05c_add_adgroupmember", T(N + 6 * MIN + 30 * SEC), admin, {
      name: "powershell.exe", path: `${sys}WindowsPowerShell\\v1.0\\powershell.exe`,
      cmdline: "powershell.exe -NoProfile -Command \"Add-ADGroupMember -Identity 'Domain Admins' -Members s.katz\"",
      parent: "cmd.exe", parentPid: 7240, pid: 7388, sha: hashes.powershell, mitre: "T1098.007", tactic: "Persistence", severity: "high", det: true,
      description: "powershell.exe ran Add-ADGroupMember for Domain Admins and s.katz in the session of t.aharoni on SRV-ADM-07, parent cmd.exe.",
    }),

    // 6. 22:54: three minutes old and already in Domain Admins (4728) (T1098).
    {
      ...winGroupMemberAdd({
        companyId: cx, id: "evt_ra_06_group_add_domain", ts: T(N + 7 * MIN), eventId: "4728", host: dc.hostname, fqdn: dc.fqdn, userEmail: admin.email,
        targetUser: admin.sam, subjectUser: admin.sam, subjectSid: adminSid, subjectLogonId: "0x9C2F5B1",
        memberName: "CN=s.katz,OU=Users,OU=Corp,DC=nexacorp,DC=com", memberSid: rogueSid, groupName: "Domain Admins",
        groupSid: "S-1-5-21-3421479547-3897544621-1789562108-512", recordId: "5548931", severity: "critical", mitre: "T1098.007", tactic: "Persistence",
        description: "The newly created account s.katz was added to the security-enabled global group Domain Admins on DC01 (Event 4728), by t.aharoni.",
      }),
      edr_scope: "hybrid", // identity plane (4728 on the DC) plus the process telemetry of the sessions that drove it
    },

    adm("evt_ra_06a_net_localgroup", T(N + 8 * MIN + 40 * SEC), admin, {
      name: "net.exe", path: `${sys}net.exe`, cmdline: "net.exe localgroup Administrators NEXACORP\\s.katz /add",
      parent: "cmd.exe", parentPid: 7240, pid: 7452, sha: hashes.net, mitre: "T1098.007", tactic: "Persistence", severity: "high", det: true,
      description: "A net.exe process (pid 7452) in the session of t.aharoni on SRV-ADM-07 added NEXACORP\\s.katz to the local Administrators group, parent cmd.exe.",
    }),

    // 7. 22:56 and into local Administrators on the jump server (4732) (T1098).
    winGroupMemberAdd({
      companyId: cx, id: "evt_ra_07_group_add_local", ts: T(N + 9 * MIN), eventId: "4732", host: adminServer.hostname, fqdn: adminServer.fqdn, userEmail: admin.email,
      targetUser: admin.sam, subjectUser: admin.sam, subjectSid: adminSid, subjectLogonId: "0xB17C440",
      memberName: "-", memberSid: rogueSid, groupName: "Administrators", groupDomain: "Builtin", groupSid: "S-1-5-32-544",
      recordId: "2215044", severity: "high", mitre: "T1098", tactic: "Persistence",
      description: "s.katz was added to the local Administrators group on SRV-ADM-07, recorded as Event 4732 on the member server itself.",
    }),

    // 8. The new account uses itself, from the same host (T1021.001).
    winLogon({
      companyId: cx, id: "evt_ra_08_new_acct_logon", ts: T(N + 15 * MIN), host: adminServer.hostname, fqdn: adminServer.fqdn, userEmail: rogue.email,
      targetUser: rogue.sam, targetSid: rogueSid, subjectUser: "SRV-ADM-07$", subjectSid: "S-1-5-18", logonId: "0xB18F2A9",
      logonType: 10, authPackage: "Negotiate", logonProcess: "User32 ", workstation: originHost.hostname, srcIp: originHost.ip, srcPort: "58622",
      processName: "C:\\Windows\\System32\\svchost.exe", recordId: "2215190", severity: "critical", mitre: "T1021.001", tactic: "Lateral Movement",
      description: "s.katz logged on to SRV-ADM-07 with LogonType 10, WorkstationName WS-ENG-2208, IpAddress 10.10.44.61.",
    }),

    // 9. The group membership takes effect: the new logon's rights (4672), written with the logon (unverified).
    {
      ...winSpecialPrivileges({
        companyId: cx, id: "evt_ra_09_new_acct_privs", ts: T(N + 15 * MIN + SEC), host: adminServer.hostname, fqdn: adminServer.fqdn, userEmail: rogue.email,
        targetUser: rogue.sam, targetSid: rogueSid, logonId: "0xB18F2A9",
        privilegeList: "SeDebugPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeSecurityPrivilege",
        recordId: "2215191", severity: "high",
        description: "The s.katz logon session on SRV-ADM-07 was issued SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege and SeLoadDriverPrivilege among others (Event 4672).",
      }),
      it_verify_result: "unverified",
      it_verify_message: "Service Desk has no change or onboarding record for s.katz. The account that received these privileges has no authorisation on file.",
    },

    // 9a. What the new account does with its rights in the first minutes.
    adm("evt_ra_09a_explorer", T(N + 15 * MIN + 20 * SEC), rogue, {
      name: "explorer.exe", path: "C:\\Windows\\explorer.exe", cmdline: "C:\\Windows\\Explorer.EXE", parent: "userinit.exe", parentPid: 4520, pid: 4564,
      sha: hashes.explorer, description: "explorer.exe started in the Remote Desktop session of s.katz on SRV-ADM-07, parent userinit.exe.",
    }),
    adm("evt_ra_09b_cmd", T(N + 18 * MIN), rogue, {
      name: "cmd.exe", path: `${sys}cmd.exe`, cmdline: "\"C:\\Windows\\System32\\cmd.exe\"", parent: "explorer.exe", parentPid: 4564, pid: 7560,
      sha: hashes.cmd, description: "cmd.exe started in the session of s.katz on SRV-ADM-07, parent explorer.exe.",
    }),
    adm("evt_ra_09c_net_group", T(N + 18 * MIN + 30 * SEC), rogue, {
      name: "net.exe", path: `${sys}net.exe`, cmdline: "net.exe group \"Domain Admins\" /domain",
      parent: "cmd.exe", parentPid: 7560, pid: 7604, sha: hashes.net, mitre: "T1069.002", tactic: "Discovery", severity: "medium",
      description: "net.exe group \"Domain Admins\" /domain ran in the session of s.katz on SRV-ADM-07, parent cmd.exe.",
    }),
    adm("evt_ra_09d_nltest", T(N + 19 * MIN + 10 * SEC), rogue, {
      name: "nltest.exe", path: `${sys}nltest.exe`, cmdline: "nltest.exe /dclist:nexacorp.com",
      parent: "cmd.exe", parentPid: 7560, pid: 7648, sha: hashes.nltest, mitre: "T1018", tactic: "Discovery", severity: "medium",
      description: "nltest.exe /dclist:nexacorp.com ran in the session of s.katz on SRV-ADM-07, parent cmd.exe.",
    }),

    // 10. The Sentinel correlation that opened the ticket, with directory context.
    sentinelAlert({
      companyId: cx, id: "evt_ra_10_siem_context", ts: T(N + 21 * MIN), host: dc.hostname, user: admin.email,
      eventType: "ueba_anomaly", alertName: "PrivilegedGroupAddition_RecentlyCreatedAccount", ruleId: "SEN-IDENT-0244", severity: "high",
      extendedProperties: {
        "Window Start": T(N + 4 * MIN), "Window End": T(N + 16 * MIN), "New Account": "NEXACORP\\s.katz",
        "New Account Created By": "NEXACORP\\t.aharoni", "Groups Added": ["NEXACORP\\Domain Admins", "SRV-ADM-07\\Administrators"],
        "Linked Change Request": "none", "Linked Onboarding Request": "none", "Standard Change Window": "Mon-Thu 09:00-17:00 UTC",
        "Actor Department": "Service Desk", "Actor Assigned Device": "WS-ITS-1140", "Actor Logon Hosts (Prior 30d)": ["WS-ITS-1140"],
        "Source Host Observed": originHost.hostname, "Source Host Department": "Engineering", "Source Host Primary User": "y.dagan@nexacorp.com",
      },
      description: "Sentinel raised the alert with directory context attached: request-record lookups for s.katz, the acting administrator's assigned device and logon history, and WS-ENG-2208's owner.",
    }),
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Late-evening privileged group change on the DC", events, T, MIN, SEC, N, dc, adminServer, originHost, admin, onboardingTicket, rogue };
}
