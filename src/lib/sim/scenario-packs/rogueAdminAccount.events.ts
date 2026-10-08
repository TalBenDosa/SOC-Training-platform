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
import { winAccountCreate, winGroupMemberAdd, winLogon, winSpecialPrivileges } from "@/lib/sim/emitters/windowsSecurity";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of `buildRogueAdminAccountScenario`: the events and the story title, no answer key. */
export function rogueAdminAccountScenarioEvents() {
  const B = new Date("2026-06-11T14:10:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // The out-of-hours activity begins 8h37m after the daytime control event.
  const N = 8 * HOUR + 37 * MIN;

  const dc = { hostname: "DC01", fqdn: "DC01.nexacorp.com", ip: "10.30.4.10" };
  const adminServer = { hostname: "SRV-ADM-07", fqdn: "SRV-ADM-07.nexacorp.com", ip: "10.30.4.18" };

  // The workstation the late-night sessions are driven from. Engineering, not Service Desk.
  const originHost = { hostname: "WS-ENG-2208", ip: "10.10.44.61" };

  // A real Service Desk administrator. The account is legitimate; tonight's use of it is the question.
  const admin = { sam: "t.aharoni", email: "t.aharoni@nexacorp.com" };
  const adminSid = "S-1-5-21-3421479547-3897544621-1789562108-2288";

  // The CONTROL — a genuine new hire created earlier the same day against a ticket.
  const newHire = { sam: "n.peretz", email: "n.peretz@nexacorp.com" };
  const newHireSid = "S-1-5-21-3421479547-3897544621-1789562108-5107";
  const onboardingTicket = "RITM0092416";

  // The account created at 22:51.
  const rogue = { sam: "s.katz", email: "s.katz@nexacorp.com" };
  const rogueSid = "S-1-5-21-3421479547-3897544621-1789562108-5108";

  // EDR↔scenario integration (Phase 4): one incident. Host-observable identity
  // abuse on the domain controller / admin server → edr_scope "edr". The other
  // 4720/4624/4672 records and the Sentinel correlation are pivot evidence; the
  // rogue account landing in Domain Admins is the alert-grade behavioural crux.
  const INCIDENT = "inc:ra:1";

  const cx = "nexacorp" as const;

  const events: TelemetryEvent[] = [
    // 1. CONTROL part 1 — an authorised onboarding request.
    {
      ...serviceNowRecord({
      companyId: cx, id: "evt_ra_01_ticket", ts: T(0), table: "sc_req_item", number: onboardingTicket, state: "Work in Progress",
      shortDescription: "New hire onboarding — standard user account", severity: "informational",
      extra: {
        "servicenow.catalog_item": "Employee Onboarding — Account Provisioning", "servicenow.approval": "Approved",
        "servicenow.requested_for": newHire.email, "servicenow.approved_by": "HR Operations", "servicenow.assignment_group": "Service Desk",
        "servicenow.assigned_to": admin.email, "servicenow.opened_at": "2026-06-11 09:42:00", "servicenow.sys_updated_on": "2026-06-11 14:10:00",
      },
      description: "New-hire onboarding request RITM0092416 was approved by HR Operations and assigned to the Service Desk queue, requested for n.peretz@nexacorp.com and assigned to t.aharoni.",
      }),
      // The control: an authorised request — legitimate activity inside the incident's story.
      is_baseline: true,
    },

    // 2. CONTROL part 2 — the 4720 the ticket authorised, in daylight (confirmed).
    {
      ...winAccountCreate({
        companyId: cx, id: "evt_ra_02_baseline_create", ts: T(6 * MIN), host: dc.hostname, fqdn: dc.fqdn, userEmail: admin.email,
        subjectUser: admin.sam, subjectSid: adminSid, subjectLogonId: "0x8A31C05", targetUser: newHire.sam, targetSid: newHireSid,
        samAccountName: newHire.sam, displayName: "Noa Peretz", upn: newHire.email, primaryGroupId: "513", uac: "%%2080\n\t\t%%2082\n\t\t%%2084",
        recordId: "5540118", severity: "informational",
        description: "t.aharoni created the domain account n.peretz on DC01 (Event 4720) after the onboarding request reached the Service Desk queue.",
      }),
      is_baseline: true,
      it_verify_result: "confirmed",
      it_verify_message: "Service Desk confirms this account was provisioned under approved onboarding request RITM0092416.",
    },

    // 3. The administrator's session opens from an unexpected place (T1021.001 over a valid account).
    winLogon({
      companyId: cx, id: "evt_ra_03_admin_logon", ts: T(N), host: adminServer.hostname, fqdn: adminServer.fqdn, userEmail: admin.email,
      targetUser: admin.sam, targetSid: adminSid, subjectUser: "SRV-ADM-07$", subjectSid: "S-1-5-18", logonId: "0xB17C440",
      logonType: 10, authPackage: "Negotiate", logonProcess: "User32 ", workstation: originHost.hostname, srcIp: originHost.ip, srcPort: "58114",
      processName: "C:\\Windows\\System32\\svchost.exe", recordId: "2214905", severity: "medium", mitre: "T1021.001", tactic: "Lateral Movement",
      description: "The t.aharoni account opened a LogonType 10 Remote Desktop session on the administrative server SRV-ADM-07, WorkstationName WS-ENG-2208, IpAddress 10.10.44.61.",
    }),

    // 4. The privilege set the admin session is issued (4672).
    {
    it_context: { result: "unverified", message: "The Service Desk has no task, change or call logged for this administrator at this hour. Their shift ended in the early evening, and nobody asked them to sign in to the admin server tonight." },
    ...winSpecialPrivileges({
      companyId: cx, id: "evt_ra_04_admin_privs", ts: T(N + 2 * MIN), host: adminServer.hostname, fqdn: adminServer.fqdn, userEmail: admin.email,
      targetUser: admin.sam, targetSid: adminSid, logonId: "0xB17C440",
      privilegeList: "SeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeSystemtimePrivilege\n\t\t\tSeRemoteShutdownPrivilege",
      recordId: "2214906", severity: "low",
      description: "The t.aharoni logon session on SRV-ADM-07 was issued its privilege set (Event 4672), including SeSecurityPrivilege, SeTakeOwnershipPrivilege and SeLoadDriverPrivilege.",
    }),
    },

    // 5. 22:51 — the account at the centre of the ticket is created (unverified) (T1136.002).
    {
      ...winAccountCreate({
        companyId: cx, id: "evt_ra_05_acct_create", ts: T(N + 4 * MIN), host: dc.hostname, fqdn: dc.fqdn, userEmail: admin.email,
        subjectUser: admin.sam, subjectSid: adminSid, subjectLogonId: "0x9C2F5B1", targetUser: rogue.sam, targetSid: rogueSid,
        samAccountName: rogue.sam, displayName: "S. Katz", upn: rogue.email, primaryGroupId: "513", uac: "%%2082\n\t\t%%2084",
        recordId: "5548907", severity: "high", mitre: "T1136.002", tactic: "Persistence",
        description: "t.aharoni created the domain user s.katz on DC01 — Event 4720, the same creator and the same directory as the n.peretz record created earlier under RITM0092416.",
      }),
      it_verify_result: "unverified",
      it_verify_message: "Service Desk searched the request and change queues for the last 30 days and found no record referencing this account name.",
    },

    // 6. 22:54 — three minutes old and already in Domain Admins (4728) (T1098).
    {
      ...winGroupMemberAdd({
        companyId: cx, id: "evt_ra_06_group_add_domain", ts: T(N + 7 * MIN), eventId: "4728", host: dc.hostname, fqdn: dc.fqdn, userEmail: admin.email,
        targetUser: admin.sam, subjectUser: admin.sam, subjectSid: adminSid, subjectLogonId: "0x9C2F5B1",
        memberName: "CN=s.katz,OU=Users,OU=Corp,DC=nexacorp,DC=com", memberSid: rogueSid, groupName: "Domain Admins",
        groupSid: "S-1-5-21-3421479547-3897544621-1789562108-512", recordId: "5548931", severity: "critical", mitre: "T1098.007", tactic: "Persistence",
        description: "The newly created account s.katz was added to the security-enabled global group Domain Admins on DC01 (Event 4728), by t.aharoni.",
      }),
      edr_scope: "non_edr",
    },

    // 7. 22:56 — and into local Administrators on the jump server (4732) (T1098).
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
      description: "s.katz logged on to SRV-ADM-07 with LogonType 10 — WorkstationName WS-ENG-2208, IpAddress 10.10.44.61.",
    }),

    // 9. The group membership takes effect — the new logon's rights (4672) (unverified).
    {
      ...winSpecialPrivileges({
        companyId: cx, id: "evt_ra_09_new_acct_privs", ts: T(N + 16 * MIN), host: adminServer.hostname, fqdn: adminServer.fqdn, userEmail: rogue.email,
        targetUser: rogue.sam, targetSid: rogueSid, logonId: "0xB18F2A9",
        privilegeList: "SeDebugPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeSecurityPrivilege",
        recordId: "2215191", severity: "high",
        description: "The s.katz logon session on SRV-ADM-07 was issued SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege and SeLoadDriverPrivilege among others (Event 4672).",
      }),
      it_verify_result: "unverified",
      it_verify_message: "Service Desk has no change or onboarding record for s.katz — the account that received these privileges has no authorisation on file.",
    },

    // 10. The Sentinel correlation that opened the ticket, with directory context.
    sentinelAlert({
      companyId: cx, id: "evt_ra_10_siem_context", ts: T(N + 21 * MIN), host: dc.hostname, user: admin.email,
      eventType: "ueba_anomaly", alertName: "PrivilegedGroupAddition_RecentlyCreatedAccount", ruleId: "SEN-IDENT-0244", severity: "high",
      extendedProperties: {
        "Window Start": T(N + 4 * MIN), "Window End": T(N + 16 * MIN), "New Account": "NEXACORP\\s.katz",
        "New Account Created By": "NEXACORP\\t.aharoni", "Groups Added": ["NEXACORP\\Domain Admins", "SRV-ADM-07\\Administrators"],
        "Linked Change Request": "none", "Linked Onboarding Request": "none", "Standard Change Window": "Mon-Thu 09:00-17:00 Asia/Jerusalem",
        "Actor Department": "Service Desk", "Actor Assigned Device": "WS-ITS-1140", "Actor Logon Hosts (Prior 30d)": ["WS-ITS-1140"],
        "Source Host Observed": originHost.hostname, "Source Host Department": "Engineering", "Source Host Primary User": "y.dagan@nexacorp.com",
      },
      description: "Sentinel raised the alert with directory context attached: request-record lookups for s.katz, the acting administrator's assigned device and logon history, and WS-ENG-2208's owner.",
    }),
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Out-of-Hours Account Creation — Service Desk Credentials", events, T, MIN, N, dc, adminServer, originHost, admin, onboardingTicket, rogue };
}
