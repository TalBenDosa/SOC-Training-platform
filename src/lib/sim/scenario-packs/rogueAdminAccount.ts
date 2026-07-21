/**
 * Scenario pack: "Out-of-Hours Account Creation — Service Desk Credentials"
 *
 * BEGINNER tier. A helpdesk administrator's account creates a new domain user
 * late at night and puts it into Domain Admins three minutes later. Every one
 * of those actions is something that account is entitled to do, and every one
 * of them succeeds cleanly. Nothing is blocked, nothing is malformed, no
 * malware runs.
 *
 * The scenario deliberately ships a CONTROL: earlier the same day the same
 * administrator created a different account, during business hours, against an
 * approved onboarding request. Put the two side by side and the difference is
 * not technical — it is the absence of an authorisation record, the hour, and
 * the group membership that followed. That comparison is the whole lesson:
 * a beginner asks "was this allowed?", an analyst asks "was this authorised?".
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildRogueAdminAccountScenario(
  scenarioId = "rogue-admin-account-2026",
): ScenarioBundle {
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

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. CONTROL part 1 — what an authorised account creation looks like.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_01_ticket",
      ts: T(0),
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      severity: "informational",
      description:
        "A new-hire onboarding request, RITM0092416, was approved by HR and assigned to the Service Desk queue. It names the person the account is for, the manager who signed it off, and the start date. Keep this record in view — you will want something to compare tonight's activity against.",
      raw: {
        "servicenow.table": "sc_req_item",
        "servicenow.number": onboardingTicket,
        "servicenow.short_description": "New hire onboarding — standard user account",
        "servicenow.catalog_item": "Employee Onboarding — Account Provisioning",
        "servicenow.state": "Work in Progress",
        "servicenow.approval": "Approved",
        "servicenow.requested_for": newHire.email,
        "servicenow.approved_by": "HR Operations",
        "servicenow.assignment_group": "Service Desk",
        "servicenow.assigned_to": admin.email,
        "servicenow.opened_at": "2026-06-11 09:42:00",
        "servicenow.sys_updated_on": "2026-06-11 14:10:00",
      },
    },

    // ---------------------------------------------------------------------
    // 2. CONTROL part 2 — the 4720 that the ticket authorised, in daylight.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_02_baseline_create",
      ts: T(6 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "account_create",
      hostname: dc.hostname,
      user_email: admin.email,
      severity: "informational",
      it_verify_result: "confirmed",
      it_verify_message:
        "Service Desk confirms this account was provisioned under approved onboarding request RITM0092416.",
      description:
        "t.aharoni created the domain account n.peretz on DC01 at 14:16, six minutes after the onboarding request landed in the Service Desk queue. This is the routine version of the same operation you will see again later tonight.",
      raw: {
        // Windows Security Event 4720 — A user account was created
        "winlog.event_id": "4720",
        "winlog.channel": "Security",
        "winlog.computer_name": dc.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5540118",
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": admin.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x8A31C05",
        "winlog.event_data.TargetSid": newHireSid,
        "winlog.event_data.TargetUserName": newHire.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.SamAccountName": newHire.sam,
        "winlog.event_data.DisplayName": "Noa Peretz",
        "winlog.event_data.UserPrincipalName": newHire.email,
        "winlog.event_data.PrimaryGroupId": "513",
        "winlog.event_data.UserAccountControl": "%%2080\n\t\t%%2082\n\t\t%%2084",
        "event.code": "4720",
        "event.action": "user-account-created",
        "event.outcome": "success",
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 3. 22:47 — the administrator's session opens from an unexpected place.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_03_admin_logon",
      ts: T(N),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: adminServer.hostname,
      user_email: admin.email,
      src_ip: originHost.ip,
      severity: "medium",
      mitre_technique: "T1078",
      mitre_tactic: "TA0001",
      description:
        "At 22:47 the t.aharoni account opened a Remote Desktop session on the administrative server SRV-ADM-07. Read WorkstationName and IpAddress on this record and hold on to them — you will meet the same two values again later in the timeline.",
      authentication: { method: "Kerberos", result: "success", logon_type: 10 },
      raw: {
        // Windows Security Event 4624 — An account was successfully logged on
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": adminServer.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2214905",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "SRV-ADM-07$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": adminSid,
        "winlog.event_data.TargetUserName": admin.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xB17C440",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32 ",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": originHost.hostname,
        "winlog.event_data.IpAddress": originHost.ip,
        "winlog.event_data.IpPort": "58114",
        "winlog.event_data.ElevatedToken": "%%1842",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\svchost.exe",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": originHost.ip,
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 4. The rights that make everything after this technically permitted.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_04_admin_privs",
      ts: T(N + 2 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "privileged_operation",
      hostname: adminServer.hostname,
      user_email: admin.email,
      severity: "low",
      description:
        "The t.aharoni logon session on SRV-ADM-07 was issued its privilege set. This is normal for a Service Desk administrator and is exactly why nothing that follows is rejected by Windows — the account holds the rights the operations require.",
      raw: {
        // Windows Security Event 4672 — Special privileges assigned to new logon
        "winlog.event_id": "4672",
        "winlog.channel": "Security",
        "winlog.computer_name": adminServer.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2214906",
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": admin.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xB17C440",
        "winlog.event_data.PrivilegeList":
          "SeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeSystemtimePrivilege\n\t\t\tSeRemoteShutdownPrivilege",
        "event.code": "4672",
        "event.action": "special-privileges-assigned",
        "event.outcome": "success",
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 5. 22:51 — the account at the centre of the ticket is created.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_05_acct_create",
      ts: T(N + 4 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "account_create",
      hostname: dc.hostname,
      user_email: admin.email,
      severity: "high",
      mitre_technique: "T1136.002",
      mitre_tactic: "TA0003",
      it_verify_result: "unverified",
      it_verify_message:
        "Service Desk searched the request and change queues for the last 30 days and found no record referencing this account name.",
      description:
        "At 22:51 the same administrator account created the domain user s.katz on DC01. The 4720 record itself is structurally identical to the one written at 14:16 — same event ID, same creator, same directory. Compare the surrounding context rather than the record.",
      raw: {
        "winlog.event_id": "4720",
        "winlog.channel": "Security",
        "winlog.computer_name": dc.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5548907",
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": admin.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xB17C440",
        "winlog.event_data.TargetSid": rogueSid,
        "winlog.event_data.TargetUserName": rogue.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.SamAccountName": rogue.sam,
        "winlog.event_data.DisplayName": "S. Katz",
        "winlog.event_data.UserPrincipalName": rogue.email,
        "winlog.event_data.PrimaryGroupId": "513",
        "winlog.event_data.UserAccountControl": "%%2080\n\t\t%%2082\n\t\t%%2084",
        "event.code": "4720",
        "event.action": "user-account-created",
        "event.outcome": "success",
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 6. 22:54 — three minutes old and already in a domain-wide group.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_06_group_add_domain",
      ts: T(N + 7 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "group_modify",
      hostname: dc.hostname,
      user_email: admin.email,
      severity: "critical",
      mitre_technique: "T1098",
      mitre_tactic: "TA0003",
      description:
        "Three minutes after it was created, s.katz was added to a security-enabled global group on DC01. Read TargetUserName on this record to see which group, and MemberName to see who was put into it.",
      raw: {
        // Windows Security Event 4728 — A member was added to a security-enabled global group
        "winlog.event_id": "4728",
        "winlog.channel": "Security",
        "winlog.computer_name": dc.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "5548931",
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": admin.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xB17C440",
        "winlog.event_data.MemberName": "CN=s.katz,OU=Users,OU=Corp,DC=nexacorp,DC=com",
        "winlog.event_data.MemberSid": rogueSid,
        "winlog.event_data.TargetUserName": "Domain Admins",
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetSid": "S-1-5-21-3421479547-3897544621-1789562108-512",
        "event.code": "4728",
        "event.action": "added-member-to-group",
        "event.outcome": "success",
        "group.name": "Domain Admins",
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 7. 22:56 — and into the local Administrators group on the jump server.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_07_group_add_local",
      ts: T(N + 9 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "group_modify",
      hostname: adminServer.hostname,
      user_email: admin.email,
      severity: "high",
      mitre_technique: "T1098",
      mitre_tactic: "TA0003",
      description:
        "Two minutes later the same account was also added to the local Administrators group on SRV-ADM-07 itself. Event 4732 is the local-group counterpart of 4728, and it is written on the member server rather than on the domain controller.",
      raw: {
        // Windows Security Event 4732 — A member was added to a security-enabled local group
        "winlog.event_id": "4732",
        "winlog.channel": "Security",
        "winlog.computer_name": adminServer.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2215044",
        "winlog.event_data.SubjectUserSid": adminSid,
        "winlog.event_data.SubjectUserName": admin.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xB17C440",
        "winlog.event_data.MemberName": "-",
        "winlog.event_data.MemberSid": rogueSid,
        "winlog.event_data.TargetUserName": "Administrators",
        "winlog.event_data.TargetDomainName": "Builtin",
        "winlog.event_data.TargetSid": "S-1-5-32-544",
        "event.code": "4732",
        "event.action": "added-member-to-group",
        "event.outcome": "success",
        "group.name": "Administrators",
        "user.name": admin.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 8. 23:02 — the new account uses itself, from a familiar-looking place.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_08_new_acct_logon",
      ts: T(N + 15 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "auth_success",
      hostname: adminServer.hostname,
      user_email: rogue.email,
      src_ip: originHost.ip,
      severity: "critical",
      mitre_technique: "T1078",
      mitre_tactic: "TA0001",
      description:
        "At 23:02 the s.katz account logged on interactively to SRV-ADM-07 for the first time, eleven minutes after it came into existence. Compare WorkstationName and IpAddress on this record with the same two fields on evt_ra_03_admin_logon.",
      authentication: { method: "Kerberos", result: "success", logon_type: 10 },
      raw: {
        "winlog.event_id": "4624",
        "winlog.channel": "Security",
        "winlog.computer_name": adminServer.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2215190",
        "winlog.event_data.SubjectUserSid": "S-1-5-18",
        "winlog.event_data.SubjectUserName": "SRV-ADM-07$",
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0x3E7",
        "winlog.event_data.TargetUserSid": rogueSid,
        "winlog.event_data.TargetUserName": rogue.sam,
        "winlog.event_data.TargetDomainName": "NEXACORP",
        "winlog.event_data.TargetLogonId": "0xB18F2A9",
        "winlog.event_data.LogonType": "10",
        "winlog.event_data.LogonProcessName": "User32 ",
        "winlog.event_data.AuthenticationPackageName": "Negotiate",
        "winlog.event_data.WorkstationName": originHost.hostname,
        "winlog.event_data.IpAddress": originHost.ip,
        "winlog.event_data.IpPort": "58622",
        "winlog.event_data.ElevatedToken": "%%1842",
        "winlog.event_data.ProcessName": "C:\\Windows\\System32\\svchost.exe",
        "event.code": "4624",
        "event.action": "logged-in",
        "event.outcome": "success",
        "source.ip": originHost.ip,
        "user.name": rogue.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 9. The group membership takes effect — visible in the new logon's rights.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_09_new_acct_privs",
      ts: T(N + 16 * MIN),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "privileged_operation",
      hostname: adminServer.hostname,
      user_email: rogue.email,
      severity: "high",
      description:
        "The s.katz logon session was issued the privilege set that comes with the groups it was placed in, including SeDebugPrivilege and SeBackupPrivilege. This is the proof that the group additions actually took effect rather than merely being requested.",
      raw: {
        "winlog.event_id": "4672",
        "winlog.channel": "Security",
        "winlog.computer_name": adminServer.fqdn,
        "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        "winlog.record_id": "2215191",
        "winlog.event_data.SubjectUserSid": rogueSid,
        "winlog.event_data.SubjectUserName": rogue.sam,
        "winlog.event_data.SubjectDomainName": "NEXACORP",
        "winlog.event_data.SubjectLogonId": "0xB18F2A9",
        "winlog.event_data.PrivilegeList":
          "SeDebugPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeSecurityPrivilege",
        "event.code": "4672",
        "event.action": "special-privileges-assigned",
        "event.outcome": "success",
        "user.name": rogue.sam,
        "user.domain": "NEXACORP",
      },
    },

    // ---------------------------------------------------------------------
    // 10. The correlation that opened the ticket, with the directory context.
    // ---------------------------------------------------------------------
    {
      id: "evt_ra_10_siem_context",
      ts: T(N + 21 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: dc.hostname,
      user_email: admin.email,
      severity: "high",
      description:
        "Sentinel raised the alert at 23:08 and attached the lookups an analyst would otherwise run by hand: which request records mention the new account, which device the acting administrator is assigned, which hosts that administrator has logged on from recently, and who WS-ENG-2208 belongs to.",
      raw: {
        "siem.rule_name": "PrivilegedGroupAddition_RecentlyCreatedAccount",
        "siem.rule_id": "SEN-IDENT-0244",
        "siem.window_start": T(N + 4 * MIN),
        "siem.window_end": T(N + 16 * MIN),
        "siem.new_account": "NEXACORP\\s.katz",
        "siem.new_account_created_by": "NEXACORP\\t.aharoni",
        "siem.groups_added": ["NEXACORP\\Domain Admins", "SRV-ADM-07\\Administrators"],
        "siem.linked_change_request": "none",
        "siem.linked_onboarding_request": "none",
        "siem.standard_change_window": "Mon-Thu 09:00-17:00 Asia/Jerusalem",
        "siem.actor_department": "Service Desk",
        "siem.actor_assigned_device": "WS-ITS-1140",
        "siem.actor_logon_hosts_prior_30d": ["WS-ITS-1140"],
        "siem.source_host_observed": originHost.hostname,
        "siem.source_host_assigned_department": "Engineering",
        "siem.source_host_primary_user": "y.dagan@nexacorp.com",
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "user",
      value: rogue.sam,
      first_seen: T(N + 4 * MIN),
      last_seen: T(N + 21 * MIN),
      reputation: "malicious",
      tags: ["created-out-of-hours", "domain-admins"],
    },
    {
      type: "user",
      value: admin.sam,
      first_seen: T(0),
      last_seen: T(N + 21 * MIN),
      reputation: "suspicious",
      tags: ["service-desk", "acting-account"],
    },
    {
      type: "host",
      value: originHost.hostname,
      first_seen: T(N),
      last_seen: T(N + 15 * MIN),
      reputation: "suspicious",
      tags: ["engineering-workstation", "session-origin"],
    },
    {
      type: "host",
      value: adminServer.hostname,
      first_seen: T(N),
      last_seen: T(N + 21 * MIN),
      reputation: "suspicious",
      tags: ["administrative-server", "rdp-target"],
    },
    {
      type: "host",
      value: dc.hostname,
      first_seen: T(6 * MIN),
      last_seen: T(N + 7 * MIN),
      reputation: "clean",
      tags: ["domain-controller", "directory-changes"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Creating a domain user is a routine Service Desk task. What single fact turns evt_ra_05_acct_create from routine administration into an incident?",
      hint: "Compare it with evt_ra_01_ticket and evt_ra_02_baseline_create.",
      kind: "single",
      options: [
        { value: "no_ticket", label: "No onboarding or change request exists for s.katz, unlike the creation of n.peretz" },
        { value: "wrong_actor", label: "It was performed by a Service Desk administrator rather than by a domain administrator" },
        { value: "naming", label: "The name does not follow the naming convention used elsewhere in this directory" },
        { value: "wrong_host", label: "It was written on DC01 instead of on the administrative server SRV-ADM-07" },
      ],
      answer: "no_ticket",
      xp: 50,
      explanation:
        "The 4720 at 22:51 is byte-for-byte the same kind of record as the 4720 at 14:16 — same event ID, same creator, same domain controller. What separates them is entirely outside the event: the afternoon one is backed by RITM0092416, and Sentinel's lookup for the late-night one returns no linked request of any kind. Option (b) is wrong because provisioning accounts is precisely a Service Desk job. Option (c) is not supported — s.katz matches the same first-initial-dot-surname form as n.peretz. Option (d) is wrong because 4720 is always written on the domain controller that processed the change.",
    },
    {
      id: "q2",
      prompt:
        "Which pair of events, read together, shows that the same workstation drove both the administrative changes and the new account's first logon?",
      hint: "Two events share a WorkstationName and an IpAddress.",
      kind: "single",
      options: [
        { value: "both_logons", label: "evt_ra_03_admin_logon + evt_ra_08_new_acct_logon — both sessions come from WS-ENG-2208" },
        { value: "create_group", label: "evt_ra_05_acct_create + evt_ra_06_group_add_domain — both were performed against DC01" },
        { value: "control_pair", label: "evt_ra_01_ticket + evt_ra_02_baseline_create — an approved request and the account it produced" },
        { value: "privs_siem", label: "evt_ra_09_new_acct_privs + evt_ra_10_siem_context — the privileges issued and the summary" },
      ],
      answer: "both_logons",
      xp: 70,
      explanation:
        "evt_ra_03_admin_logon carries WorkstationName WS-ENG-2208 and IpAddress 10.10.44.61; evt_ra_08_new_acct_logon carries exactly the same two values for a different account fifteen minutes later. One person at one keyboard used the administrator to build the account and then used the account. That is also what pushes the case from 'a helpdesk admin did something odd' towards 'the helpdesk admin's credentials are being used by someone else' — Sentinel records that t.aharoni is assigned WS-ITS-1140 and had logged on only from that device for the previous thirty days. Pair (b) shares a host but is one actor doing two things, pair (c) is the control, and pair (d) is the aftermath and its restatement.",
    },
    {
      id: "q3",
      prompt:
        "evt_ra_04_admin_privs shows that the t.aharoni session held the rights needed for everything that followed. What does that establish?",
      kind: "single",
      options: [
        { value: "permitted_not_authorised", label: "Only that the actions were technically permitted, not that they were authorised" },
        { value: "legitimate", label: "That the actions must be legitimate, because those rights were granted deliberately" },
        { value: "escalated", label: "That the helpdesk session escalated itself to a higher privilege level during the night" },
        { value: "domain_admin", label: "That the operations were carried out by a domain administrator and not by the helpdesk" },
      ],
      answer: "permitted_not_authorised",
      xp: 60,
      explanation:
        "This is the distinction the scenario is built around. Windows enforces permission, not intention: it checks whether the token holds the right and then does the work. A Service Desk administrator legitimately holds account-management rights, so a stolen Service Desk credential produces a clean, error-free, entirely 'allowed' sequence of events. Authorisation is a business fact recorded outside the operating system — a ticket, an approval, a named requester — and it is missing here. Option (c) is contradicted by the log: no escalation event appears, the rights were already present at 22:49.",
    },
    {
      id: "q4",
      prompt:
        "Put the night's events in the order the logs actually support.",
      kind: "single",
      options: [
        { value: "correct_order", label: "Admin logon → new user created → added to Domain Admins → the new user logs in" },
        { value: "order_b", label: "New user created → admin logon → the new user logs in → added to Domain Admins" },
        { value: "order_c", label: "Added to Domain Admins → new user created → admin logon → the new user logs in" },
        { value: "order_d", label: "The new user logs in → admin logon → new user created → added to Domain Admins" },
      ],
      answer: "correct_order",
      xp: 60,
      explanation:
        "The timestamps give it directly: 22:47 the administrator's Remote Desktop session opens on SRV-ADM-07, 22:51 the 4720 creates s.katz on DC01, 22:54 the 4728 adds it to Domain Admins and 22:56 the 4732 adds it to the local Administrators group, 23:02 the 4624 shows s.katz logging on for the first time. The other orders are impossible — a group cannot take a member that does not exist yet, and an account cannot log on before it is created. Getting this sequence right is what lets you state, in the report, that the compromise of t.aharoni came first and the new account is its product, not its cause.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Out-of-Hours Account Creation — Service Desk Credentials",
    threat_actor: "Intruder operating a legitimate Service Desk administrator account",
    attack_kind: "rogue_admin_account",
    briefing:
      "Microsoft Sentinel raised a High alert at 23:08 on DC01. The domain user s.katz did not exist at 22:00 and was a member of a privileged group by 22:56. The Service Desk has no record of a request for it. Establish whether this was authorised and report what has happened since.",
    narrative: `At 14:10 an approved onboarding request, RITM0092416, reached the Service Desk queue, and six minutes later t.aharoni created the domain user n.peretz on DC01. That is the shape of a legitimate account creation at NexaCorp: a request, an approver, a named person, and a daytime timestamp. Keep it in mind, because the record written eight hours later looks exactly the same.

At 22:47 the t.aharoni account opened a Remote Desktop session on the administrative server SRV-ADM-07 — from 10.10.44.61, the address of WS-ENG-2208. WS-ENG-2208 is an Engineering workstation whose primary user is y.dagan; t.aharoni sits in the Service Desk, is assigned WS-ITS-1140, and had logged on from nothing else in the previous thirty days. Two minutes later the session was issued its usual administrative privilege set, which is why nothing that follows is ever refused.

At 22:51 that session created the domain user s.katz on DC01. At 22:54 s.katz was added to Domain Admins, and at 22:56 to the local Administrators group on SRV-ADM-07. At 23:02, eleven minutes old, s.katz logged on interactively to SRV-ADM-07 — from WS-ENG-2208 and 10.10.44.61 again, the same keyboard that had just built it — and the 4672 written a minute later shows the account collecting SeDebugPrivilege and SeBackupPrivilege, so the group memberships were live.

Every one of those operations was permitted. A Service Desk administrator is entitled to create users and manage groups, and Windows raised not a single error. What makes it an incident is what is missing and what surrounds it: Sentinel's lookups return no change request and no onboarding request for s.katz, the work happened outside the standard change window, the new account went straight into the domain's most privileged group three minutes after birth, and both sessions came from a workstation that belongs to neither of the accounts involved.

The working conclusion is that t.aharoni's credentials are being used by someone else, and that s.katz is a second way back in for when the first one is closed. The lesson for the report is the question you asked: not "was this allowed?" — it plainly was — but "who authorised it?", which nobody did.`,
    learning_objectives: [
      "Read the Windows account-lifecycle events in order: 4720 creation, 4728 global group addition, 4732 local group addition, 4624 first logon, 4672 privileges issued",
      "Treat the absence of a change or onboarding record as evidence in its own right, and know where to look for it",
      "Separate 'technically permitted' from 'authorised', and recognise that a stolen administrator credential produces a completely clean log trail",
      "Use timing — outside business hours, and minutes between creation and privileged group membership — as a supporting rather than a standalone indicator",
      "Correlate WorkstationName and IpAddress across two different accounts' logons to place them at one origin",
    ],
    // alerts are attached by the catalogue wiring
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Baseline", action: `${onboardingTicket} approved — an authorised onboarding request reaches the Service Desk` },
      { ts: T(6 * MIN), phase: "Baseline", action: "t.aharoni creates n.peretz on DC01 under that request — the control case" },
      { ts: T(N), phase: "Valid Accounts", action: "t.aharoni opens a Remote Desktop session on SRV-ADM-07 from WS-ENG-2208" },
      { ts: T(N + 4 * MIN), phase: "Persistence", action: "4720 — the domain user s.katz is created on DC01 with no linked request" },
      { ts: T(N + 7 * MIN), phase: "Persistence", action: "4728 — s.katz added to Domain Admins three minutes after creation" },
      { ts: T(N + 9 * MIN), phase: "Persistence", action: "4732 — s.katz added to the local Administrators group on SRV-ADM-07" },
      { ts: T(N + 15 * MIN), phase: "Valid Accounts", action: "s.katz logs on to SRV-ADM-07 from WS-ENG-2208 — the same origin as the admin session" },
      { ts: T(N + 16 * MIN), phase: "Valid Accounts", action: "4672 — the new account is issued SeDebugPrivilege and SeBackupPrivilege" },
      { ts: T(N + 21 * MIN), phase: "Detection", action: "Sentinel correlates the creation and the group addition and raises the alert" },
    ],
    questions,
  };
}
