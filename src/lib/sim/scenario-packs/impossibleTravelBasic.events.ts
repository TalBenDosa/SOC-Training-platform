/**
 * Events-only half of the ./impossibleTravelBasic.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./impossibleTravelBasic.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

/** Telemetry half of `buildImpossibleTravelBasicScenario`: the events and the story title, no answer key. */
export function impossibleTravelBasicScenarioEvents() {
  const B = new Date("2026-06-11T06:12:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = {
    email: "d.harel@nexacorp.com",
    display: "Dana Harel",
    userId: "3c9e71a8-4d20-4b6f-9a13-6e85f0c2d417",
    hostname: "LT-FIN-3390",
    corpIp: "10.10.62.114",
    homeIp: "86.150.23.44",
    deviceId: "6b41f0d9-2ea7-4c85-b310-97ff5c2a4e68",
  };

  // The corporate remote-access gateway's public address. Anything sourced from
  // the corporate VPN leaves the internet-facing world looking like this.
  const vpnGatewayPublicIp = "194.90.7.20";
  const vpnAssignedIp = "10.99.14.62";

  const attackerIp = "146.190.62.117";
  const phishDomain = "nexacorp-signin-verify.com";
  const phishIp = "91.229.23.86";
  const dropAddress = "ap-archive.2026@securemaildrop.net";
  const vendorAddress = "accounts@ridgeline-supply.com";

  // Every action taken from the foreign address shares one session identifier.
  const hostileSession = "a4f8c1d2-7b93-4e15-8c60-3d29f7a1b504";

  const corpUserAgent =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0";
  const hostileUserAgent =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0";

  // EDR↔scenario integration (Phase 4): control-plane-only incident — a phished
  // token replayed as an impossible-travel Entra sign-in, with no host EDR events
  // and no process to walk. edr_scope "non_edr": nothing to investigate in the EDR
  // console. No is_detection (no EDR detections); edr_scope goes on the identity
  // detection that opens the ticket — the SIEM impossible-travel correlation.
  const INCIDENT = "inc:itb:1";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. BASELINE — what a normal morning looks like for this account.
    //    Everything the foreign sign-in is later compared against is here.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_01_morning_signin",
      ts: T(0),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      user_email: victim.email,
      user_title: "Accounts Payable Clerk",
      hostname: victim.hostname,
      src_ip: victim.homeIp,
      severity: "informational",
      geo: { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 },
      authentication: { method: "Password", mfa_type: "Mobile app notification", result: "success" },
      description:
        "Dana Harel signed in to Exchange Online at 06:12 from her home address in London on the corporate laptop LT-FIN-3390, MFA completed by Authenticator push.",
      raw: {
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.resultType": "0",
        "azure.signinlogs.resultDescription": "",
        "azure.signinlogs.properties.id": "7c1e9a34-5d80-4b62-9f17-3a06c8e42d59",
        "azure.signinlogs.properties.userPrincipalName": victim.email,
        "azure.signinlogs.properties.userDisplayName": victim.display,
        "azure.signinlogs.properties.userId": victim.userId,
        "azure.signinlogs.properties.appDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.appId": "00000002-0000-0ff1-ce00-000000000000",
        "azure.signinlogs.properties.resourceDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.ipAddress": victim.homeIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 5378,
        "azure.signinlogs.properties.location.city": "London",
        "azure.signinlogs.properties.location.state": "England",
        "azure.signinlogs.properties.location.countryOrRegion": "GB",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 51.5074,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": -0.1278,
        "azure.signinlogs.properties.userAgent": corpUserAgent,
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationMethod: "Password",
            authenticationStepResultDetail: "Correct password",
            succeeded: true,
          },
          {
            authenticationMethod: "Mobile app notification",
            authenticationStepResultDetail: "MFA completed in Azure AD",
            succeeded: true,
          },
        ],
        "azure.signinlogs.properties.incomingTokenType": "none",
        "azure.signinlogs.properties.deviceDetail.deviceId": victim.deviceId,
        "azure.signinlogs.properties.deviceDetail.displayName": victim.hostname,
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 11",
        "azure.signinlogs.properties.deviceDetail.browser": "Edge 124.0.0",
        "azure.signinlogs.properties.deviceDetail.isCompliant": true,
        "azure.signinlogs.properties.deviceDetail.isManaged": true,
        "azure.signinlogs.properties.deviceDetail.trustType": "Azure AD joined",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.riskEventTypes_v2": [],
        "azure.signinlogs.properties.sessionId": "1f0b7c56-92da-4f37-9b48-05c8ad631e72",
        "azure.signinlogs.properties.correlationId": "e7a3d915-6c40-4b02-8f71-2ad5906cb114",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The corporate VPN session — the innocent explanation, made testable.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_02_vpn_connect",
      ts: T(6 * MIN),
      source: "vpn",
      vendor: "Cisco AnyConnect",
      event_type: "vpn_login",
      user_email: victim.email,
      hostname: victim.hostname,
      src_ip: victim.homeIp,
      severity: "informational",
      description:
        "d.harel connected to the corporate remote-access VPN from 86.150.23.44 and was assigned 10.99.14.62. The gateway VPN-GW-01 egresses from the public address 194.90.7.20.",
      raw: {
        "event.action": "vpn-session-established",
        "cisco.asa.message_id": "722022",
        "cisco.asa.username": "d.harel",
        "cisco.asa.tunnel_group": "NEXACORP-RA-VPN",
        "cisco.asa.group_policy": "GP-NEXACORP-STAFF",
        "cisco.asa.session_type": "SSL",
        "cisco.asa.public_ip": victim.homeIp,
        "cisco.asa.assigned_ip": vpnAssignedIp,
        "cisco.asa.client_version": "Cisco Secure Client 5.1.2.42",
        "cisco.asa.client_os": "Windows 11 Enterprise 23H2",
        "cisco.asa.session_id": "884213",
        "observer.name": "VPN-GW-01",
        "observer.ip": vpnGatewayPublicIp,
        "observer.egress.interface.name": "outside",
        "source.geo.country_iso_code": "GB",
        "source.geo.city_name": "London",
        "event.outcome": "success",
      },
    },

    // ---------------------------------------------------------------------
    // 3. The lure. Delivered, not blocked.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_03_phish_email",
      ts: T(74 * MIN),
      source: "email_gateway",
      vendor: "Microsoft Defender for Office 365",
      event_type: "email_received",
      user_email: victim.email,
      src_ip: "45.87.154.209",
      severity: "medium",
      mitre_technique: "T1566.002",
      mitre_tactic: "Initial Access",
      network: { domain: phishDomain },
      description:
        "External mail to d.harel linking to nexacorp-signin-verify.com was delivered to the inbox. SPF and DMARC both fail; the display name reads \"NexaCorp Service Desk\".",
      raw: {
        "email.from.address": "no-reply@nexacorp-signin-verify.com",
        "email.from.display_name": "NexaCorp Service Desk",
        "email.to.address": victim.email,
        "email.subject": "Action required: re-verify your NexaCorp sign-in session",
        "email.direction": "inbound",
        "email.message_id": "<9f1c2ad4-5e80-4b13-b7a6-2c04e1f5a930@nexacorp-signin-verify.com>",
        "email.url": `https://${phishDomain}/auth/session-check`,
        "email.url_domain": phishDomain,
        "email.spf": "fail",
        "email.dkim": "none",
        "email.dmarc": "fail",
        "source.ip": "45.87.154.209",
        "o365.DeliveryAction": "Delivered",
        "o365.DeliveryLocation": "Inbox",
        "o365.ThreatTypes": "Phish",
        "o365.DetectionMethods": "None",
      },
    },

    // ---------------------------------------------------------------------
    // 4. She visits the page and submits. This is where the session is lost.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_04_phish_post",
      ts: T(79 * MIN),
      source: "proxy",
      vendor: "Zscaler Internet Access",
      event_type: "http_request",
      user_email: victim.email,
      hostname: victim.hostname,
      src_ip: victim.corpIp,
      dst_ip: phishIp,
      dst_port: 443,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1539",
      mitre_tactic: "Credential Access",
      network: {
        url: `https://${phishDomain}/auth/session-check`,
        domain: phishDomain,
        method: "POST",
        status: 302,
        bytes_out: 2418,
        bytes_in: 1104,
        user_agent: corpUserAgent,
      },
      description:
        "LT-FIN-3390 POSTed 2,418 bytes of form data to nexacorp-signin-verify.com/auth/session-check and received a 302. Zscaler categorised the host as newly registered and allowed it.",
      raw: {
        "zscaler.action": "Allowed",
        "zscaler.reason": "Allowed",
        "zscaler.urlcategory": "Newly Registered and Observed Domains",
        "zscaler.urlsupercategory": "Miscellaneous or Unknown",
        "zscaler.appname": "General Browsing",
        "zscaler.appclass": "General Browsing",
        "zscaler.threatname": "None",
        "zscaler.malwarecategory": "None",
        "zscaler.department": "Finance",
        "zscaler.location": "LON-HQ",
        "zscaler.login": victim.email,
        "zscaler.url": `https://${phishDomain}/auth/session-check`,
        "zscaler.hostname": phishDomain,
        "zscaler.cip": victim.corpIp,
        "zscaler.sip": phishIp,
        "zscaler.reqmethod": "POST",
        "zscaler.respcode": 302,
        "zscaler.reqsize": 2418,
        "zscaler.respsize": 1104,
        "zscaler.useragent": corpUserAgent,
        "zscaler.serverip": phishIp,
      },
    },

    // ---------------------------------------------------------------------
    // 5. The VPN session ENDS — 47 minutes before the foreign sign-in.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_05_vpn_disconnect",
      ts: T(88 * MIN),
      source: "vpn",
      vendor: "Cisco AnyConnect",
      event_type: "vpn_logout",
      user_email: victim.email,
      hostname: victim.hostname,
      src_ip: victim.homeIp,
      severity: "informational",
      description:
        "The d.harel VPN session on VPN-GW-01 was torn down at 07:40 after 1h 22m, reason \"User Requested\". No further remote-access session was opened for this account.",
      raw: {
        "event.action": "vpn-session-terminated",
        "cisco.asa.message_id": "113019",
        "cisco.asa.username": "d.harel",
        "cisco.asa.tunnel_group": "NEXACORP-RA-VPN",
        "cisco.asa.session_id": "884213",
        "cisco.asa.public_ip": victim.homeIp,
        "cisco.asa.assigned_ip": vpnAssignedIp,
        "cisco.asa.duration": "1h:22m:11s",
        "cisco.asa.bytes_xmt": "18441920",
        "cisco.asa.bytes_rcv": "94217216",
        "cisco.asa.reason": "User Requested",
        "observer.name": "VPN-GW-01",
        "observer.ip": vpnGatewayPublicIp,
        "event.outcome": "success",
      },
    },

    // ---------------------------------------------------------------------
    // 6. THE FOREIGN SIGN-IN. Succeeds. Different everything.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_06_foreign_signin",
      ts: T(135 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      user_email: victim.email,
      user_title: "Accounts Payable Clerk",
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078.004",
      mitre_tactic: "Initial Access",
      geo: { country: "United States", city: "New York", latitude: 40.7128, longitude: -74.006 },
      authentication: { method: "Previously satisfied", result: "success" },
      description:
        "The same account signed in successfully to Exchange Online at 08:27 from 146.190.62.117 in New York, on AutonomousSystemNumber 14061.",
      raw: {
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.resultType": "0",
        "azure.signinlogs.resultDescription": "",
        "azure.signinlogs.properties.id": "94a7c1e2-3f68-4b09-8d5a-6c40e18f27b3",
        "azure.signinlogs.properties.userPrincipalName": victim.email,
        "azure.signinlogs.properties.userDisplayName": victim.display,
        "azure.signinlogs.properties.userId": victim.userId,
        "azure.signinlogs.properties.appDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.appId": "00000002-0000-0ff1-ce00-000000000000",
        "azure.signinlogs.properties.resourceDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.ipAddress": attackerIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 14061,
        "azure.signinlogs.properties.location.city": "New York",
        "azure.signinlogs.properties.location.state": "New York",
        "azure.signinlogs.properties.location.countryOrRegion": "US",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 40.7128,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": -74.006,
        "azure.signinlogs.properties.networkLocationDetails.networkType": "",
        "azure.signinlogs.properties.userAgent": hostileUserAgent,
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationMethod: "Previously satisfied",
            authenticationStepResultDetail: "MFA requirement satisfied by claim in the token",
            succeeded: true,
          },
        ],
        "azure.signinlogs.properties.incomingTokenType": "primaryRefreshToken",
        "azure.signinlogs.properties.deviceDetail.deviceId": "",
        "azure.signinlogs.properties.deviceDetail.displayName": "",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "MacOs",
        "azure.signinlogs.properties.deviceDetail.browser": "Firefox 126.0",
        "azure.signinlogs.properties.deviceDetail.isCompliant": false,
        "azure.signinlogs.properties.deviceDetail.isManaged": false,
        "azure.signinlogs.properties.deviceDetail.trustType": "",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "high",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.riskState": "atRisk",
        "azure.signinlogs.properties.riskEventTypes_v2": ["unfamiliarFeatures", "unlikelyTravel"],
        "azure.signinlogs.properties.sessionId": hostileSession,
        "azure.signinlogs.properties.correlationId": "b58c2f47-0e91-4a6d-89b2-73f1c0d4a825",
      },
    },

    // ---------------------------------------------------------------------
    // 7. THE ALARM — the correlation rule. Geography only. This is the ticket.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_07_travel_alert",
      ts: T(137 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078.004",
      mitre_tactic: "Initial Access",
      edr_scope: "non_edr", // primary identity detection that opens the ticket; control-plane only, no EDR to pivot to
      description:
        "Sentinel joined the 06:12 and 08:27 sign-ins for d.harel and raised an impossible-travel anomaly: 5,570 km in 135 minutes, implied speed 2,476 km/h — no commercial flight plus airport time covers London to New York in that window.",
      raw: {
        "AlertName": "Impossible travel to an atypical location",
        "alert.rule.id": "SEN-IDN-0114",
        "AlertSeverity": "High",
        "target.user.email": victim.email,
        "source.ip": attackerIp,
        "ExtendedProperties.Prior Sign-in Time": T(0),
        "ExtendedProperties.Prior Sign-in IP": victim.homeIp,
        "ExtendedProperties.Prior Sign-in Location": "London, GB",
        "ExtendedProperties.Current Sign-in Time": T(135 * MIN),
        "ExtendedProperties.Current Sign-in Location": "New York, US",
        "ExtendedProperties.Distance (km)": 5570,
        "ExtendedProperties.Elapsed Minutes": 135,
        "ExtendedProperties.Implied Speed (km/h)": 2476,
        "ExtendedProperties.Linked Sign-in IDs": ["evt_itb_01_morning_signin", "evt_itb_06_foreign_signin"],
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },

    // ---------------------------------------------------------------------
    // 8. The foreign session creates a hiding rule in the mailbox.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_08_inbox_rule",
      ts: T(141 * MIN),
      source: "o365",
      vendor: "Microsoft 365 Unified Audit Log",
      event_type: "account_modify",
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1114.003",
      mitre_tactic: "Collection",
      description:
        "An inbox rule named \"AP sync\" was created on the d.harel mailbox from 146.190.62.117: mail matching payment keywords is forwarded to an external address and the originals moved to RSS Subscriptions.",
      raw: {
        "data.office365.Operation": "New-InboxRule",
        "data.office365.Workload": "Exchange",
        "data.office365.RecordType": "1",
        "data.office365.UserId": victim.email,
        "data.office365.UserType": "Regular",
        "data.office365.ObjectId": "nexacorp.com/Users/Dana Harel/AP sync",
        "data.office365.ClientIPAddress": attackerIp,
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "data.office365.SessionId": hostileSession,
        "data.office365.ExternalAccess": "false",
        "data.office365.Parameters.Name": "AP sync",
        "data.office365.Parameters.SubjectOrBodyContainsWords":
          "invoice;remittance;bank details;IBAN;payment",
        "data.office365.Parameters.ForwardAsAttachmentTo": dropAddress,
        "data.office365.Parameters.MoveToFolder": "RSS Subscriptions",
        "data.office365.Parameters.MarkAsRead": "True",
        "data.office365.Parameters.StopProcessingRules": "True",
        "data.office365.ResultStatus": "True",
      },
    },

    // ---------------------------------------------------------------------
    // 9. Bulk mailbox reading from the same session.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_09_mail_access",
      ts: T(149 * MIN),
      source: "o365",
      vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_storage_access",
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1114.002",
      mitre_tactic: "Collection",
      description:
        "Exchange recorded a MailItemsAccessed sync of 812 items from the Vendor Banking folder in the d.harel mailbox, from 146.190.62.117.",
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.Workload": "Exchange",
        "data.office365.RecordType": "50",
        "data.office365.UserId": victim.email,
        "data.office365.MailboxOwnerUPN": victim.email,
        "data.office365.LogonType": "Owner",
        "data.office365.ClientIPAddress": attackerIp,
        "data.office365.ClientInfoString": "Client=REST;Client=RESTSystem;;",
        "data.office365.SessionId": hostileSession,
        "data.office365.OperationCount": "812",
        "data.office365.OperationProperties.MailAccessType": "Sync",
        "data.office365.OperationProperties.IsThrottled": "False",
        "data.office365.Folders.Path": "\\Inbox\\Accounts Payable\\Vendor Banking",
        "data.office365.AppId": "00000002-0000-0ff1-ce00-000000000000",
        "data.office365.ResultStatus": "Succeeded",
      },
    },

    // ---------------------------------------------------------------------
    // 10. The point of the whole exercise, from the attacker's side.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_10_vendor_mail",
      ts: T(160 * MIN),
      source: "o365",
      vendor: "Microsoft 365 Unified Audit Log",
      event_type: "email_sent",
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "critical",
      description:
        "A message with the subject \"Updated remittance details — June invoices\" and a PDF attached was sent from the d.harel mailbox to accounts@ridgeline-supply.com from 146.190.62.117.",
      raw: {
        "data.office365.Operation": "Send",
        "data.office365.Workload": "Exchange",
        "data.office365.RecordType": "2",
        "data.office365.UserId": victim.email,
        "data.office365.MailboxOwnerUPN": victim.email,
        "data.office365.LogonType": "Owner",
        "data.office365.ClientIPAddress": attackerIp,
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "data.office365.SessionId": hostileSession,
        "data.office365.Item.Subject": "Updated remittance details — June invoices",
        "data.office365.Item.ParentFolder.Path": "\\Drafts",
        "email.from.address": victim.email,
        "email.to.address": vendorAddress,
        "email.direction": "outbound",
        "email.attachments.count": "1",
        "email.attachment.name": "Remittance_Update_June.pdf",
        "data.office365.ResultStatus": "Succeeded",
      },
    },
  ];

  // Every event belongs to the one impossible-travel account-takeover incident
  // (correlation key; also lets the EDR console associate the identity-plane case).
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Impossible Travel — Accounts Payable Mailbox", events, T, MIN, victim, attackerIp, phishDomain, phishIp, dropAddress };
}
