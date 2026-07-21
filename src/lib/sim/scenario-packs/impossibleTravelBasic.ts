/**
 * Scenario pack: "Impossible Travel — Accounts Payable Mailbox"
 *
 * A REAL account takeover, told at beginner reading level.
 *
 * A finance user signs in normally from her usual city in the morning. Two and
 * a quarter hours later the same account signs in successfully from another
 * country, and the identity correlation rule fires on the geography.
 *
 * "Impossible travel" is only a HYPOTHESIS at that point. The two failure modes
 * a beginner falls into are closing it as "probably a VPN" and escalating on the
 * map alone. Neither is analysis. The telemetry contains the fields that settle
 * it, and the student has to go and read them:
 *
 *   - the corporate VPN session is logged, and it ENDED 47 minutes before the
 *     foreign sign-in — so "she was on the VPN" is testable, and it fails;
 *   - the foreign sign-in carries a different device (no deviceId, unmanaged,
 *     non-compliant, different OS and browser) and a hosting-provider ASN
 *     rather than her consumer ISP or the VPN gateway's address;
 *   - MFA is recorded as "satisfied", but by a claim inside the token rather
 *     than by the Authenticator push she completes every other morning;
 *   - and the foreign session then does things this mailbox has never done.
 *
 * Registry note: register in scenarios.ts with difficulty "beginner"
 * (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildImpossibleTravelBasicScenario(
  scenarioId = "impossible-travel-basic-2026",
): ScenarioBundle {
  const B = new Date("2026-06-11T06:12:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = {
    email: "d.harel@nexacorp.com",
    display: "Dana Harel",
    userId: "3c9e71a8-4d20-4b6f-9a13-6e85f0c2d417",
    hostname: "LT-FIN-3390",
    corpIp: "10.10.62.114",
    homeIp: "82.166.44.19",
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
      geo: { country: "IL", city: "Tel Aviv", latitude: 32.0853, longitude: 34.7818 },
      authentication: { method: "Password", mfa_type: "Mobile app notification", result: "success" },
      description:
        "Dana Harel signed in to Exchange Online at 06:12 from her usual home address in Tel Aviv, on her corporate laptop LT-FIN-3390. This is the record every later sign-in on this account has to be compared against — note the device, the network and how MFA was completed.",
      raw: {
        OperationName: "Sign-in activity",
        Category: "SignInLogs",
        ResultType: "0",
        ResultDescription: "",
        UserPrincipalName: victim.email,
        UserDisplayName: victim.display,
        UserId: victim.userId,
        AppDisplayName: "Office 365 Exchange Online",
        AppId: "00000002-0000-0ff1-ce00-000000000000",
        ResourceDisplayName: "Office 365 Exchange Online",
        ClientAppUsed: "Browser",
        IPAddress: victim.homeIp,
        AutonomousSystemNumber: 12400,
        "LocationDetails.city": "Tel Aviv",
        "LocationDetails.state": "Tel Aviv",
        "LocationDetails.countryOrRegion": "IL",
        UserAgent: corpUserAgent,
        ConditionalAccessStatus: "success",
        AuthenticationRequirement: "multiFactorAuthentication",
        AuthenticationDetails: [
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
        IncomingTokenType: "none",
        "DeviceDetail.deviceId": victim.deviceId,
        "DeviceDetail.displayName": victim.hostname,
        "DeviceDetail.operatingSystem": "Windows 11",
        "DeviceDetail.browser": "Edge 124.0.0",
        "DeviceDetail.isCompliant": true,
        "DeviceDetail.isManaged": true,
        "DeviceDetail.trustType": "Azure AD joined",
        RiskLevelDuringSignIn: "none",
        RiskState: "none",
        RiskEventTypes_V2: [],
        SessionId: "1f0b7c56-92da-4f37-9b48-05c8ad631e72",
        CorrelationId: "e7a3d915-6c40-4b02-8f71-2ad5906cb114",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The corporate VPN session — the innocent explanation, made testable.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_02_vpn_connect",
      ts: T(6 * MIN),
      source: "vpn",
      vendor: "Cisco ASA",
      event_type: "vpn_login",
      user_email: victim.email,
      hostname: victim.hostname,
      src_ip: victim.homeIp,
      severity: "informational",
      description:
        "d.harel connected to the corporate remote-access VPN from 82.166.44.19 and was given the internal address 10.99.14.62. Traffic that leaves the company through this gateway reaches the internet from the gateway's own public address, 194.90.7.20 — worth remembering when a later sign-in has to be attributed to a network.",
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
        "source.geo.country_iso_code": "IL",
        "source.geo.city_name": "Tel Aviv",
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
      mitre_tactic: "TA0001",
      network: { domain: phishDomain },
      description:
        "An external email reached d.harel claiming her sign-in session needed re-verification, with a link to nexacorp-signin-verify.com. The sending domain fails SPF and DMARC, and the display name imitates the internal service desk. The message was delivered to the inbox, not quarantined.",
      raw: {
        "event.action": "EmailDelivered",
        "event.outcome": "success",
        "email.from.address": "no-reply@nexacorp-signin-verify.com",
        "email.from.display_name": "NexaCorp Service Desk",
        "email.to.address": victim.email,
        "email.subject": "Action required: re-verify your NexaCorp sign-in session",
        "email.direction": "inbound",
        "email.message_id": "<9f1c2ad4-5e80-4b13-b7a6-2c04e1f5a930@nexacorp-signin-verify.com>",
        "url.original": `https://${phishDomain}/auth/session-check`,
        "url.domain": phishDomain,
        "spf.result": "fail",
        "dkim.result": "none",
        "dmarc.result": "fail",
        "source.ip": "45.87.154.209",
        "o365.DeliveryAction": "Delivered",
        "o365.DeliveryLocation": "Inbox",
        "o365.ThreatTypes": "Phish",
        "o365.DetectionMethods": "None",
        action_result: "delivered",
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
      mitre_tactic: "TA0006",
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
        "LT-FIN-3390 loaded the linked page and then sent a POST containing form data to it. The proxy categorised the destination as a newly registered and observed domain and allowed the request — the category is a description of the site's age, not a safety verdict.",
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
        "zscaler.location": "TLV-HQ",
        "zscaler.login": victim.email,
        "url.full": `https://${phishDomain}/auth/session-check`,
        "url.domain": phishDomain,
        "url.path": "/auth/session-check",
        "http.request.method": "POST",
        "http.request.referrer": `https://${phishDomain}/auth/session-check`,
        "http.response.status_code": "302",
        "http.request.bytes": "2418",
        "http.response.bytes": "1104",
        "user_agent.original": corpUserAgent,
        "source.ip": victim.corpIp,
        "destination.ip": phishIp,
        "destination.port": "443",
        "tls.server.ja3s": "e35df3e00ca4ef31d42b34bebaa2f86e",
        "tls.server.issuer": "CN=R11, O=Let's Encrypt, C=US",
        "tls.server.subject": `CN=${phishDomain}`,
        "tls.server_certificate.not_before": "2026-06-05",
        action_result: "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 5. The VPN session ENDS — 47 minutes before the foreign sign-in.
    // ---------------------------------------------------------------------
    {
      id: "evt_itb_05_vpn_disconnect",
      ts: T(88 * MIN),
      source: "vpn",
      vendor: "Cisco ASA",
      event_type: "vpn_logout",
      user_email: victim.email,
      hostname: victim.hostname,
      src_ip: victim.homeIp,
      severity: "informational",
      description:
        "The d.harel VPN session on VPN-GW-01 was torn down at 07:40 after 1 hour 22 minutes, at the client's request. No further remote-access session was opened for this account. Anything this account does after 07:40 did not come through the corporate gateway.",
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
      mitre_tactic: "TA0001",
      geo: { country: "NL", city: "Amsterdam", latitude: 52.3702, longitude: 4.8952 },
      authentication: { method: "Previously satisfied", result: "success" },
      description:
        "The same account signed in successfully to Exchange Online at 08:27 from 146.190.62.117 in Amsterdam. Read the DeviceDetail block, the AutonomousSystemNumber and the AuthenticationDetails entry closely and compare each of them with the 06:12 record.",
      raw: {
        OperationName: "Sign-in activity",
        Category: "SignInLogs",
        ResultType: "0",
        ResultDescription: "",
        UserPrincipalName: victim.email,
        UserDisplayName: victim.display,
        UserId: victim.userId,
        AppDisplayName: "Office 365 Exchange Online",
        AppId: "00000002-0000-0ff1-ce00-000000000000",
        ResourceDisplayName: "Office 365 Exchange Online",
        ClientAppUsed: "Browser",
        IPAddress: attackerIp,
        AutonomousSystemNumber: 14061,
        "LocationDetails.city": "Amsterdam",
        "LocationDetails.state": "North Holland",
        "LocationDetails.countryOrRegion": "NL",
        "NetworkLocationDetails.networkType": "",
        UserAgent: hostileUserAgent,
        ConditionalAccessStatus: "success",
        AuthenticationRequirement: "multiFactorAuthentication",
        AuthenticationDetails: [
          {
            authenticationMethod: "Previously satisfied",
            authenticationStepResultDetail: "MFA requirement satisfied by claim in the token",
            succeeded: true,
          },
        ],
        IncomingTokenType: "primaryRefreshToken",
        "DeviceDetail.deviceId": "",
        "DeviceDetail.displayName": "",
        "DeviceDetail.operatingSystem": "MacOs",
        "DeviceDetail.browser": "Firefox 126.0",
        "DeviceDetail.isCompliant": false,
        "DeviceDetail.isManaged": false,
        "DeviceDetail.trustType": "",
        RiskLevelDuringSignIn: "high",
        RiskState: "atRisk",
        RiskEventTypes_V2: ["unfamiliarFeatures", "unlikelyTravel"],
        SessionId: hostileSession,
        CorrelationId: "b58c2f47-0e91-4a6d-89b2-73f1c0d4a825",
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
      mitre_tactic: "TA0001",
      description:
        "Sentinel joined the 06:12 and 08:27 sign-ins for d.harel and raised an impossible-travel anomaly. The rule compares two locations and a clock and nothing else — it does not know whether a VPN, a proxy or a stolen session is responsible.",
      raw: {
        "siem.rule_name": "Impossible travel to an atypical location",
        "siem.rule_id": "SEN-IDN-0114",
        "siem.alert_severity": "High",
        "siem.entity_account": victim.email,
        "siem.prior_signin_time": T(0),
        "siem.prior_signin_ip": victim.homeIp,
        "siem.prior_signin_location": "Tel Aviv, IL",
        "siem.current_signin_time": T(135 * MIN),
        "siem.current_signin_ip": attackerIp,
        "siem.current_signin_location": "Amsterdam, NL",
        "siem.distance_km": 3290,
        "siem.elapsed_minutes": 135,
        "siem.implied_speed_kmh": 1462,
        "siem.linked_signin_ids": ["evt_itb_01_morning_signin", "evt_itb_06_foreign_signin"],
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
      mitre_tactic: "TA0009",
      description:
        "A new inbox rule named \"AP sync\" was created on the d.harel mailbox from 146.190.62.117. It copies mail matching payment keywords to an outside address and moves the originals into RSS Subscriptions, a folder nobody opens. The SessionId on this record is the one to check.",
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
      mitre_tactic: "TA0009",
      description:
        "Exchange recorded a bulk read of the Vendor Banking folder in the d.harel mailbox from the Amsterdam address — 812 items in a single sync, from the same session that created the rule. Dana's own client syncs a handful of new items at a time.",
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
        "A message went out from the d.harel mailbox to a supplier contact at ridgeline-supply.com asking that June remittances be paid to new bank details. It was sent from 146.190.62.117 in the same session as the rule and the bulk read, and a copy does not appear in Sent Items.",
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

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp,
      first_seen: T(135 * MIN),
      last_seen: T(160 * MIN),
      reputation: "malicious",
      tags: ["hosting-provider", "asn-14061", "amsterdam"],
    },
    {
      type: "domain",
      value: phishDomain,
      first_seen: T(74 * MIN),
      last_seen: T(79 * MIN),
      reputation: "malicious",
      tags: ["credential-harvesting", "newly-registered", "lookalike"],
    },
    {
      type: "ip",
      value: phishIp,
      first_seen: T(79 * MIN),
      last_seen: T(79 * MIN),
      reputation: "malicious",
      tags: ["phishing-host"],
    },
    {
      type: "email",
      value: dropAddress,
      first_seen: T(141 * MIN),
      last_seen: T(141 * MIN),
      reputation: "malicious",
      tags: ["forwarding-target", "external"],
    },
    {
      type: "user",
      value: victim.email,
      first_seen: T(0),
      last_seen: T(160 * MIN),
      reputation: "suspicious",
      tags: ["compromised-account", "accounts-payable"],
    },
    {
      type: "ip",
      value: victim.homeIp,
      first_seen: T(0),
      last_seen: T(88 * MIN),
      reputation: "clean",
      tags: ["home-isp", "asn-12400", "user-baseline"],
    },
    {
      type: "host",
      value: victim.hostname,
      first_seen: T(0),
      last_seen: T(79 * MIN),
      reputation: "clean",
      tags: ["corporate-laptop", "entra-joined"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Your team lead says \"she's probably just on the company VPN.\" Which PAIR of events lets you test that claim and rule it out?",
      hint: "One event tells you when the VPN session ended; the other tells you where the 08:27 sign-in actually came from.",
      kind: "single",
      options: [
        {
          value: "vpnend_foreign",
          label:
            "evt_itb_05_vpn_disconnect + evt_itb_06_foreign_signin — session closed at 07:40, and 08:27 came from a different address",
        },
        {
          value: "morning_vpnstart",
          label:
            "evt_itb_01_morning_signin + evt_itb_02_vpn_connect — she signed in from home and then opened a VPN tunnel",
        },
        {
          value: "phish_post",
          label:
            "evt_itb_03_phish_email + evt_itb_04_phish_post — a lure arrived and the linked page received a form submission",
        },
        {
          value: "alert_rule",
          label:
            "evt_itb_07_travel_alert + evt_itb_08_inbox_rule — the travel anomaly fired and a mailbox rule was then created",
        },
      ],
      answer: "vpnend_foreign",
      xp: 50,
      explanation:
        "\"Probably a VPN\" is a claim you can check, and checking it is the job. The gateway log shows the d.harel tunnel torn down at 07:40 with no later session, so at 08:27 there was nothing to be on. And traffic that does leave through that gateway appears on the internet as 194.90.7.20, whereas the 08:27 sign-in came from 146.190.62.117 on AutonomousSystemNumber 14061 — a hosting provider, not the corporate gateway and not her ISP's 12400. Pair (b) is the ordinary baseline. Pair (c) matters for how the account was taken, not for the VPN question. Pair (d) is the alarm plus a consequence of the compromise.",
    },
    {
      id: "q2",
      prompt:
        "Both sign-ins record AuthenticationRequirement as multiFactorAuthentication. What is actually different between them?",
      kind: "single",
      options: [
        {
          value: "token_claim",
          label:
            "At 06:12 an Authenticator push was answered; at 08:27 MFA was satisfied by a claim already inside the token",
        },
        {
          value: "ca_status",
          label:
            "ConditionalAccessStatus reads success in the morning and notApplied on the foreign sign-in record",
        },
        {
          value: "app_used",
          label:
            "The morning sign-in targeted Exchange Online while the foreign one targeted a different application",
        },
        {
          value: "result_type",
          label:
            "The morning sign-in returned ResultType 0 and the foreign sign-in returned a non-zero failure code",
        },
      ],
      answer: "token_claim",
      xp: 60,
      explanation:
        "The AuthenticationDetails block is where the difference lives. In the morning there are two steps: a correct password, then \"Mobile app notification — MFA completed in Azure AD\". Dana physically approved something. At 08:27 there is one step: \"Previously satisfied — MFA requirement satisfied by claim in the token\", with IncomingTokenType primaryRefreshToken. Nobody was challenged, because whoever signed in already held a token that says MFA happened. Options (b), (c) and (d) all describe fields you can read directly in the two records, and in each case the two records agree — ConditionalAccessStatus is success on both, both target Office 365 Exchange Online, and both returned ResultType 0.",
    },
    {
      id: "q3",
      prompt:
        "Which detail in evt_itb_06_foreign_signin most strongly argues the 08:27 session is NOT Dana's laptop with a VPN app running on it?",
      kind: "single",
      options: [
        {
          value: "device_block",
          label:
            "DeviceDetail carries an empty deviceId with isManaged and isCompliant both false, on MacOs and Firefox",
        },
        {
          value: "geo_city",
          label:
            "LocationDetails places the sign-in in Amsterdam rather than in the Tel Aviv area she normally works from",
        },
        {
          value: "risk_level",
          label:
            "RiskLevelDuringSignIn is high and RiskState is atRisk, which Entra sets automatically on the record",
        },
        {
          value: "app_display",
          label:
            "AppDisplayName is Office 365 Exchange Online, an application she does not normally sign in to",
        },
      ],
      answer: "device_block",
      xp: 60,
      explanation:
        "A VPN client changes where a device appears on the network. It does not erase the device. Her laptop is Entra-joined and Intune-managed, so its records carry deviceId 6b41f0d9-2ea7-4c85-b310-97ff5c2a4e68, displayName LT-FIN-3390, Windows 11, Edge, isCompliant true. The 08:27 record has an empty deviceId, isManaged false, isCompliant false, MacOs and Firefox. That is a different machine, and no VPN does that. Option (b) is the alert you already have, which is exactly what you are trying to explain. Option (c) is Entra's own opinion, not independent evidence. Option (d) is wrong on the facts — the 06:12 record targets the same application.",
    },
    {
      id: "q4",
      prompt:
        "Which single finding turns \"an odd sign-in location\" into a confirmed account takeover you should escalate?",
      hint: "Compare the SessionId on the post-sign-in activity with the SessionId on the foreign sign-in.",
      kind: "single",
      options: [
        {
          value: "session_actions",
          label:
            "A hiding forward rule, an 812-item folder read and a supplier payment email, all in the foreign session",
        },
        {
          value: "distance",
          label:
            "Sentinel computed 3,290 km in 135 minutes, an implied travel speed no commercial aircraft achieves",
        },
        {
          value: "phish_delivered",
          label:
            "A phishing message reached the inbox because the gateway recorded DetectionMethods as None",
        },
        {
          value: "asn_hosting",
          label:
            "The sign-in address belongs to a hosting provider rather than to a home or corporate network",
        },
      ],
      answer: "session_actions",
      xp: 70,
      explanation:
        "SessionId a4f8c1d2-7b93-4e15-8c60-3d29f7a1b504 appears on the 08:27 sign-in and then on all three follow-on actions: a rule that forwards payment mail to ap-archive.2026@securemaildrop.net and buries the originals in RSS Subscriptions, a Sync read of 812 items from the Vendor Banking folder, and an outbound message to ridgeline-supply.com changing remittance details. Nobody explains that away with a travel booking. Option (b) is the hypothesis, not the proof. Option (c) explains how it started. Option (d) is strong supporting evidence but hosting ASNs also carry consumer VPN exits — on its own it moves your confidence, it does not close the case. State the SessionId in your report: it is the thread that ties the intrusion together.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Impossible Travel — Accounts Payable Mailbox",
    threat_actor: "Business Email Compromise operator (financially motivated)",
    attack_kind: "impossible_travel_basic",
    briefing:
      "Microsoft Sentinel opened a ticket at 08:29 on an impossible-travel anomaly for d.harel@nexacorp.com: a successful Exchange Online sign-in from Tel Aviv at 06:12 and another successful sign-in from Amsterdam at 08:27. Finance say Dana is at her desk in the Tel Aviv office today. Determine whether the account is compromised and what was done with it.",
    narrative: `At 06:12 Dana Harel, an accounts payable clerk, signed in to Exchange Online the way she signs in every morning: from her home address 82.166.44.19 on her corporate laptop LT-FIN-3390, an Entra-joined and Intune-managed Windows 11 machine, with an Authenticator push answered on her phone. Six minutes later she brought up the corporate VPN through VPN-GW-01.

At 07:26 a message reached her inbox claiming her sign-in session needed re-verifying, with a link to nexacorp-signin-verify.com — a lookalike domain that failed SPF and DMARC and was delivered anyway (T1566.002). Five minutes later the proxy recorded her laptop POSTing form data to that page, which the proxy filed under "Newly Registered and Observed Domains" and allowed. That request is where her authenticated session left the building (T1539). At 07:40 the VPN session closed after one hour and twenty-two minutes.

At 08:27 the same account signed in successfully to Exchange Online from 146.190.62.117 in Amsterdam, on AutonomousSystemNumber 14061 — a hosting provider, not her ISP and not the 194.90.7.20 address the corporate gateway uses. The device fields are empty: no deviceId, isManaged false, isCompliant false, MacOs and Firefox instead of Windows 11 and Edge. MFA is recorded as satisfied, but by a claim carried inside the token rather than by any challenge anyone answered. Those three facts together are what convert the impossible-travel hypothesis into a verdict; the map alone never could, and "she must be on a VPN" is a claim the gateway log had already disproved.

What the intruder did next removes any doubt. Everything from 08:27 onwards shares SessionId a4f8c1d2-7b93-4e15-8c60-3d29f7a1b504. At 08:33 a rule called "AP sync" was created on the mailbox, forwarding anything matching invoice, remittance, bank details, IBAN or payment to ap-archive.2026@securemaildrop.net and moving the originals into RSS Subscriptions marked as read (T1114.003). At 08:41 the Vendor Banking folder was read in bulk — 812 items in a single sync (T1114.002). At 08:52 a message went out to a supplier contact at ridgeline-supply.com with new remittance details attached, sent from the Drafts folder so it never appeared in Sent Items where Dana would have seen it.

Containment is an identity action, not a host action: revoke the account's refresh tokens so the stolen session dies, force a password reset, delete the "AP sync" rule, and tell accounts payable to phone the supplier on a number from the contract rather than one from any email.`,
    learning_objectives: [
      "Treat an impossible-travel alert as a hypothesis and name the specific fields that would confirm or refute it, rather than deciding from the map",
      "Test the innocent explanation with evidence — read the VPN gateway log for session start, end and public egress address instead of assuming a VPN was involved",
      "Compare DeviceDetail, AutonomousSystemNumber and UserAgent against the user's own baseline sign-in to tell a different network from a different machine",
      "Read AuthenticationDetails to see how MFA was satisfied, and recognise that a requirement met by a claim in the token means no challenge was ever answered",
      "Use SessionId to link post-authentication actions back to a specific sign-in, and escalate on that linkage rather than on geography",
    ],
    // alerts are attached by the catalogue wiring
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Baseline", action: "d.harel signs in from Tel Aviv on LT-FIN-3390 with an Authenticator push" },
      { ts: T(74 * MIN), phase: "Initial Access", action: "Lookalike re-verification email delivered to the inbox" },
      { ts: T(79 * MIN), phase: "Credential Access", action: "Laptop POSTs to nexacorp-signin-verify.com — session token captured" },
      { ts: T(88 * MIN), phase: "Context", action: "Corporate VPN session ends — nothing after this came through the gateway" },
      { ts: T(135 * MIN), phase: "Valid Accounts", action: "Successful sign-in from 146.190.62.117, unmanaged device, MFA satisfied by token claim" },
      { ts: T(137 * MIN), phase: "Detection", action: "Sentinel raises the impossible-travel anomaly" },
      { ts: T(141 * MIN), phase: "Persistence", action: "\"AP sync\" inbox rule forwards payment mail out and hides the originals" },
      { ts: T(149 * MIN), phase: "Collection", action: "812 items read in one sync from the Vendor Banking folder" },
      { ts: T(160 * MIN), phase: "Impact", action: "Payment-detail change sent to a supplier from the compromised mailbox" },
    ],
    questions,
  };
}
