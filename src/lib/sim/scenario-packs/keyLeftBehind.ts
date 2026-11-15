/**
 * Scenario pack: "The key left behind"
 *
 * INTERMEDIATE tier. A Microsoft 365 identity case where the alert looks like a
 * textbook false positive. At 02:14 Sentinel raises "Mailbox sign-in outside
 * business hours" for a.feldman (Anna Feldman, Procurement Manager, NexaCorp).
 * Every entity on the alert checks out: the address is the company's GlobalProtect
 * egress, the device is her own compliant, Entra-joined laptop, VirusTotal knows
 * nothing bad about either address, the CMDB confirms she owns the laptop, Defender
 * shows only Outlook syncing, and the Azure Activity Log is quiet. The night-shift
 * Tier 1 proposes closing it as benign.
 *
 * The alert is right for the wrong reason. The analytic counted MailItemsAccessed
 * volume (the real signal) and then JOINED the user's latest Outlook/Office sign-in
 * to fill its IP and host entities. Her laptop, left on overnight on always-on VPN,
 * refreshed its Outlook token one minute earlier, so the enrichment pinned the alert
 * to an innocent session. The mailbox reads themselves were made by a different
 * client: "eSign Document Viewer", an unverified multi-tenant OAuth app she consented
 * to the previous morning from a supplier-themed lure that linked to the REAL
 * login.microsoftonline.com. The consent handed the app a refresh token (offline_access)
 * for Mail.ReadWrite, Mail.Send and MailboxSettings.ReadWrite. No password was stolen,
 * MFA was satisfied by her own device, and the token keeps working after a password
 * reset: the key she left behind.
 *
 * The teaching spine:
 *   • An alert's entities can be ENRICHMENT, not evidence. Read the rule's query and
 *     go back to the records that triggered it (the UAL rows), not the sign-in it joined.
 *   • The decisive pivots are AppId / ClientAppId and ClientIPAddress on MailItemsAccessed,
 *     the non-interactive Graph sign-ins with no device from hosting, and the Entra audit
 *     "Consent to application" the day before. A clean VirusTotal score on fresh hosting
 *     proves nothing; consent grants live in the Entra audit log, not the Azure Activity Log.
 *   • Containment is revoking the grant and the refresh tokens, not resetting the password.
 *
 * BENIGN CONTROLS (same shape, opposite verdict): the laptop's own Outlook token
 * refresh from the VPN egress the night BEFORE the lure (02:12 on 12 Nov), and the
 * same refresh at 02:13 on the alert night. Both are routine; the alert night differs
 * only in the app reading the mailbox from 203.0.113.142.
 *
 * Covers T1566.002 (Spearphishing Link, the consent lure), T1528 (Steal Application
 * Access Token, the illicit consent), T1550.001 (Application Access Token, the app
 * signing in with the refresh token), T1114.002 (Remote Email Collection), T1564.008
 * (Email Hiding Rules) and T1534 (Internal Spearphishing, the remittance email).
 *
 * SOURCES (registry-valid for their declared vendor): Microsoft Sentinel (the
 * SecurityAlert), Microsoft Entra ID (sign-in and audit logs), Microsoft 365 Unified
 * Audit Log (MailItemsAccessed, New-InboxRule, Send), Microsoft Defender for Office 365
 * (the lure and the Safe Links click), Microsoft Defender for Endpoint (the laptop's
 * network event), VirusTotal (IP address reports, API v3), ServiceNow (the CMDB records
 * and the ITSM tickets) and the Azure Activity Log. Fits the nexacorp stack.
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate".
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { entraSignIn, entraAudit } from "@/lib/sim/emitters/entra";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { mdeNetwork } from "@/lib/sim/emitters/mde";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";

export function buildKeyLeftBehindScenario(scenarioId = "key-left-behind-2026"): ScenarioBundle {
  const INCIDENT = "inc:klb:1";
  const companyId = "nexacorp";

  // The employee, her laptop and the company VPN.
  const victim = { email: "a.feldman@nexacorp.com", name: "Anna Feldman", sam: "a.feldman", title: "Procurement Manager" };
  const laptop = { host: "WS-PRC-3318", deviceId: "3f6b2c91-7d4e-4a08-b5c2-91e7d0a4f6b3", vpnIp: "10.10.60.23" };
  const vpnEgress = "192.0.2.151";          // GlobalProtect gateway NAT, London
  const london = { country: "United Kingdom", city: "London", countryCode: "GB" };

  // The OAuth app the lure asked her to approve, and where it runs.
  const app = { name: "eSign Document Viewer", appId: "7c3f9a12-5e48-4b6d-9a1f-3d82c0e6b415" };
  const appIp = "203.0.113.142";            // hosting, Frankfurt
  const frankfurt = { country: "Germany", city: "Frankfurt am Main", countryCode: "DE" };
  const lureDomain = "esign-docviewer.com";
  const lureSender = `notifications@${lureDomain}`;
  const lureSendIp = "203.0.113.61";
  const scopes = "Mail.ReadWrite Mail.Send MailboxSettings.ReadWrite offline_access User.Read";
  const consentUrl =
    `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${app.appId}&response_type=code` +
    `&redirect_uri=https%3A%2F%2F${lureDomain}%2Fauth%2Fcallback&scope=Mail.ReadWrite%20Mail.Send%20MailboxSettings.ReadWrite%20offline_access%20User.Read&state=mrdn-q1-2027`;
  const lureSubject = "Meridian Supplies: supplier agreement Q1-2027 ready for your review";

  const outlook = { app: "Microsoft Office", appId: "d3590ed6-52b3-4102-aeff-aad2292ab01c", resource: "Office 365 Exchange Online" };
  const outlookUa = "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.18129; Pro)";
  const exoFrontDoor = "52.98.151.66";      // outlook.office365.com

  const soc = "soc-tier1@nexacorp.com";
  const socTicket = "INC0104417";
  const deskTicket = "INC0104288";

  // Her laptop's Outlook refreshing its token over the VPN: routine, every night it is left on.
  const laptopRefresh = (id: string, ts: string, description: string, fp: string): TelemetryEvent => ({
    ...entraSignIn({
      id, ts, companyId, user: victim.email, displayName: victim.name, userTitle: victim.title,
      srcIp: vpnEgress, geo: london, app: outlook.app, appId: outlook.appId, resource: outlook.resource,
      isInteractive: false, mfa: true, managed: true, compliant: true, trustType: "Azure AD joined",
      deviceId: laptop.deviceId, deviceName: laptop.host, os: "Windows 11", userAgent: outlookUa,
      incomingTokenType: "primaryRefreshToken", severity: "medium", description,
      extra: { "azure.signinlogs.properties.clientAppUsed": "Mobile Apps and Desktop clients" },
    }),
    expected_verdict: "fp",
    fp_explanation: fp,
  });

  // The OAuth app redeeming its refresh token from its own server: no device, hosting address.
  const appSignIn = (id: string, ts: string, description: string): TelemetryEvent => entraSignIn({
    id, ts, companyId, user: victim.email, displayName: victim.name, userTitle: victim.title,
    srcIp: appIp, geo: frankfurt, asn: 14061, app: app.name, appId: app.appId, resource: "Microsoft Graph",
    isInteractive: false, mfa: false, managed: false, compliant: false, incomingTokenType: "refreshToken",
    userAgent: "python-requests/2.32.3",
    conditionalAccess: "notApplicable", severity: "medium", mitre: "T1550.001", tactic: "Lateral Movement",
    incidentId: INCIDENT, description,
    extra: { "azure.signinlogs.properties.clientAppUsed": "Mobile Apps and Desktop clients" },
  });

  const events: TelemetryEvent[] = [
    // ── 12 Nov, 02:12 · BENIGN CONTROL: the laptop's nightly Outlook refresh, before any lure ──
    laptopRefresh("evt_klb_00_laptop_refresh_prev", "2026-11-12T02:12:41.000Z",
      "Non-interactive sign-in for a.feldman to Office 365 Exchange Online from Microsoft Office on WS-PRC-3318 (compliant, Entra-joined) via 192.0.2.151, the night before the alert.",
      "Benign. Her laptop stays docked and connected to the always-on GlobalProtect VPN overnight, and Outlook renews its token about once an hour. Same app, same device id, same VPN egress, primary refresh token: this is what the 02:13 sign-in on the alert night looks like too, so that sign-in on its own says nothing about who read the mailbox."),

    // ── 12 Nov, 10:02 · the lure: a supplier-themed e-signature notice, clean authentication ──
    {
      id: "evt_klb_01_lure_email",
      ts: "2026-11-12T10:02:14.000Z",
      source: "email_gateway",
      vendor: "Microsoft Defender for Office 365",
      event_type: "email_received",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: lureSendIp,
      geo: { country: "Netherlands", city: "Amsterdam" },
      severity: "low",
      mitre_technique: "T1566.002",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "A message to a.feldman from \"Meridian Supplies via eSign\" <notifications@esign-docviewer.com> asks her to review a supplier agreement. SPF, DKIM and DMARC pass for esign-docviewer.com; its button links to login.microsoftonline.com. Delivered to the inbox with no threat verdict.",
      network: { url: consentUrl, domain: "login.microsoftonline.com", method: "GET" },
      raw: {
        "email.from.display_name": "Meridian Supplies via eSign",
        "email.from.address": lureSender,
        "email.sender.address": `bounces@mail.${lureDomain}`,
        "email.to.address": victim.email,
        "email.subject": lureSubject,
        "email.direction": "inbound",
        "email.message_id": `<20261112100211.4f7a2c@mail.${lureDomain}>`,
        "email.url": consentUrl,
        "email.url_domain": "login.microsoftonline.com",
        "email.spf": "pass",
        "email.dkim": "pass",
        "email.dmarc": "pass",
        "email.auth.compauth": "pass",
        "data.office365.Directionality": "Inbound",
        "data.office365.DeliveryAction": "Delivered",
        "data.office365.DeliveryLocation": "Inbox",
        "data.office365.ThreatType": "None",
        "data.office365.SpamConfidenceLevel": "1",
        "data.office365.Sender": lureSender,
        "data.office365.SenderIp": lureSendIp,
        "data.office365.NetworkMessageId": "b2e7c4a9-1d36-4f58-8a0e-6c91d3f2a705",
        "data.office365.InternetMessageId": `<20261112100211.4f7a2c@mail.${lureDomain}>`,
        "data.office365.MailboxOwnerUPN": victim.email,
        "data.office365.Url": consentUrl,
        "data.office365.UrlDomain": "login.microsoftonline.com",
        "source.ip": lureSendIp,
      },
    },

    // ── 10:06 · Safe Links records the click (a Microsoft URL, allowed) ──
    {
      id: "evt_klb_02_safelinks_click",
      ts: "2026-11-12T10:06:52.000Z",
      source: "email_gateway",
      vendor: "Microsoft Defender for Office 365",
      event_type: "email_clicked",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: vpnEgress,
      geo: { country: "United Kingdom", city: "London" },
      severity: "low",
      mitre_technique: "T1566.002",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "Safe Links recorded a.feldman opening the message's login.microsoftonline.com link from 192.0.2.151; the click was allowed.",
      network: { url: consentUrl, domain: "login.microsoftonline.com", method: "GET" },
      raw: {
        "data.office365.Url": consentUrl,
        "data.office365.UrlDomain": "login.microsoftonline.com",
        "data.office365.UserId": victim.email,
        "data.office365.NetworkMessageId": "b2e7c4a9-1d36-4f58-8a0e-6c91d3f2a705",
        "data.office365.ClientIP": vpnEgress,
        "data.office365.Workload": "Email",
        "source.ip": vpnEgress,
      },
    },

    // ── 10:07 · she signs in to the app with her own device (MFA by her PRT) ──
    entraSignIn({
      id: "evt_klb_03_app_interactive_signin", ts: "2026-11-12T10:07:19.000Z", companyId,
      user: victim.email, displayName: victim.name, userTitle: victim.title,
      srcIp: vpnEgress, geo: london, app: app.name, appId: app.appId, resource: "Microsoft Graph",
      isInteractive: true, mfa: true, managed: true, compliant: true, trustType: "Azure AD joined",
      deviceId: laptop.deviceId, deviceName: laptop.host, os: "Windows 11", browser: "Edge 130.0.0",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
      severity: "low", mitre: "T1528", tactic: "Credential Access", incidentId: INCIDENT,
      description: "Interactive sign-in for a.feldman to the application \"eSign Document Viewer\" (resource Microsoft Graph) from WS-PRC-3318 via 192.0.2.151; MFA satisfied, Conditional Access success.",
    }),

    // ── 10:07 · the grant: user consent to an unverified multi-tenant app ──
    entraAudit({
      id: "evt_klb_04_consent", ts: "2026-11-12T10:07:31.000Z", companyId,
      operationName: "Consent to application", category: "ApplicationManagement", loggedByService: "Core Directory",
      operationType: "Assign", initiatedByUpn: victim.email, initiatedByIp: vpnEgress, eventType: "account_modify",
      severity: "medium", mitre: "T1528", tactic: "Credential Access", incidentId: INCIDENT, geo: { country: "United Kingdom", city: "London" },
      description: "Entra audit: a.feldman consented to \"eSign Document Viewer\" for Mail.ReadWrite, Mail.Send, MailboxSettings.ReadWrite, offline_access and User.Read. IsAdminConsent False.",
      extra: {
        "azure.auditlogs.properties.targetResources[0].type": "ServicePrincipal",
        "azure.auditlogs.properties.targetResources[0].displayName": app.name,
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "ConsentContext.IsAdminConsent",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "\"False\"",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[1].displayName": "ConsentContext.OnBehalfOfAll",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[1].newValue": "\"False\"",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[2].displayName": "ConsentAction.Permissions",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[2].newValue": `"[] => [[ConsentType: Principal, Scope: ${scopes}]]; "`,
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[3].displayName": "TargetId.ServicePrincipalNames",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[3].newValue": `"${app.appId}"`,
      },
    }),

    // ── 10:08 · the app's first sign-in, from its own server, 31 seconds after the grant ──
    appSignIn("evt_klb_05_app_first_token", "2026-11-12T10:08:02.000Z",
      "Non-interactive sign-in for a.feldman to Microsoft Graph by the application \"eSign Document Viewer\" from 203.0.113.142 (AS14061, Frankfurt). Device id empty, not managed, incoming token type refreshToken."),

    // ── 10:09 · first read of her mailbox by the app ──
    m365Operation({
      id: "evt_klb_06_first_mail_read", ts: "2026-11-12T10:09:40.000Z", companyId, user: victim.email, userTitle: victim.title,
      operation: "MailItemsAccessed", workload: "Exchange", srcIp: appIp, eventType: "cloud_api_call",
      severity: "medium", mitre: "T1114.002", tactic: "Collection", incidentId: INCIDENT,
      description: "MailItemsAccessed (Bind, 37 items, Inbox) on a.feldman's mailbox from 203.0.113.142, client app id 7c3f9a12-5e48-4b6d-9a1f-3d82c0e6b415 (eSign Document Viewer).",
      extra: {
        RecordType: "50", MailboxOwnerUPN: victim.email, MailAccessType: "Bind", OperationCount: "37", "Folders[0].Path": "\\Inbox",
        ClientIPAddress: appIp, AppId: app.appId, ClientAppId: app.appId, "AppAccessContext.ClientAppName": app.name,
      },
    }),

    // ── 10:11 · her helpdesk ticket: the "document" was a blank page ──
    serviceNowRecord({
      id: "evt_klb_07_helpdesk_ticket", ts: "2026-11-12T10:41:00.000Z", incidentId: INCIDENT, user: victim.email,
      table: "incident", number: deskTicket, state: "Resolved", callerId: victim.email, severity: "low",
      shortDescription: "Supplier e-signature link shows a blank page after Microsoft sign-in",
      eventType: "policy_modification",
      extra: {
        "servicenow.description": "Caller received a Meridian Supplies agreement through an e-signature notice. She signed in with her Microsoft account, accepted the prompt and then got an empty page. Asks whether the document can be opened another way.",
        "servicenow.category": "Software",
        "servicenow.subcategory": "Email",
        "servicenow.contact_type": "Self-service",
        "servicenow.opened_by": victim.email,
        "servicenow.assignment_group": "Service Desk",
        "servicenow.assigned_to": "k.ibrahim@nexacorp.com",
        "servicenow.opened_at": "2026-11-12 10:11:00",
        "servicenow.sys_created_on": "2026-11-12 10:11:00",
        "servicenow.resolved_by": "k.ibrahim@nexacorp.com",
        "servicenow.resolved_at": "2026-11-12 10:41:00",
        "servicenow.close_code": "Solved (Work Around)",
        "servicenow.close_notes": "Link probably expired on the supplier side. Advised the user to ask Meridian Supplies to resend the agreement.",
      },
      description: `Service desk ticket ${deskTicket}, opened by a.feldman at 10:11 and resolved at 10:41: a supplier e-signature link showed a blank page after she signed in and accepted a prompt.`,
    }),

    // ── 13 Nov, 02:00 · Azure Activity Log: the subscription's only night-time entry ──
    {
      id: "evt_klb_08_azure_activity_runbook",
      ts: "2026-11-13T02:00:04.000Z",
      source: "cloud_azure",
      vendor: "Azure Activity Log",
      event_type: "cloud_api_call",
      severity: "informational",
      description:
        "Azure Activity Log: the automation account aa-ops-nightly started the scheduled runbook job Stop-DevVMs-Nightly in rg-ops-automation (Microsoft.Automation/automationAccounts/jobs/write). No other operation in the subscription between 00:00 and 03:00.",
      cloud: { provider: "Microsoft", service: "Azure Automation", api_call: "Microsoft.Automation/automationAccounts/jobs/write", region: "uksouth", resource: "aa-ops-nightly" },
      raw: {
        "azure.activitylogs.operationName": "Microsoft.Automation/automationAccounts/jobs/write",
        "azure.resource.id": "/SUBSCRIPTIONS/6A1D3E58-2C47-4B9F-8E10-7F4C92D5B3A6/RESOURCEGROUPS/RG-OPS-AUTOMATION/PROVIDERS/MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/AA-OPS-NIGHTLY/JOBS/0E9C4B21-73A8-4D5F-B612-8C3A0F7E9D44",
        "azure.subscription.id": "6a1d3e58-2c47-4b9f-8e10-7f4c92d5b3a6",
        "azure.resource.group": "rg-ops-automation",
        "azure.correlation_id": "4c8e1f92-6a3b-4d07-9e51-2b7f0c8a6d13",
        "azure.activitylogs.event_category": "Administrative",
        "azure.activitylogs.resultType": "Success",
        "azure.activitylogs.resultSignature": "Succeeded.Created",
        "azure.activitylogs.identity.claims.appid": "e1b7c3a4-9d26-4f80-a5c1-3f6e0b9d2a87",
        "azure.activitylogs.identity.authorization.evidence.role": "Automation Operator",
        "azure.activitylogs.identity.authorization.evidence.principalType": "ServicePrincipal",
      },
    },

    // ── 02:13 · BENIGN CONTROL: the same nightly Outlook refresh from her laptop ──
    laptopRefresh("evt_klb_09_laptop_refresh", "2026-11-13T02:13:05.000Z",
      "Non-interactive sign-in for a.feldman to Office 365 Exchange Online from Microsoft Office on WS-PRC-3318 (compliant, Entra-joined) via 192.0.2.151.",
      "Benign on its own. It is the laptop's hourly Outlook token renewal over the always-on VPN, identical to the 02:12 sign-in the night before. It is the sign-in the Sentinel rule joined to fill the alert's IP and host, but it is not the client that read the mailbox at 02:14."),

    // ── 02:13 · Defender: Outlook on the laptop syncing to Exchange Online ──
    mdeNetwork({
      id: "evt_klb_10_laptop_outlook_sync", ts: "2026-11-13T02:13:06.000Z", companyId, host: laptop.host, user: victim.email,
      srcIp: laptop.vpnIp, remoteIp: exoFrontDoor, remotePort: 443, application: "tls", domain: "outlook.office365.com",
      url: "outlook.office365.com", initiatingProcess: "OUTLOOK.EXE", severity: "low",
      description: "Defender for Endpoint on WS-PRC-3318: OUTLOOK.EXE connected to outlook.office365.com (52.98.151.66:443) from the VPN address 10.10.60.23. No alerts on the device in the last 7 days.",
    }),

    // ── 02:13:48 · the app's token again, from the same hosting address ──
    appSignIn("evt_klb_11_app_night_token", "2026-11-13T02:13:48.000Z",
      "Non-interactive sign-in for a.feldman to Microsoft Graph by the application \"eSign Document Viewer\" from 203.0.113.142 (AS14061, Frankfurt). Device id empty, not managed, incoming token type refreshToken."),

    // ── 02:14 · the mailbox read that fires the analytic ──
    m365Operation({
      id: "evt_klb_12_night_mail_read", ts: "2026-11-13T02:14:05.000Z", companyId, user: victim.email, userTitle: victim.title,
      operation: "MailItemsAccessed", workload: "Exchange", srcIp: appIp, eventType: "cloud_api_call",
      severity: "high", mitre: "T1114.002", tactic: "Collection", incidentId: INCIDENT,
      description: "MailItemsAccessed (Bind, 214 items, Inbox and Sent Items) on a.feldman's mailbox from 203.0.113.142, client app id 7c3f9a12-5e48-4b6d-9a1f-3d82c0e6b415 (eSign Document Viewer).",
      extra: {
        RecordType: "50", MailboxOwnerUPN: victim.email, MailAccessType: "Bind", OperationCount: "214", "Folders[0].Path": "\\Inbox, \\Sent Items",
        ClientIPAddress: appIp, AppId: app.appId, ClientAppId: app.appId, "AppAccessContext.ClientAppName": app.name,
      },
    }),

    // ── 02:14:30 · THE ALERT: the rule counted the reads, then joined her Outlook sign-in ──
    sentinelAlert({
      id: "evt_klb_13_sentinel_alert", ts: "2026-11-13T02:14:30.000Z", companyId, user: victim.email, host: laptop.host, srcIp: vpnEgress,
      alertName: "Mailbox sign-in outside business hours", subject: "mail", severity: "medium",
      startTime: "2026-11-13T02:14:05.000Z", endTime: "2026-11-13T02:14:05.000Z",
      mitre: "T1114.002", tactic: "Collection", incidentId: INCIDENT,
      detail: "Mailbox activity for a user between 00:00 and 05:00 UTC above the threshold, with the user's latest Outlook sign-in.",
      entities: [
        { "$id": "1", Type: "account", Name: victim.sam, UPNSuffix: "nexacorp.com" },
        { "$id": "2", Type: "ip", Address: vpnEgress },
        { "$id": "3", Type: "host", HostName: laptop.host, DnsDomain: "nexacorp.com", FQDN: `${laptop.host}.nexacorp.com` },
      ],
      extendedProperties: {
        "Analytic Rule Name": "Mailbox sign-in outside business hours",
        "Query Period": "1h",
        "Trigger Operator": "GreaterThan",
        "Trigger Threshold": "0",
        "Search Query Results Overall Count": "1",
        "Query":
          "OfficeActivity | where Operation == \"MailItemsAccessed\" | where hourofday(TimeGenerated) between (0 .. 4) " +
          "| summarize Items = sum(toint(OperationCount)) by UserId | where Items > 50 " +
          "| join kind=inner (union SigninLogs, AADNonInteractiveUserSignInLogs | where AppDisplayName in (\"Microsoft Office\", \"Outlook Mobile\") " +
          "| summarize arg_max(TimeGenerated, IPAddress, DeviceDetail) by UserPrincipalName) on $left.UserId == $right.UserPrincipalName",
      },
      description: "Sentinel raised a Medium alert, Mailbox sign-in outside business hours, for a.feldman. Entities: account a.feldman, IP 192.0.2.151, host WS-PRC-3318.",
    }),

    // ── 02:15 · SOAR enrichment: VirusTotal reports for both addresses that signed in as her ──
    {
      id: "evt_klb_14_vt_vpn_ip",
      ts: "2026-11-13T02:15:10.000Z",
      source: "threat_intel",
      vendor: "VirusTotal",
      event_type: "cloud_api_call",
      src_ip: vpnEgress,
      user_email: victim.email,
      severity: "informational",
      description: "VirusTotal IP report for 192.0.2.151: 0 of 94 engines malicious, owner NexaCorp Financial Ltd, GB.",
      raw: {
        "data.id": vpnEgress,
        "data.type": "ip_address",
        "data.links.self": `https://www.virustotal.com/api/v3/ip_addresses/${vpnEgress}`,
        "data.attributes.as_owner": "NexaCorp Financial Ltd",
        "data.attributes.asn": 64500,
        "data.attributes.country": "GB",
        "data.attributes.continent": "EU",
        "data.attributes.network": "192.0.2.144/28",
        "data.attributes.regional_internet_registry": "RIPE NCC",
        "data.attributes.reputation": 0,
        "data.attributes.last_analysis_date": 1762999200,
        "data.attributes.last_analysis_stats.malicious": 0,
        "data.attributes.last_analysis_stats.suspicious": 0,
        "data.attributes.last_analysis_stats.harmless": 61,
        "data.attributes.last_analysis_stats.undetected": 33,
        "data.attributes.last_analysis_stats.timeout": 0,
        "data.attributes.tags": [],
      },
    },
    {
      id: "evt_klb_15_vt_app_ip",
      ts: "2026-11-13T02:15:12.000Z",
      source: "threat_intel",
      vendor: "VirusTotal",
      event_type: "cloud_api_call",
      src_ip: appIp,
      user_email: victim.email,
      severity: "informational",
      description: "VirusTotal IP report for 203.0.113.142: 0 of 94 engines malicious, owner DIGITALOCEAN-ASN (AS14061), DE, reputation 0.",
      raw: {
        "data.id": appIp,
        "data.type": "ip_address",
        "data.links.self": `https://www.virustotal.com/api/v3/ip_addresses/${appIp}`,
        "data.attributes.as_owner": "DIGITALOCEAN-ASN",
        "data.attributes.asn": 14061,
        "data.attributes.country": "DE",
        "data.attributes.continent": "EU",
        "data.attributes.network": "203.0.113.0/24",
        "data.attributes.regional_internet_registry": "RIPE NCC",
        "data.attributes.reputation": 0,
        "data.attributes.last_analysis_date": 1762999212,
        "data.attributes.last_analysis_stats.malicious": 0,
        "data.attributes.last_analysis_stats.suspicious": 0,
        "data.attributes.last_analysis_stats.harmless": 58,
        "data.attributes.last_analysis_stats.undetected": 36,
        "data.attributes.last_analysis_stats.timeout": 0,
        "data.attributes.tags": [],
      },
    },

    // ── 02:15:30 · the app hides replies: a rule that moves payment mail out of sight ──
    m365Operation({
      id: "evt_klb_16_inbox_rule", ts: "2026-11-13T02:15:30.000Z", companyId, user: victim.email, userTitle: victim.title,
      operation: "New-InboxRule", workload: "Exchange", srcIp: appIp, eventType: "policy_modification",
      severity: "high", mitre: "T1564.008", tactic: "Stealth", incidentId: INCIDENT,
      description: "New-InboxRule \".\" on a.feldman's mailbox from 203.0.113.142 by app id 7c3f9a12-5e48-4b6d-9a1f-3d82c0e6b415: messages containing remittance, bank details or payment are moved to RSS Feeds and marked as read.",
      extra: {
        RecordType: "1", AppId: app.appId, ClientAppId: app.appId,
        Parameters: JSON.stringify([
          { Name: "Name", Value: "." },
          { Name: "SubjectOrBodyContainsWords", Value: "remittance;bank details;payment" },
          { Name: "MoveToFolder", Value: "RSS Feeds" },
          { Name: "MarkAsRead", Value: "True" },
          { Name: "StopProcessingRules", Value: "True" },
        ]),
      },
    }),

    // ── 02:16 · the CMDB answers the Tier 1's ownership check ──
    {
      id: "evt_klb_17_cmdb_laptop",
      ts: "2026-11-13T02:16:20.000Z",
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      hostname: laptop.host,
      user_email: victim.email,
      user: { full_name: victim.name, email: victim.email, department: "Procurement", title: victim.title },
      severity: "informational",
      description: "CMDB record for WS-PRC-3318: Windows 11 Enterprise laptop, assigned to a.feldman (Procurement), installed and operational, last discovered at 10.10.60.23.",
      raw: {
        "servicenow.table": "cmdb_ci_computer",
        "servicenow.name": laptop.host,
        "servicenow.asset_tag": "NXC-AST-03318",
        "servicenow.serial_number": "PF4X2K9L",
        "servicenow.manufacturer": "Lenovo",
        "servicenow.model_id": "ThinkPad T14 Gen 4",
        "servicenow.os": "Windows 11 Enterprise",
        "servicenow.os_version": "10.0.22631",
        "servicenow.ip_address": laptop.vpnIp,
        "servicenow.assigned_to": victim.email,
        "servicenow.department": "Procurement",
        "servicenow.location": "London - Canary Wharf",
        "servicenow.install_status": "1",
        "servicenow.operational_status": "1",
        "servicenow.discovery_source": "SCCM",
        "servicenow.last_discovered": "2026-11-12 18:02:11",
      },
    },
    {
      id: "evt_klb_18_cmdb_vpn_gateway",
      ts: "2026-11-13T02:16:24.000Z",
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      hostname: "PA-GP-LON-01",
      severity: "informational",
      description: "CMDB record for PA-GP-LON-01: the GlobalProtect gateway firewall in London, public NAT address 192.0.2.151, owned by Network Operations.",
      raw: {
        "servicenow.table": "cmdb_ci_ip_firewall",
        "servicenow.name": "PA-GP-LON-01",
        "servicenow.asset_tag": "NXC-NET-00412",
        "servicenow.serial_number": "013201004127",
        "servicenow.manufacturer": "Palo Alto Networks",
        "servicenow.model_id": "PA-3410",
        "servicenow.ip_address": vpnEgress,
        "servicenow.short_description": "GlobalProtect gateway, remote-access NAT pool for all VPN users",
        "servicenow.department": "Network Operations",
        "servicenow.location": "London - Canary Wharf",
        "servicenow.install_status": "1",
        "servicenow.operational_status": "1",
        "servicenow.discovery_source": "ServiceNow",
        "servicenow.last_discovered": "2026-11-12 23:40:05",
      },
    },

    // ── 02:16:40 · the app sends mail as her: new bank details to Accounts Payable ──
    m365Operation({
      id: "evt_klb_19_send_remittance", ts: "2026-11-13T02:16:40.000Z", companyId, user: victim.email, userTitle: victim.title,
      operation: "Send", workload: "Exchange", srcIp: appIp, eventType: "email_sent",
      severity: "high", mitre: "T1534", tactic: "Lateral Movement", incidentId: INCIDENT,
      description: "Send from a.feldman's mailbox at 02:16 by app id 7c3f9a12-5e48-4b6d-9a1f-3d82c0e6b415 from 203.0.113.142, subject \"Meridian Supplies: updated remittance details\", to accounts.payable@nexacorp.com.",
      extra: {
        RecordType: "2", MailboxOwnerUPN: victim.email, ClientIPAddress: appIp, AppId: app.appId, ClientAppId: app.appId,
        "AppAccessContext.ClientAppName": app.name, "Item.Subject": "Meridian Supplies: updated remittance details",
      },
    }),

    // ── 02:21 · the case: opened by the SIEM integration, Tier 1 proposes closing ──
    serviceNowRecord({
      id: "evt_klb_20_soc_case", ts: "2026-11-13T02:31:00.000Z", incidentId: INCIDENT, user: victim.email,
      table: "incident", number: socTicket, state: "In Progress", callerId: victim.email, severity: "medium",
      shortDescription: "Sentinel: Mailbox sign-in outside business hours (a.feldman)",
      extra: {
        "servicenow.description": "Created from Microsoft Sentinel alert \"Mailbox sign-in outside business hours\". Entities: account a.feldman, IP 192.0.2.151, host WS-PRC-3318.",
        "servicenow.category": "Security",
        "servicenow.subcategory": "Identity",
        "servicenow.contact_type": "Monitoring",
        "servicenow.priority": "3 - Moderate",
        "servicenow.impact": "2 - Medium",
        "servicenow.urgency": "2 - Medium",
        "servicenow.opened_by": "svc-sentinel-itsm",
        "servicenow.assignment_group": "SOC Tier 1",
        "servicenow.assigned_to": soc,
        "servicenow.cmdb_ci": laptop.host,
        "servicenow.opened_at": "2026-11-13 02:21:00",
        "servicenow.sys_created_on": "2026-11-13 02:21:00",
        "servicenow.work_notes": "Checked the alert entities. 192.0.2.151 is our GlobalProtect egress (CMDB PA-GP-LON-01). WS-PRC-3318 is her own laptop, compliant, no Defender alerts. VirusTotal 0/94 on the alert IP. Proposing to close as benign: user laptop left on VPN overnight.",
      },
      description: `SOC case ${socTicket}, opened by the Sentinel integration at 02:21. The Tier 1 work note proposes closing it as benign after checking the alert's IP, host and VirusTotal score.`,
    }),
  ];

  events.sort((a, b) => a.ts.localeCompare(b.ts));

  const iocs: IOC[] = [
    { type: "ip", value: appIp, first_seen: "2026-11-12T10:08:02.000Z", last_seen: "2026-11-13T02:16:40.000Z", reputation: "malicious", tags: ["oauth-app-infrastructure", "hosting-asn", "AS14061"] },
    { type: "domain", value: lureDomain, first_seen: "2026-11-12T10:02:14.000Z", last_seen: "2026-11-12T10:07:31.000Z", reputation: "malicious", tags: ["lure-sender-domain", "oauth-redirect-uri"] },
    { type: "email", value: lureSender, first_seen: "2026-11-12T10:02:14.000Z", last_seen: "2026-11-12T10:02:14.000Z", reputation: "malicious", tags: ["lure-sender"] },
    { type: "url", value: consentUrl, first_seen: "2026-11-12T10:02:14.000Z", last_seen: "2026-11-12T10:06:52.000Z", reputation: "malicious", tags: ["consent-link", "login.microsoftonline.com", `client_id ${app.appId}`] },
    { type: "user", value: victim.email, first_seen: "2026-11-12T10:07:31.000Z", last_seen: "2026-11-13T02:16:40.000Z", reputation: "suspicious", tags: ["consented-user", "mailbox-accessed-by-app"] },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt: "The alert lists IP 192.0.2.151 and host WS-PRC-3318. Read the rule's Query in the alert. Where do those two values come from?",
      hint: "Follow the KQL in ExtendedProperties.Query: what does the summarize count, and what does the join add afterwards?",
      kind: "single",
      options: [
        { value: "join_enrichment", label: "From the join to her latest Microsoft Office sign-in, added after the rule had already counted the MailItemsAccessed rows" },
        { value: "from_mail_rows", label: "From the MailItemsAccessed rows themselves, which record the VPN egress as the ClientIPAddress of each mailbox read" },
        { value: "from_defender", label: "From Defender for Endpoint, which stamps every identity alert with the device that last synced the user's mailbox" },
        { value: "from_cmdb", label: "From the CMDB lookup the SIEM runs on every alert to map the user to her assigned laptop and its public address" },
      ],
      answer: "join_enrichment",
      xp: 60,
      explanation:
        "The rule does two things. First it sums OperationCount on MailItemsAccessed between 00:00 and 05:00 and keeps users above 50: that is the trigger, and it came from the 214-item read at 02:14. Then it joins SigninLogs and AADNonInteractiveUserSignInLogs, filtered to the Microsoft Office and Outlook Mobile apps, and takes the latest row per user with arg_max. That row was her laptop's 02:13 Outlook token refresh, so the alert's IP and host are enrichment from a different session, not the address that read the mail. The MailItemsAccessed rows carry 203.0.113.142, Defender does not stamp Sentinel entities, and no CMDB lookup feeds this rule.",
    },
    {
      id: "q2",
      prompt: "Which evidence shows who actually read the mailbox at 02:14?",
      hint: "Open the UAL row behind the trigger and compare its client fields with the sign-ins in the same minute.",
      kind: "single",
      options: [
        { value: "appid_and_ip", label: "MailItemsAccessed with ClientAppId 7c3f9a12 (eSign Document Viewer) from 203.0.113.142, and that app's sign-in with no device" },
        { value: "laptop_outlook", label: "The Defender network event of OUTLOOK.EXE on WS-PRC-3318 reaching Exchange Online at 02:13 over the VPN address 10.10.60.23" },
        { value: "vpn_signin", label: "The 02:13 Entra sign-in from 192.0.2.151 with a primary refresh token, since a PRT can only be issued to her own device" },
        { value: "azure_runbook", label: "The Azure Activity Log runbook at 02:00, since the automation identity has delegated rights to every mailbox in the tenant" },
      ],
      answer: "appid_and_ip",
      xp: 65,
      explanation:
        "The mailbox record names the client that read it. The 02:14 MailItemsAccessed row carries AppId and ClientAppId 7c3f9a12-5e48-4b6d-9a1f-3d82c0e6b415, the eSign Document Viewer app, and ClientIPAddress 203.0.113.142. Thirty seconds earlier Entra logged that same app signing in as a.feldman to Microsoft Graph from 203.0.113.142 with an empty device id and a refresh token. The laptop's Outlook traffic and its PRT sign-in are real but they are the benign control: they show her laptop renewing a token, not who read 214 items. The runbook belongs to an automation account with an Automation Operator role and touches no mailbox.",
    },
    {
      id: "q3",
      prompt: "How did the reader of the mailbox get access without her password?",
      hint: "Go back to 12 November. What happened in Entra between the Safe Links click at 10:06 and the first app sign-in at 10:08?",
      kind: "single",
      options: [
        { value: "consent_grant", label: "She consented to an unverified app for Mail.ReadWrite, Mail.Send and offline_access, which gave it a refresh token of its own" },
        { value: "aitm_cookie", label: "A reverse proxy captured her session cookie at sign-in, and the attacker replayed that cookie to Outlook on the web at night" },
        { value: "password_spray", label: "Her password was guessed in a spray against Exchange Online, and MFA was skipped because the VPN egress is a trusted location" },
        { value: "infostealer", label: "Malware on WS-PRC-3318 copied the Outlook token cache, and the tokens were replayed from the laptop over the company VPN" },
      ],
      answer: "consent_grant",
      xp: 60,
      explanation:
        "The lure linked to the genuine login.microsoftonline.com authorize endpoint with client_id 7c3f9a12 and a redirect to esign-docviewer.com, so every URL and authentication check passed. At 10:07:19 she signed in to \"eSign Document Viewer\" from her own compliant device, and at 10:07:31 Entra logged Consent to application with ConsentType Principal and Scope Mail.ReadWrite Mail.Send MailboxSettings.ReadWrite offline_access User.Read. Thirty-one seconds later the app signed in from 203.0.113.142 with a refresh token. offline_access is what lets it keep doing that for weeks. There is no proxy domain in the sign-in, no failed sign-ins, and Defender shows no malware on the laptop, so the other stories have no evidence behind them. Her ticket at 10:11 about a blank page after accepting a prompt is the user-side trace of the same consent.",
    },
    {
      id: "q4",
      prompt: "The Tier 1 work note proposes closing the case as benign. Why is that close wrong even though each check in it is accurate?",
      kind: "single",
      options: [
        { value: "checked_wrong_session", label: "Every check validates the joined laptop session; none looks at the app behind the reads, and VirusTotal 0/94 on new hosting proves nothing" },
        { value: "vt_was_wrong", label: "The VirusTotal result was stale: a fresh scan of 192.0.2.151 would have shown the company's VPN egress listed as malicious" },
        { value: "device_noncompliant", label: "WS-PRC-3318 was not really compliant, because Defender reported an alert on the laptop that the Tier 1 overlooked" },
        { value: "cmdb_mismatch", label: "The CMDB assigns WS-PRC-3318 to a different user, so the laptop session itself belonged to someone else that night" },
      ],
      answer: "checked_wrong_session",
      xp: 65,
      explanation:
        "Each fact in the note is true: 192.0.2.151 is the GlobalProtect egress (CMDB PA-GP-LON-01), the laptop is hers and compliant, Defender is quiet, and VirusTotal scores the alert IP 0/94. The mistake is scope. All of those checks validate the session the rule joined, not the records that triggered it. Even the second VirusTotal report, for 203.0.113.142, is 0/94, because a freshly rented hosting address has no history; reputation absence is not evidence of safety. The VirusTotal data, Defender and the CMDB are all consistent, which is exactly why the close looks safe.",
    },
    {
      id: "q5",
      prompt: "The Tier 1 also looked at the Azure Activity Log and found only a runbook. Where is the record of the access being granted?",
      kind: "single",
      options: [
        { value: "entra_audit", label: "In the Entra ID audit log, as Consent to application on 12 November, because a grant is a tenant directory object" },
        { value: "azure_activity", label: "In the Azure Activity Log under Microsoft.Authorization/roleAssignments/write, if the retention window had been longer" },
        { value: "ual_send", label: "In the Unified Audit Log as a Send operation, since the grant is created when the app first sends mail as the user" },
        { value: "defender_endpoint", label: "In Defender for Endpoint as a browser event on WS-PRC-3318, because consent is stored on the device that approved it" },
      ],
      answer: "entra_audit",
      xp: 55,
      explanation:
        "An OAuth consent creates a delegated permission grant and a service principal in the Entra tenant, so it is logged in the Entra audit log (AuditLogs) as Consent to application, with the scopes in ConsentAction.Permissions. The Azure Activity Log records Azure Resource Manager operations on subscriptions: role assignments, VMs, runbooks. A quiet Activity Log therefore says nothing about mailbox access. The UAL shows what the app later did with the grant, and the device only showed the browser that rendered the prompt.",
    },
    {
      id: "q6",
      prompt: "You reopen the case as malicious. Which response actually removes the attacker's access?",
      kind: "single",
      options: [
        { value: "revoke_grant", label: "Remove the app's grant and service principal, revoke her refresh tokens, delete the rule, stop the remittance mail, restrict user consent" },
        { value: "reset_password", label: "Reset her password and require MFA re-registration, which invalidates every token issued to her account, including the app's" },
        { value: "isolate_laptop", label: "Isolate WS-PRC-3318 in Defender and reimage it, since the alert shows the mailbox was read from the laptop over the VPN" },
        { value: "block_ip_only", label: "Block 203.0.113.142 at the Palo Alto perimeter and keep the case open in monitoring, since the app cannot reach Graph any more" },
      ],
      answer: "revoke_grant",
      xp: 70,
      explanation:
        "The app's access lives in the consent grant and the refresh token issued to it, so containment is: delete the eSign Document Viewer service principal and its OAuth2 permission grant, revoke a.feldman's refresh tokens (Revoke-MgUserSignInSession), remove the \".\" inbox rule, and stop or recall the 02:16 remittance email before Accounts Payable acts on it. Then search for other users who consented to the same app id and set user consent to verified publishers or an admin consent workflow. A password reset does not revoke an app's delegated grant. The laptop was never involved. Blocking one IP is trivial to evade: the app's server runs from the cloud, and Graph is reachable from anywhere.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "The key left behind",
    threat_actor: "Consent-phishing operator abusing a multi-tenant OAuth app (cloud identity, no host foothold)",
    attack_kind: "oauth_consent_phishing",
    briefing:
      "At 02:14 Sentinel raised a Medium alert, Mailbox sign-in outside business hours, for a.feldman (Procurement). The alert points at her own laptop on the company VPN, and the night-shift Tier 1 has proposed closing case INC0104417 as benign. Review the evidence and decide whether that close is right.",
    narrative: `At 02:14 on 13 November Sentinel raised "Mailbox sign-in outside business hours" for Anna Feldman, NexaCorp's Procurement Manager. Every entity on it checked out. The IP, 192.0.2.151, is the GlobalProtect gateway's NAT address (CMDB PA-GP-LON-01). The host, WS-PRC-3318, is her own Entra-joined, compliant ThinkPad. Defender showed only OUTLOOK.EXE syncing with Exchange Online. VirusTotal scored the address 0 of 94. The Azure Activity Log held one scheduled runbook. The night-shift Tier 1 wrote it up as a laptop left on the VPN and proposed closing it.

Every one of those checks was accurate, and every one validated the wrong thing. The analytic counts MailItemsAccessed volume between midnight and 05:00, which is the real signal, and then joins the user's most recent Microsoft Office sign-in to fill the IP and host. Her laptop, left docked on always-on VPN, renews its Outlook token every hour; it did so at 02:13, exactly as it had at 02:12 the night before. The join picked that innocent session. The 214-item read at 02:14 was made by a different client: the MailItemsAccessed row names ClientAppId 7c3f9a12-5e48-4b6d-9a1f-3d82c0e6b415, "eSign Document Viewer", from 203.0.113.142, a DigitalOcean address in Frankfurt that Entra had seen signing in as her to Microsoft Graph thirty seconds earlier with no device and a refresh token.

The key was handed over the morning before. At 10:02 on 12 November a supplier-themed e-signature notice from esign-docviewer.com reached her inbox with SPF, DKIM and DMARC passing. Its button pointed at the real login.microsoftonline.com, with the app's client_id and a redirect to the attacker's domain, so Safe Links allowed the click. She signed in from her own laptop, MFA satisfied, and at 10:07:31 consented to the app for Mail.ReadWrite, Mail.Send, MailboxSettings.ReadWrite and offline_access. Thirty-one seconds later the app redeemed its token from Frankfurt and read 37 messages. When the page went blank she opened a service desk ticket, which was resolved as an expired supplier link.

No password was stolen, so no password check could find it, and a reset would not have ended it: the app holds its own refresh token. On the alert night it read the inbox and sent items, created an inbox rule named "." that hides replies about remittance, bank details and payment in RSS Feeds, and at 02:16 sent Accounts Payable "updated remittance details" from her real mailbox. The fix is to revoke the grant and the tokens, remove the rule, stop the payment email, hunt for other consents to the same app id, and restrict user consent. The lesson is to check which client did the reading, not which device the alert names.`,
    learning_objectives: [
      "Read a SIEM analytic's query to separate the trigger (MailItemsAccessed volume) from enrichment joined afterwards (the latest Outlook sign-in), and recognise when an alert's IP and host belong to a different session",
      "Attribute mailbox access to the client that performed it using AppId / ClientAppId and ClientIPAddress on MailItemsAccessed, and correlate it with non-interactive Microsoft Graph sign-ins that have no device",
      "Reconstruct an illicit OAuth consent from the Entra audit log (Consent to application, ConsentAction.Permissions, offline_access) and the lure that pointed at the genuine Microsoft sign-in page",
      "Explain why accurate checks (VPN egress in the CMDB, a compliant device, a quiet EDR, VirusTotal 0/94, a quiet Azure Activity Log) do not clear an identity alert, and why a clean reputation on fresh hosting proves nothing",
      "Contain an app-based mailbox compromise by revoking the grant and refresh tokens, removing the inbox rule, stopping the fraudulent email and restricting user consent, rather than resetting the password",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-11-12T02:12:41.000Z", phase: "Context", action: "Benign control: her laptop renews its Outlook token over the VPN from 192.0.2.151, as it does every night" },
      { ts: "2026-11-12T10:02:14.000Z", phase: "Initial Access", action: `Supplier-themed lure from ${lureDomain} links to the real login.microsoftonline.com consent flow (T1566.002)` },
      { ts: "2026-11-12T10:06:52.000Z", phase: "Initial Access", action: "Safe Links allows the click from 192.0.2.151 (T1566.002)" },
      { ts: "2026-11-12T10:07:31.000Z", phase: "Credential Access", action: `Consent to application: ${app.name} granted ${scopes} (T1528)` },
      { ts: "2026-11-12T10:08:02.000Z", phase: "Lateral Movement", action: `${app.name} signs in as a.feldman to Microsoft Graph from ${appIp} with a refresh token (T1550.001)` },
      { ts: "2026-11-12T10:09:40.000Z", phase: "Collection", action: "First MailItemsAccessed by the app: 37 items in the Inbox (T1114.002)" },
      { ts: "2026-11-13T02:13:05.000Z", phase: "Context", action: "Her laptop renews its Outlook token again; this is the session the alert later joins" },
      { ts: "2026-11-13T02:14:05.000Z", phase: "Collection", action: `MailItemsAccessed: 214 items by ClientAppId ${app.appId} from ${appIp} (T1114.002)` },
      { ts: "2026-11-13T02:14:30.000Z", phase: "Detection", action: "Sentinel alert fires on the volume; its IP and host come from the joined laptop sign-in" },
      { ts: "2026-11-13T02:15:30.000Z", phase: "Stealth", action: "Inbox rule \".\" moves remittance, bank details and payment mail to RSS Feeds (T1564.008)" },
      { ts: "2026-11-13T02:16:40.000Z", phase: "Lateral Movement", action: "The app sends Accounts Payable \"updated remittance details\" from her mailbox (T1534)" },
      { ts: "2026-11-13T02:21:00.000Z", phase: "Investigation", action: `Case ${socTicket} opened; Tier 1 proposes a benign close after checking only the alert's entities` },
    ],
    questions,
  };
}
