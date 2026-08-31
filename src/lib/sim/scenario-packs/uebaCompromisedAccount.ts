/**
 * Scenario pack: "Behavioral Risk First — a UEBA-led Account-Compromise Hunt"
 *
 * INTERMEDIATE tier. This is the platform's first ANOMALY-DRIVEN investigation:
 * it does not open with a signature alert (no malware verdict, no firewall block,
 * no DLP match). It opens with a NUMBER — Microsoft Sentinel UEBA raised the
 * entity risk score of a Finance manager, Jordan Almeida, after correlating three
 * behaviours that are each ordinary in isolation but wrong together: an atypical
 * sign-in from an unfamiliar location and a hosting ASN, a burst of file downloads
 * from OneDrive/SharePoint far above his own norm, and a newly-created mailbox
 * forwarding rule. None of those is a "this is an attack" event on its own; the
 * signal is the correlation, expressed as a risk score.
 *
 * The teaching arc is deliberately three-step: (1) start from the anomaly score,
 * (2) pivot DOWN into the primary telemetry — the Entra sign-in behind the
 * "impossible travel", the O365 audit records behind the "mass download" and the
 * "new inbox rule" — and (3) reach a verdict from that primary evidence, not from
 * the score. A high UEBA score is a REASON TO LOOK, never a verdict by itself.
 *
 * That is exactly why a BENIGN CONTROL is included and is the pedagogical crux: a
 * second user, Renée Laurent, trips the SAME ImpossibleTravel anomaly the same
 * night — but her sign-in is corroborated by an approved travel record, a known
 * corporate-VPN egress ASN, a compliant managed device and a satisfied MFA
 * requirement. Same "risky sign-in anomaly" shape, opposite verdict. Not every
 * high score is a compromise, and the analyst has to learn to tell them apart
 * from the underlying sign-in — not from the alert title.
 *
 * Covers T1078 (Valid Accounts — the compromised sign-in), T1539 (Steal Web
 * Session Cookie — the replayed session token that skipped the MFA prompt),
 * T1213.002 (Data from Information Repositories: SharePoint — the mass download)
 * and T1114.003 (Email Collection: Email Forwarding Rule — the hiding/forwarding
 * inbox rule).
 *
 * SOURCES (all fields registry-valid for their declared vendor): Microsoft
 * Sentinel (UEBA behaviour/anomaly indicators and the entity risk score that
 * opens the case), Microsoft Entra ID / Azure AD (the sign-in logs the anomalies
 * were derived from) and the Microsoft 365 Unified Audit Log (the OneDrive/
 * SharePoint download burst and the Exchange New-InboxRule). This pack fits the
 * Microsoft-365 / Entra company profiles (nexacorp, medcore, globallogis).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildUebaCompromisedAccountScenario(
  scenarioId = "ueba-compromised-account-2026",
): ScenarioBundle {
  const B = new Date("2026-08-30T23:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // One incident — the whole hunt is a single account-compromise case.
  const INCIDENT = "inc:uca:1";

  // The compromised account and his normal working context.
  const victim = {
    email: "j.almeida@nexacorp.com",
    name: "Jordan Almeida",
    sam: "j.almeida",
    title: "Finance Manager",
    dept: "Finance",
    userId: "a7f3c210-9b64-4e18-8d02-51c9e4a7b330",
    homeIp: "72.14.201.88",           // his usual corporate/home egress (New York)
  };

  // The attacker's session origin: a hosting/VPS ASN in Sofia, Bulgaria.
  const attackerIp = "45.135.232.71";
  const attackerAsn = 200651;         // a real-world hosting AS range
  const attackerAsnOrg = "Flokinet-Hosting";
  const hostileSession = "6f0b9d47-2a15-4c88-b3e1-7d92a4c0e6f5";

  // The external address the forwarding rule ships mail to.
  const dropAddress = "acct.archive.9y@gmail.com";

  // A representative downloaded file — its hash is the citable data IOC.
  const marqueeFile = "FY26_Budget_Consolidation.xlsx";
  const marqueeFileHash = makeSha256("nexacorp_fy26_budget_consolidation_xlsx_2026");

  // The BENIGN CONTROL: a Sales director who trips the SAME ImpossibleTravel
  // anomaly the same night, but legitimately — approved travel, corporate VPN
  // egress, compliant managed device, satisfied MFA.
  const benign = {
    email: "r.laurent@nexacorp.com",
    name: "Renée Laurent",
    sam: "r.laurent",
    title: "Sales Director",
    ip: "203.116.40.12",              // Singapore, corporate-VPN egress
  };

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a UEBA impossible-travel anomaly that resolves BENIGN.
    //    Same anomaly shape as the incident: a sign-in from far away flagged
    //    ImpossibleTravel. But it is corroborated (approved travel, corporate
    //    VPN ASN, compliant managed device, MFA satisfied), so the score is a
    //    false anomaly. This is what a high UEBA score can also mean.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_uca_00_benign_impossible_travel",
      ts: T(-3 * HOUR),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      user_email: benign.email,
      user_title: benign.title,
      src_ip: benign.ip,
      severity: "informational",
      fp_explanation:
        "Benign. r.laurent tripped ImpossibleTravelActivity the same night, but the sign-in is corroborated: an approved travel record for Singapore, egress over the known corporate-VPN ASN, a compliant managed device, and a satisfied MFA requirement. The anomaly score is real, the verdict is not a compromise — a UEBA score is a reason to look, not a conclusion. Contrast with j.almeida, whose sign-in has none of that corroboration.",
      description:
        "Sentinel raised an impossible-travel anomaly for r.laurent (New York → Singapore), but the Singapore sign-in came over the corporate VPN egress on a compliant, managed device with MFA satisfied, and matches an approved travel record.",
      raw: {
        "AlertName": "Atypical travel",
        "AlertSeverity": "Informational",
        "ImpossibleTravelActivity": "true",
        "entity.name": benign.sam,
        "entity.type": "user",
        "user.name": `NEXACORP\\${benign.sam}`,
        "user.email": benign.email,
        "source.geo.country_name": "Singapore",
        "authentication.status": "success",
        "authentication.mfa": "true",
        "device.compliant": "true",
        "risk.level": "low",
        "risk.state": "dismissed",
        "anomaly.score": "22",
        "anomaly.type": "AtypicalTravel",
        "anomaly.reason": "Sign-in from a new country for this account",
        "ExtendedProperties.Prior Sign-in Location": "New York, US",
        "ExtendedProperties.Current Sign-in Location": "Singapore, SG",
        "ExtendedProperties.Egress ASN": "AS9498 corporate VPN (sanctioned)",
        "ExtendedProperties.Device Compliance": "Compliant / Managed",
        "ExtendedProperties.Travel Record": "Approved — Sales offsite, Singapore",
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE BASELINE SIGN-IN — j.almeida's own normal Entra logon earlier that
    //    evening from New York, compliant/managed device, MFA satisfied. This is
    //    the reference point the "impossible travel" is measured against.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_uca_01_baseline_signin",
      ts: T(-40 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: victim.homeIp,
      geo: { country: "United States", city: "New York", latitude: 40.7128, longitude: -74.006 },
      severity: "informational",
      description:
        "A normal interactive Entra sign-in for j.almeida at 23:00 from New York (72.14.201.88), on his compliant, managed Windows workstation with MFA satisfied — his usual session.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "3b8e1c04-77a2-4d19-9c53-0a1e6f27b481",
        "azure.signinlogs.properties.createdDateTime": T(-40 * MIN),
        "azure.signinlogs.properties.userPrincipalName": victim.email,
        "azure.signinlogs.properties.userDisplayName": victim.name,
        "azure.signinlogs.properties.userId": victim.userId,
        "azure.signinlogs.properties.sessionId": "0d21b7a9-4e6c-41f8-90a3-2c5b8e14d7a2",
        "azure.signinlogs.properties.appDisplayName": "Office 365",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": true,
        "azure.signinlogs.properties.ipAddress": victim.homeIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 6128,
        "azure.signinlogs.properties.location.city": "New York",
        "azure.signinlogs.properties.location.state": "New York",
        "azure.signinlogs.properties.location.countryOrRegion": "US",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 40.7128,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": -74.006,
        "azure.signinlogs.properties.deviceDetail.displayName": "FIN-LT-Almeida",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 11",
        "azure.signinlogs.properties.deviceDetail.browser": "Edge 128.0",
        "azure.signinlogs.properties.deviceDetail.isCompliant": true,
        "azure.signinlogs.properties.deviceDetail.isManaged": true,
        "azure.signinlogs.properties.deviceDetail.trustType": "Azure AD joined",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.resultType": "0",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE ATYPICAL SIGN-IN — the same account, minutes later, from Sofia over
    //    a hosting ASN, on an unmanaged/non-compliant device, and MFA is NOT
    //    prompted: the requirement is satisfied single-factor because a session
    //    token was replayed. Valid Accounts (T1078); the enabling technique is
    //    the stolen web-session cookie recorded separately.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_uca_02_atypical_signin",
      ts: T(0),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: attackerIp,
      geo: { country: "Bulgaria", city: "Sofia", latitude: 42.6977, longitude: 23.3219 },
      severity: "high",
      mitre_technique: "T1078",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "A second Entra sign-in for j.almeida arrived at 23:40 from 45.135.232.71 in Sofia, Bulgaria (AS200651, a hosting provider), on an unmanaged device — and the MFA requirement was met single-factor, satisfied by a claim already in the presented token.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "e91c7f52-3d84-4a6b-b210-6c8f0a91d374",
        "azure.signinlogs.properties.createdDateTime": T(0),
        "azure.signinlogs.properties.userPrincipalName": victim.email,
        "azure.signinlogs.properties.userDisplayName": victim.name,
        "azure.signinlogs.properties.userId": victim.userId,
        "azure.signinlogs.properties.sessionId": hostileSession,
        "azure.signinlogs.properties.appDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": false,
        "azure.signinlogs.properties.ipAddress": attackerIp,
        "azure.signinlogs.properties.autonomousSystemNumber": attackerAsn,
        "azure.signinlogs.properties.location.city": "Sofia",
        "azure.signinlogs.properties.location.state": "Sofia-grad",
        "azure.signinlogs.properties.location.countryOrRegion": "BG",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 42.6977,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": 23.3219,
        "azure.signinlogs.properties.deviceDetail.deviceId": "",
        "azure.signinlogs.properties.deviceDetail.displayName": "",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 10",
        "azure.signinlogs.properties.deviceDetail.browser": "Chrome 127.0",
        "azure.signinlogs.properties.deviceDetail.isCompliant": false,
        "azure.signinlogs.properties.deviceDetail.isManaged": false,
        "azure.signinlogs.properties.deviceDetail.trustType": "",
        "azure.signinlogs.properties.userAgent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "azure.signinlogs.properties.authenticationRequirement": "singleFactorAuthentication",
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "high",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.riskState": "atRisk",
        "azure.signinlogs.properties.riskEventTypes_v2": ["unfamiliarFeatures", "anonymizedIPAddress"],
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "primaryRefreshToken",
        "azure.signinlogs.resultType": "0",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. UEBA ANOMALY #1 — Sentinel joins the two sign-ins and raises an
    //    impossible-travel / unfamiliar-properties anomaly. This is one of the
    //    inputs that will accumulate into the entity risk score. (T1078)
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_uca_03_ueba_impossible_travel",
      ts: T(3 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1078",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "Sentinel joined the 23:00 New York sign-in and the 23:40 Sofia sign-in for j.almeida and raised an impossible-travel anomaly with unfamiliar sign-in properties: ~7,900 km in 40 minutes.",
      raw: {
        "AlertName": "Impossible travel to an atypical location",
        "AlertSeverity": "High",
        "ImpossibleTravelActivity": "true",
        "UnfamiliarSignInProperties": "true",
        "entity.name": victim.sam,
        "entity.type": "user",
        "user.name": `NEXACORP\\${victim.sam}`,
        "user.email": victim.email,
        "source.ip": attackerIp,
        "source.geo.country_name": "Bulgaria",
        "anomaly.type": "ImpossibleTravel",
        "anomaly.score": "78",
        "anomaly.reason": "Two sign-ins from distant locations within an impossible window",
        "ExtendedProperties.Prior Sign-in Time": T(-40 * MIN),
        "ExtendedProperties.Prior Sign-in Location": "New York, US",
        "ExtendedProperties.Current Sign-in Time": T(0),
        "ExtendedProperties.Current Sign-in Location": "Sofia, BG",
        "ExtendedProperties.Distance (km)": 7900,
        "ExtendedProperties.Elapsed Minutes": 40,
        "ExtendedProperties.Egress ASN": "AS200651 hosting provider (unmanaged device)",
        "ExtendedProperties.Linked Sign-in IDs": ["evt_uca_01_baseline_signin", "evt_uca_02_atypical_signin"],
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. UEBA ANOMALY #2 — the token angle. The Sofia session presented a
    //    pre-existing refresh token from an anonymized IP, so no MFA prompt was
    //    raised: a stolen web-session cookie replayed (T1539).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_uca_04_ueba_token_replay",
      ts: T(4 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1539",
      mitre_tactic: "Credential Access",
      incident_id: INCIDENT,
      description:
        "Sentinel flagged the Sofia session for j.almeida as an anonymized-IP sign-in that met MFA with a claim already in the token — the session was authenticated by a presented cookie, not a fresh credential prompt.",
      raw: {
        "AlertName": "Sign-in from an anonymous IP address",
        "AlertSeverity": "High",
        "AnonymousIPAccess": "true",
        "RiskySignIn": "true",
        "entity.name": victim.sam,
        "entity.type": "user",
        "user.name": `NEXACORP\\${victim.sam}`,
        "user.email": victim.email,
        "source.ip": attackerIp,
        "source.geo.country_name": "Bulgaria",
        "authentication.status": "success",
        "authentication.mfa": "false",
        "session.id": hostileSession,
        "anomaly.type": "AnonymousIPAddress",
        "anomaly.score": "74",
        "anomaly.confidence": "high",
        "anomaly.reason": "Session presented a pre-existing refresh token from an anonymized IP",
        "ExtendedProperties.Incoming Token Type": "primaryRefreshToken",
        "ExtendedProperties.Authentication Requirement": "singleFactorAuthentication",
        "ExtendedProperties.Session ID": hostileSession,
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE MASS DOWNLOAD — from the hostile session, OneDrive/SharePoint logs
    //    a burst of FileSyncDownloadedFull far above this account's norm. This
    //    is the primary telemetry behind the MassDownloadActivity anomaly.
    //    Data from Information Repositories: SharePoint (T1213.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_uca_05_mass_download",
      ts: T(12 * MIN),
      source: "o365",
      vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_storage_access",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1213.002",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "Beginning 23:52, the j.almeida OneDrive/SharePoint recorded 340+ FileSyncDownloadedFull operations from the Finance site in about six minutes, from 45.135.232.71 — a representative record from a burst far above his usual download volume.",
      file: { name: marqueeFile, path: `/sites/Finance/Shared Documents/Budget/${marqueeFile}`, extension: "xlsx", size: 8_734_208, sha256: marqueeFileHash },
      raw: {
        "data.office365.Operation": "FileSyncDownloadedFull",
        "data.office365.Workload": "OneDrive",
        "data.office365.RecordType": "6",
        "data.office365.UserId": victim.email,
        "data.office365.UserType": "Regular",
        "data.office365.ClientIP": attackerIp,
        "data.office365.SessionId": hostileSession,
        "data.office365.SiteUrl": "https://nexacorp.sharepoint.com/sites/Finance/",
        "data.office365.SourceRelativeUrl": "Shared Documents/Budget",
        "data.office365.SourceFileName": marqueeFile,
        "data.office365.SourceFileExtension": "xlsx",
        "data.office365.ObjectId": `https://nexacorp.sharepoint.com/sites/Finance/Shared Documents/Budget/${marqueeFile}`,
        "data.office365.FileHashSha256": marqueeFileHash,
        "data.office365.FileSizeBytes": "8734208",
        "data.office365.UserAgent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "data.office365.ResultStatus": "Succeeded",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE FORWARDING RULE — the hostile session creates an Exchange inbox
    //    rule that ships finance mail to an external address and hides the
    //    originals. Email Collection: Email Forwarding Rule (T1114.003).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_uca_06_inbox_rule",
      ts: T(18 * MIN),
      source: "o365",
      vendor: "Microsoft 365 Unified Audit Log",
      event_type: "account_modify",
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "high",
      mitre_technique: "T1114.003",
      mitre_tactic: "Collection",
      incident_id: INCIDENT,
      description:
        "An inbox rule named \"Ext backup\" was created on the j.almeida mailbox from 45.135.232.71: mail whose subject or body mentions finance keywords is forwarded to acct.archive.9y@gmail.com and the originals moved to RSS Subscriptions and marked read.",
      raw: {
        "data.office365.Operation": "New-InboxRule",
        "data.office365.Workload": "Exchange",
        "data.office365.RecordType": "1",
        "data.office365.UserId": victim.email,
        "data.office365.UserType": "Regular",
        "data.office365.ObjectId": "nexacorp.com/Users/Jordan Almeida/Ext backup",
        "data.office365.ClientIPAddress": attackerIp,
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "data.office365.SessionId": hostileSession,
        "data.office365.ExternalAccess": "false",
        "data.office365.Parameters.Name": "Ext backup",
        "data.office365.Parameters.SubjectOrBodyContainsWords": "invoice;wire;IBAN;remittance;budget",
        "data.office365.Parameters.ForwardAsAttachmentTo": dropAddress,
        "data.office365.Parameters.MoveToFolder": "RSS Subscriptions",
        "data.office365.Parameters.MarkAsRead": "True",
        "data.office365.Parameters.StopProcessingRules": "True",
        "data.office365.ResultStatus": "True",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. THE ENTITY RISK SCORE — the case-opening detection. Sentinel UEBA rolls
    //    the impossible travel, the anonymous-IP token session, the mass download
    //    and the new inbox rule into ONE risky-user score. This is where the hunt
    //    begins: an anomaly-driven detection, not a signature. is_detection +
    //    edr_scope "non_edr" (control-plane only — no host process to walk).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_uca_07_entity_risk_score",
      ts: T(25 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "risk_score_change",
      user_email: victim.email,
      src_ip: attackerIp,
      severity: "critical",
      mitre_technique: "T1078",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      is_detection: true,   // the anomaly-driven detection that opens the case
      edr_scope: "non_edr", // control-plane only — identity/SaaS, no EDR to pivot to
      description:
        "Sentinel UEBA raised j.almeida to a high entity risk score, correlating four behaviours in 25 minutes: an impossible-travel sign-in, an anonymous-IP token session, a download burst from the Finance site, and a new mailbox forwarding rule.",
      raw: {
        "AlertName": "User risk level increased to High",
        "AlertSeverity": "High",
        "RiskyUser": "true",
        "ImpossibleTravelActivity": "true",
        "AnonymousIPAccess": "true",
        "MassDownloadActivity": "true",
        "SuspiciousInboxRule": "true",
        "UnfamiliarSignInProperties": "true",
        "entity.name": victim.sam,
        "entity.type": "user",
        "user.name": `NEXACORP\\${victim.sam}`,
        "user.email": victim.email,
        "user.department": victim.dept,
        "user.title": victim.title,
        "source.ip": attackerIp,
        "behavior.name": "account_takeover_pattern",
        "behavior.category": "identity",
        "behavior.score": "212",
        "anomaly.score": "94",
        "risk.level": "high",
        "risk.score": "94",
        "risk.state": "atRisk",
        "threat.technique.id": "T1078",
        "threat.tactic.name": "Initial Access",
        "ExtendedProperties.Correlated Signals": [
          "Impossible travel New York -> Sofia (evt_uca_03_ueba_impossible_travel)",
          "Anonymous-IP token session (evt_uca_04_ueba_token_replay)",
          "340+ file download burst from Finance site (evt_uca_05_mass_download)",
          "New forwarding inbox rule to " + dropAddress + " (evt_uca_06_inbox_rule)",
        ],
        "ExtendedProperties.Usual Sign-in Country": "United States",
        "ExtendedProperties.Usual Download Volume": "~15 files/day",
        "ExtendedProperties.Score Window": "25 minutes",
        "event.action": "risk-score-update",
        "event.outcome": "alerted",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 45.135.232.71 — the hostile session's hosting-ASN origin
      first_seen: T(0),
      last_seen: T(25 * MIN),
      reputation: "malicious",
      tags: ["session-origin", "hosting-asn", "internal-actor-none"],
    },
    {
      type: "user",
      value: victim.sam, // j.almeida — the compromised account
      first_seen: T(-40 * MIN),
      last_seen: T(25 * MIN),
      reputation: "suspicious",
      tags: ["compromised-account", "finance", "high-risk-entity"],
    },
    {
      type: "email",
      value: victim.email, // j.almeida@nexacorp.com — the compromised mailbox
      first_seen: T(-40 * MIN),
      last_seen: T(25 * MIN),
      reputation: "suspicious",
      tags: ["compromised-mailbox", "finance"],
    },
    {
      type: "email",
      value: dropAddress, // the external forwarding destination
      first_seen: T(18 * MIN),
      last_seen: T(25 * MIN),
      reputation: "malicious",
      tags: ["external-forward", "rule-destination"],
    },
    {
      type: "sha256",
      value: marqueeFileHash, // a representative downloaded finance workbook
      first_seen: T(12 * MIN),
      last_seen: T(12 * MIN),
      reputation: "unknown",
      tags: ["finance-data", "downloaded-file"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Unlike every prior case, this investigation does not open with a signature alert. What is the triggering detection here, and what kind of signal is it?",
      hint: "Look at which event carries is_detection. Nothing said 'malware' or 'blocked' — one telemetry source raised a number from correlated behaviours.",
      kind: "single",
      options: [
        { value: "ueba_risk_score", label: "evt_uca_07_entity_risk_score — a behaviour-analytics entity score that climbed to High from multiple weak indicators joined together; the aggregate itself is the detection, not any single line" },
        { value: "firewall_block", label: "A perimeter firewall denied the Sofia IP outbound, and that single blocked connection is what opened the ticket for the analyst to work through" },
        { value: "edr_malware", label: "An EDR endpoint detection flagged a malicious process on j.almeida's laptop, which is the root of the case" },
        { value: "dlp_block", label: "A DLP policy blocked the file download to the external session, and the blocked action raised the alert" },
      ],
      answer: "ueba_risk_score",
      xp: 55,
      explanation:
        "This is the pack's whole point: an anomaly-driven hunt. The detection is evt_uca_07, a Sentinel UEBA risky-user score that reached High by rolling four behaviours — impossible travel, an anonymous-IP token session, a download burst and a new inbox rule — into one number. No signature fired: there is no firewall block (b), no EDR host detection (c) — edr_scope is non_edr, there is no endpoint process to walk — and nothing was DLP-blocked (d). The analyst starts from the score and pivots DOWN into the primary telemetry to confirm or dismiss it.",
    },
    {
      id: "q2",
      prompt:
        "You pivot from the score into the two Entra sign-ins (evt_uca_01 baseline, evt_uca_02 atypical). Which combination of sign-in fields confirms the Sofia session is a compromise rather than a benign anomaly?",
      hint: "Compare autonomousSystemNumber, deviceDetail.isManaged/isCompliant, and authenticationRequirement between the New York and Sofia sign-ins.",
      kind: "single",
      options: [
        { value: "asn_device_token", label: "The Sofia sign-in is from a hosting ASN (AS200651) on an unmanaged, non-compliant device, and MFA was met single-factor by a token claim — while the baseline is a corporate ASN, a compliant managed device, and a full MFA requirement" },
        { value: "resulttype", label: "The Sofia sign-in has resultType 0, and any sign-in with resultType 0 is by definition a compromised logon" },
        { value: "country_alone", label: "The Sofia sign-in is from Bulgaria and the baseline from the US — a sign-in from a different country than the baseline is on its own proof of compromise" },
        { value: "appdisplayname", label: "The appDisplayName differs between the two sign-ins, and a change of application between logons is what identifies account takeover" },
      ],
      answer: "asn_device_token",
      xp: 60,
      explanation:
        "The verdict comes from the primary telemetry, read against the baseline. The Sofia sign-in (evt_uca_02) originates from a hosting/VPS ASN, on a device that is neither managed nor compliant, and its authenticationRequirement is singleFactorAuthentication with an incoming primaryRefreshToken — MFA was never re-prompted because a session token was replayed. The baseline (evt_uca_01) is the opposite on every one of those fields. (b) over-reads a single field: resultType 0 just means the sign-in succeeded — both did. (c) is exactly the benign-anomaly trap the control disproves: a new country alone is not a verdict. (d) is noise. The compromise is the ASN + unmanaged device + token-satisfied MFA together.",
    },
    {
      id: "q3",
      prompt:
        "evt_uca_00 shows r.laurent tripping the SAME ImpossibleTravelActivity anomaly the same night, yet it is benign. Reading it against j.almeida, what actually separates a real compromise from a false anomaly here?",
      hint: "If the anomaly score decided it, both would be compromises. Compare corroboration: device compliance, egress ASN, MFA, and an approved travel record.",
      kind: "single",
      options: [
        { value: "corroboration", label: "Corroboration: r.laurent's far-away sign-in is over the sanctioned corporate-VPN ASN, on a compliant managed device, with MFA satisfied and an approved travel record — j.almeida's has none of that, arriving from a hosting ASN on an unmanaged device with a replayed token" },
        { value: "score_decides", label: "The score decides it — r.laurent's anomaly score is lower than j.almeida's, so score magnitude alone cleanly separates benign anomalies from compromises" },
        { value: "same_verdict", label: "Nothing separates them — both are impossible-travel sign-ins the same night, so both should be treated as confirmed account compromises" },
        { value: "flagged_or_not", label: "Whether UEBA flagged it — only j.almeida was flagged by Sentinel, so the presence of the anomaly alert alone distinguishes the two with no further context" },
      ],
      answer: "corroboration",
      xp: 60,
      explanation:
        "This is the core skill: a UEBA score is a reason to look, not a verdict. Both users trip ImpossibleTravelActivity, so the anomaly itself cannot decide — that rules out (b) and (d), and (d) is also factually wrong since BOTH were flagged. The difference is corroboration in the underlying sign-in: r.laurent egresses over the known corporate-VPN ASN, on a compliant managed device, with MFA satisfied and an approved-travel record, so the anomaly resolves benign (risk.state dismissed). j.almeida has none of that — hosting ASN, unmanaged device, single-factor token session — so his resolves to compromise. (c) is the failure the control exists to prevent: treating every high score as an attack.",
    },
    {
      id: "q4",
      prompt:
        "Two of the behaviours in the score are the attacker acting on the mailbox and the data. Which event is the persistence/collection foothold that would keep feeding the attacker AFTER the session ends?",
      hint: "One event copies files out now; the other quietly re-routes future mail. Which one survives a password reset if left in place?",
      kind: "single",
      options: [
        { value: "inbox_rule", label: "evt_uca_06_inbox_rule — the New-InboxRule that forwards finance mail to an external address and hides the originals, which keeps exfiltrating new mail until the rule is removed" },
        { value: "mass_download", label: "evt_uca_05_mass_download — the 340+ file OneDrive download burst, which is a one-time pull of files already present, not a mechanism for future mail" },
        { value: "atypical_signin", label: "evt_uca_02_atypical_signin — the Sofia sign-in, which only establishes the session and does nothing to the mailbox itself" },
        { value: "token_replay", label: "evt_uca_04_ueba_token_replay — the anonymous-IP token anomaly, which is a detection signal, not an action the attacker took on the mailbox" },
      ],
      answer: "inbox_rule",
      xp: 55,
      explanation:
        "The forwarding rule (evt_uca_06, T1114.003) is the durable foothold: it auto-forwards mail matching finance keywords to an external Gmail address and moves the originals to RSS Subscriptions marked read, so it keeps leaking new correspondence and stays invisible to the user — and it survives a password reset if not explicitly removed. The mass download (b) is collection, but a one-time pull of existing files (T1213.002). The sign-in (c) only establishes access. The token anomaly (d) is a Sentinel detection signal, not an attacker action. Remediation must explicitly delete the rule, not just reset the credential.",
    },
    {
      id: "q5",
      prompt:
        "You are writing the verdict and the response. The evidence is a token-replay sign-in, a download burst and a forwarding rule, all under j.almeida's valid account. How should this be classified and handled?",
      kind: "single",
      options: [
        { value: "compromise_revoke", label: "Confirmed account compromise — revoke j.almeida's sessions/refresh tokens, force a password reset with MFA re-registration, delete the forwarding rule, and review what was downloaded and forwarded; the valid-account access is a takeover, not benign travel" },
        { value: "benign_travel", label: "Benign — the sign-in is just impossible-travel from a trip, every action used a valid account, and the files are ones his role can access, so close it with no action" },
        { value: "reset_only", label: "Reset j.almeida's password and consider it done — a new password invalidates the session, so no other step (rule removal, token revocation) is needed" },
        { value: "wait_for_malware", label: "Hold — without malware or a blocked action there is no confirmed intrusion, so wait for an EDR signal before treating it as an incident" },
      ],
      answer: "compromise_revoke",
      xp: 65,
      explanation:
        "The primary telemetry confirms takeover: a token-replayed sign-in from a hosting ASN on an unmanaged device (T1078/T1539), a 340+ file download burst (T1213.002), and a forwarding rule to an external address (T1114.003) — all inside 25 minutes. Response must REVOKE the stolen session and refresh tokens (a password reset alone does not kill an already-issued token, so (c) is insufficient), force a reset with MFA re-registration, delete the inbox rule, and scope what left. (b) is the benign-anomaly trap the control disproves — the corroboration that cleared r.laurent is absent here. (d) waits for a host signal that will never come in a cloud identity compromise. attack_kind is account_compromise, escalate.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Behavioral Risk First — a UEBA-led Account-Compromise Hunt",
    threat_actor: "External actor operating a stolen session (cloud identity takeover — no host foothold)",
    attack_kind: "account_compromise",
    briefing:
      "Microsoft Sentinel UEBA raised the risk score of j.almeida (Finance Manager) to High overnight after correlating several sign-in and mailbox anomalies. There is no malware verdict and nothing was blocked — only a score. Pivot from the score into the underlying Entra and O365 telemetry and decide whether the account is compromised or the anomalies are benign.",
    narrative: `This is the SOC's first anomaly-driven case: it opens not with a signature alert but with a number. At 00:05 Microsoft Sentinel UEBA raised Jordan Almeida, a Finance Manager, to a High entity risk score — a value built by correlating four behaviours from the preceding half hour, none of them alarming on its own.

At 23:00 Almeida had signed in normally from New York, on his compliant, managed workstation, MFA satisfied — the baseline. At 23:40 a second Entra sign-in for the same account arrived from 45.135.232.71 in Sofia, Bulgaria, on a hosting-provider ASN (AS200651), from an unmanaged device — and the MFA requirement was met single-factor, satisfied by a claim already inside a presented token. No password was typed and no push was sent: a stolen session cookie was replayed. Sentinel joined the two sign-ins into an impossible-travel anomaly (~7,900 km in 40 minutes) and separately flagged the Sofia session as an anonymous-IP token replay.

From that session the attacker acted. At 23:52 the Finance SharePoint/OneDrive logged a burst of 340+ FileSyncDownloadedFull operations — far above Almeida's ~15-files-a-day norm. At 23:58 a new Exchange inbox rule, "Ext backup", was created: mail mentioning invoice, wire, IBAN, remittance or budget is forwarded to acct.archive.9y@gmail.com and the originals moved to RSS Subscriptions and marked read — a quiet, durable channel that survives a password reset. At 00:05 UEBA rolled all four signals into the risky-user score that opened this ticket.

The instructive comparison is Renée Laurent, a Sales director, who tripped the SAME impossible-travel anomaly the same night — New York to Singapore. But her far-away sign-in came over the sanctioned corporate-VPN ASN, on a compliant managed device, with MFA satisfied and an approved travel record on file, so her anomaly resolves benign. Same score-shape, opposite verdict. The lesson of a UEBA hunt is exactly that: a high score is a reason to look, and the verdict is reached from the primary sign-in and audit telemetry underneath it — not from the alert title.`,
    learning_objectives: [
      "Run an anomaly-driven (UEBA-led) investigation: start from a Sentinel entity risk score built by correlation, then pivot DOWN into the primary Entra and O365 telemetry to confirm or dismiss it",
      "Confirm a compromised sign-in (T1078) from Entra fields — hosting ASN, unmanaged/non-compliant device, and an MFA requirement satisfied single-factor by a replayed session token (T1539) — read against the account's own baseline sign-in",
      "Recognise a mass download from a cloud information repository (T1213.002) and a malicious mailbox forwarding rule (T1114.003) as the primary telemetry behind MassDownloadActivity and SuspiciousInboxRule anomalies",
      "Distinguish a real account compromise from a benign UEBA anomaly using corroboration (device compliance, egress ASN, MFA, approved-travel context) rather than the anomaly score alone",
      "Scope response for a cloud identity takeover: revoke sessions and refresh tokens, reset with MFA re-registration, delete the forwarding rule, and review what was downloaded and forwarded",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-3 * HOUR), phase: "Context", action: "Benign control — r.laurent trips ImpossibleTravel but is corroborated (corporate VPN, compliant device, MFA, approved travel)" },
      { ts: T(-40 * MIN), phase: "Baseline", action: `Normal Entra sign-in for ${victim.sam} from New York — compliant managed device, MFA satisfied` },
      { ts: T(0), phase: "Initial Access", action: `Atypical Entra sign-in for ${victim.sam} from Sofia (AS200651), unmanaged device, token-satisfied MFA (T1078)` },
      { ts: T(3 * MIN), phase: "Detection", action: "Sentinel raises impossible-travel + unfamiliar-properties anomaly" },
      { ts: T(4 * MIN), phase: "Credential Access", action: "Sentinel flags the Sofia session as an anonymous-IP replayed-token sign-in (T1539)" },
      { ts: T(12 * MIN), phase: "Collection", action: "340+ FileSyncDownloadedFull from the Finance site — download burst above baseline (T1213.002)" },
      { ts: T(18 * MIN), phase: "Collection", action: `New Exchange inbox rule forwards finance mail to ${dropAddress} and hides originals (T1114.003)` },
      { ts: T(25 * MIN), phase: "Detection", action: "Sentinel UEBA rolls all four behaviours into a High risky-user score — the case opens" },
    ],
    questions,
  };
}
