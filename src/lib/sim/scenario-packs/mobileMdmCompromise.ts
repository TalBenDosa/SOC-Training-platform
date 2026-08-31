/**
 * Scenario pack: "Mobile in the Blind Spot — an Intune-Managed Phone Goes Rogue"
 *
 * INTERMEDIATE tier. The platform is heavy on endpoint, identity and cloud but
 * thin on MOBILE — this pack fills that blind spot. A corporate-enrolled Android
 * phone (Microsoft Intune / Entra) belonging to a field sales lead is compromised:
 * a mobile-phishing (smishing) text lures the user to sideload an app outside the
 * managed store. On-device, that app abuses an elevation weakness to root the
 * handset. Microsoft Defender for Endpoint (the Intune Mobile-Threat-Defense
 * connector) reports the device as rooted, Intune flips the device's compliance
 * state to non-compliant — and then the SAME phone, now non-compliant, signs in to
 * corporate mail and file storage using its valid Entra session.
 *
 * The teaching spine is deliberately mobile-shaped:
 *   (1) the ORIGIN is a control-plane pair — an Intune Mobile-Threat-Defense signal
 *       (rooted device) plus the compliance-state flip it drives — NOT a host EDR
 *       process tree (there is no mobile endpoint console to walk here);
 *   (2) the IMPACT is the corporate-resource access from that non-compliant device,
 *       visible only as Entra sign-ins into Exchange Online and SharePoint Online
 *       whose deviceDetail.isCompliant is false yet whose conditionalAccessStatus is
 *       success — a Conditional-Access GAP the analyst has to name.
 *
 * A BENIGN CONTROL is included and is the pedagogical crux: a second managed phone
 * trips the SAME "device went non-compliant" event the same night — but for a
 * pending OS security update that self-remediates, with no threat signal and no
 * sideloaded app. Same device-compliance event shape, opposite verdict. Not every
 * non-compliant phone is a compromise.
 *
 * MITRE (Mobile + Enterprise, pairings verified against current ATT&CK):
 *   T1660 Phishing (Mobile) — Initial Access — the smishing-delivered sideload
 *   T1626 Abuse Elevation Control Mechanism (Mobile) — Privilege Escalation — rooting
 *   T1078.004 Valid Accounts: Cloud Accounts (Enterprise) — the corporate access
 *
 * SOURCES (fields registry-valid for the declared vendor): Microsoft Intune (app
 * inventory / install state, Mobile-Threat-Defense signal, device compliance state)
 * and Microsoft Entra ID / Azure AD (the mobile sign-ins and their Conditional-Access
 * evaluation). This pack fits the Microsoft-365 / Entra company profiles
 * (nexacorp, medcore, globallogis).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildMobileMdmCompromiseScenario(
  scenarioId = "mobile-mdm-compromise-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T21:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // One incident — the whole case is a single mobile-compromise chain.
  const INCIDENT = "inc:mmc:1";

  // The compromised user and his corporate-enrolled Android phone.
  const victim = {
    upn: "d.okafor@nexacorp.com",
    sam: "d.okafor",
    name: "Daniel Okafor",
    title: "Regional Sales Lead",
    dept: "Sales",
    userId: "b41d9a72-5e08-4c17-9f36-2ad7c0e18b45",
  };
  const device = {
    name: "AND-Okafor-Pixel7",
    id: "7c2f0ae4-91b8-46d3-a5e1-08db3f27c604",
    platform: "Android",
    osVersion: "14.0",
    homeIp: "104.28.51.19",     // his usual US mobile-carrier egress (baseline)
  };

  // The foreign hosting/VPS egress the compromised app relays the session through.
  const sessionIp = "45.148.10.62";       // Amsterdam, NL — hosting ASN
  const hostileSession = "a83c0f16-7d24-4b9e-8c51-6f0a29d4e7b1";

  // The sideloaded (non-managed-store) application.
  const rogueApp = {
    display: "SalesRoute Tracker",
    pkg: "com.salesroute.tracker",
    publisher: "unknown",
    version: "3.2.0",
    id: "e07b5c92-3a41-4d68-b019-7c2e6f84a5d3",
  };

  // The BENIGN CONTROL: a second managed phone that trips the same
  // "device went non-compliant" event the same night — a pending OS update.
  const benign = {
    upn: "s.mendel@nexacorp.com",
    sam: "s.mendel",
    deviceName: "AND-Mendel-GalaxyS23",
    deviceId: "3fa9c108-62d7-4e55-b8a0-1c9e5d720f38",
  };

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a managed phone goes non-compliant for a benign,
    //    self-remediating reason: a pending OS security update. Same device-
    //    compliance event shape as the incident, opposite verdict. No threat
    //    signal, no sideloaded app; compliance returns on its own after update.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_mmc_00_benign_compliance",
      ts: T(-2 * HOUR),
      source: "cloud_azure",
      vendor: "Microsoft Intune",
      event_type: "risk_score_change",
      user_email: benign.upn,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "Benign. s.mendel's managed Galaxy went non-compliant only because a required OS security patch was pending; there is no Mobile-Threat-Defense signal on it, no sideloaded app, and the device returned to compliant after the update installed on its next sync. Same 'device went non-compliant' record as the incident phone — the difference is the reason and the presence of a threat signal, not the compliance flip itself.",
      description:
        "Intune marked s.mendel's managed phone AND-Mendel-GalaxyS23 non-compliant against the OS-version policy, with a pending security update noted; it returned to compliant on the next sync.",
      raw: {
        "intune.category": "Compliance",
        "intune.activityType": "DeviceComplianceStateChanged",
        "intune.activityOperationType": "Patch",
        "intune.activityResult": "Success",
        "intune.activityDateTime": T(-2 * HOUR),
        "intune.actor.applicationDisplayName": "Microsoft Intune",
        "intune.deviceName": benign.deviceName,
        "intune.deviceId": benign.deviceId,
        "intune.userPrincipalName": benign.upn,
        "intune.platform": "Android",
        "intune.osVersion": "13.0",
        "intune.complianceState": "noncompliant",
        "intune.report": "Compliance policy: Minimum OS version — Update pending",
        "intune.errorCode": "0",
        "intune.lastSyncDateTime": T(-2 * HOUR),
        "rule.id": "92310",
        "rule.level": "3",
        "rule.description": "Microsoft Intune: Managed device reported non-compliant",
        "rule.groups": ["intune", "mdm", "compliance"],
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. BASELINE — the victim's normal Entra sign-in earlier that evening from
    //    the SAME phone while it was still healthy: compliant, managed, MFA
    //    satisfied, from his usual US carrier IP. The reference point.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_mmc_01_baseline_signin",
      ts: T(-40 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      user_email: victim.upn,
      user_title: victim.title,
      src_ip: device.homeIp,
      geo: { country: "United States", city: "Chicago", latitude: 41.8781, longitude: -87.6298 },
      severity: "informational",
      description:
        "A normal Entra sign-in for d.okafor at 20:20 from Chicago (104.28.51.19) on his enrolled Android phone — compliant, managed, MFA satisfied, into the Outlook mobile app.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "1a4f9c73-0b28-4e61-8d92-3f07a6c15be0",
        "azure.signinlogs.properties.createdDateTime": T(-40 * MIN),
        "azure.signinlogs.properties.userPrincipalName": victim.upn,
        "azure.signinlogs.properties.userDisplayName": victim.name,
        "azure.signinlogs.properties.userId": victim.userId,
        "azure.signinlogs.properties.appDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.clientAppUsed": "Mobile Apps and Desktop clients",
        "azure.signinlogs.properties.isInteractive": true,
        "azure.signinlogs.properties.ipAddress": device.homeIp,
        "azure.signinlogs.properties.location.city": "Chicago",
        "azure.signinlogs.properties.location.state": "Illinois",
        "azure.signinlogs.properties.location.countryOrRegion": "US",
        "azure.signinlogs.properties.deviceDetail.deviceId": device.id,
        "azure.signinlogs.properties.deviceDetail.displayName": device.name,
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Android 14.0",
        "azure.signinlogs.properties.deviceDetail.browser": "Outlook Mobile",
        "azure.signinlogs.properties.deviceDetail.isCompliant": true,
        "azure.signinlogs.properties.deviceDetail.isManaged": true,
        "azure.signinlogs.properties.deviceDetail.trustType": "Azure AD registered",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.resultType": "0",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE SIDELOAD — an app that did not come from the managed store appears
    //    on the phone. Publisher unknown, install source outside Intune's own
    //    app catalog. Delivered by a smishing text (T1660). This is the entry.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_mmc_02_app_sideload",
      ts: T(0),
      source: "cloud_azure",
      vendor: "Microsoft Intune",
      event_type: "cloud_api_call",
      user_email: victim.upn,
      user_title: victim.title,
      severity: "medium",
      mitre_technique: "T1660",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "Intune app inventory for AND-Okafor-Pixel7 recorded a new app, \"SalesRoute Tracker\" (com.salesroute.tracker), publisher unknown, installState installed — an app that is not in the managed app catalog.",
      raw: {
        "intune.report": "DiscoveredApps",
        "intune.category": "Application",
        "intune.appDisplayName": rogueApp.display,
        "intune.appId": rogueApp.id,
        "intune.appVersion": rogueApp.version,
        "intune.deviceName": device.name,
        "intune.deviceId": device.id,
        "intune.userPrincipalName": victim.upn,
        "intune.platform": "Android",
        "intune.osVersion": device.osVersion,
        "intune.installIntent": "available",
        "intune.installState": "installed",
        "intune.installStateDetail": "installedFromOutsideManagedApp",
        "intune.errorCode": "0",
        "intune.lastSyncDateTime": T(0),
        "mobileApp.id": rogueApp.id,
        "mobileApp.displayName": rogueApp.display,
        "mobileApp.displayVersion": rogueApp.version,
        "mobileApp.publisher": rogueApp.publisher,
        "mobileApp.detectionRules.fileOrFolderName": rogueApp.pkg,
        "rule.id": "92330",
        "rule.level": "6",
        "rule.description": "Microsoft Intune: Non-managed application discovered on device",
        "rule.groups": ["intune", "mdm", "application"],
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE THREAT SIGNAL — Microsoft Defender for Endpoint (the Intune Mobile-
    //    Threat-Defense connector) reports the phone as rooted. This is the
    //    case-opening detection: control-plane only (no mobile EDR console to
    //    walk), so is_detection + edr_scope "non_edr". Abuse of an elevation
    //    control to root the device (T1626).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_mmc_03_mtd_threat_signal",
      ts: T(6 * MIN),
      source: "cloud_azure",
      vendor: "Microsoft Intune",
      event_type: "risk_score_change",
      user_email: victim.upn,
      user_title: victim.title,
      severity: "critical",
      mitre_technique: "T1626",
      mitre_tactic: "Privilege Escalation",
      incident_id: INCIDENT,
      is_detection: true,   // the Mobile-Threat-Defense signal that opens the case
      edr_scope: "non_edr", // MDM / identity control-plane — no host process tree to pivot into
      description:
        "The Mobile-Threat-Defense connector (Defender for Endpoint) reported AND-Okafor-Pixel7 with a High device threat level and a rooted-device finding; Intune received the signal at 21:06.",
      raw: {
        "intune.category": "Compliance",
        "intune.activityType": "MobileThreatDefenseDeviceThreatLevel",
        "intune.activityOperationType": "Action",
        "intune.activityResult": "Success",
        "intune.activityDateTime": T(6 * MIN),
        "intune.actor.applicationDisplayName": "Microsoft Defender for Endpoint",
        "intune.deviceName": device.name,
        "intune.deviceId": device.id,
        "intune.userPrincipalName": victim.upn,
        "intune.platform": "Android",
        "intune.osVersion": device.osVersion,
        "intune.report": "DeviceThreatLevel: high; Finding: rooted device",
        "intune.errorCode": "0",
        "intune.lastSyncDateTime": T(6 * MIN),
        "rule.id": "92350",
        "rule.level": "12",
        "rule.description": "Microsoft Intune: Mobile Threat Defense reported high device threat level",
        "rule.groups": ["intune", "mdm", "mobile-threat-defense"],
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. THE COMPLIANCE FLIP — driven by the threat signal, Intune moves the
    //    device's compliance state to non-compliant. This is the state change
    //    Conditional Access is supposed to key off. An observation, no MITRE.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_mmc_04_compliance_flip",
      ts: T(7 * MIN),
      source: "cloud_azure",
      vendor: "Microsoft Intune",
      event_type: "risk_score_change",
      user_email: victim.upn,
      user_title: victim.title,
      severity: "high",
      incident_id: INCIDENT,
      description:
        "Intune flipped AND-Okafor-Pixel7 to complianceState noncompliant against the device-threat-level policy, following the High threat-level signal on the handset.",
      raw: {
        "intune.category": "Compliance",
        "intune.activityType": "DeviceComplianceStateChanged",
        "intune.activityOperationType": "Patch",
        "intune.activityResult": "Success",
        "intune.activityDateTime": T(7 * MIN),
        "intune.actor.applicationDisplayName": "Microsoft Intune",
        "intune.deviceName": device.name,
        "intune.deviceId": device.id,
        "intune.userPrincipalName": victim.upn,
        "intune.platform": "Android",
        "intune.osVersion": device.osVersion,
        "intune.complianceState": "noncompliant",
        "intune.report": "Compliance policy: Require the device to be at or under the machine risk score — Failed",
        "intune.errorCode": "0",
        "intune.lastSyncDateTime": T(7 * MIN),
        "rule.id": "92310",
        "rule.level": "10",
        "rule.description": "Microsoft Intune: Managed device reported non-compliant",
        "rule.groups": ["intune", "mdm", "compliance"],
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE IMPACT (mail) — the SAME phone, now non-compliant, signs in to
    //    Exchange Online through its valid Entra session, from a foreign hosting
    //    IP. deviceDetail.isCompliant is false, yet conditionalAccessStatus is
    //    success: the app was not covered by a require-compliant-device policy —
    //    a Conditional-Access gap. Valid Accounts: Cloud Accounts (T1078.004).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_mmc_05_mail_access_noncompliant",
      ts: T(14 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      user_email: victim.upn,
      user_title: victim.title,
      src_ip: sessionIp,
      geo: { country: "Netherlands", city: "Amsterdam", latitude: 52.3676, longitude: 4.9041 },
      severity: "critical",
      mitre_technique: "T1078.004",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "An Entra sign-in for d.okafor into Exchange Online at 21:14 from 45.148.10.62 (Amsterdam, NL), from device AND-Okafor-Pixel7 with deviceDetail.isCompliant false — yet conditionalAccessStatus success.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "9d51c4a8-6e02-4b73-90a1-7c8f0e263ad9",
        "azure.signinlogs.properties.createdDateTime": T(14 * MIN),
        "azure.signinlogs.properties.userPrincipalName": victim.upn,
        "azure.signinlogs.properties.userDisplayName": victim.name,
        "azure.signinlogs.properties.userId": victim.userId,
        "azure.signinlogs.properties.sessionId": hostileSession,
        "azure.signinlogs.properties.appDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.clientAppUsed": "Mobile Apps and Desktop clients",
        "azure.signinlogs.properties.isInteractive": false,
        "azure.signinlogs.properties.ipAddress": sessionIp,
        "azure.signinlogs.properties.location.city": "Amsterdam",
        "azure.signinlogs.properties.location.state": "North Holland",
        "azure.signinlogs.properties.location.countryOrRegion": "NL",
        "azure.signinlogs.properties.deviceDetail.deviceId": device.id,
        "azure.signinlogs.properties.deviceDetail.displayName": device.name,
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Android 14.0",
        "azure.signinlogs.properties.deviceDetail.browser": "Outlook Mobile",
        "azure.signinlogs.properties.deviceDetail.isCompliant": false,
        "azure.signinlogs.properties.deviceDetail.isManaged": true,
        "azure.signinlogs.properties.deviceDetail.trustType": "Azure AD registered",
        "azure.signinlogs.properties.authenticationRequirement": "singleFactorAuthentication",
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "high",
        "azure.signinlogs.properties.riskState": "atRisk",
        "azure.signinlogs.properties.riskEventTypes_v2": ["unfamiliarFeatures"],
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "primaryRefreshToken",
        "azure.signinlogs.resultType": "0",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE IMPACT (files) — the same non-compliant phone reaches SharePoint
    //    Online moments later on the same hostile session. Valid cloud account
    //    used to blend in and reach corporate data (T1078.004).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_mmc_06_sharepoint_access_noncompliant",
      ts: T(19 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      user_email: victim.upn,
      user_title: victim.title,
      src_ip: sessionIp,
      geo: { country: "Netherlands", city: "Amsterdam", latitude: 52.3676, longitude: 4.9041 },
      severity: "high",
      mitre_technique: "T1078.004",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        "A second Entra sign-in for d.okafor at 21:19 into SharePoint Online, same session and same 45.148.10.62 origin, from AND-Okafor-Pixel7 with deviceDetail.isCompliant false and conditionalAccessStatus success.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "2f7a09d3-1c64-4e88-b5f0-90a1c7e23648",
        "azure.signinlogs.properties.createdDateTime": T(19 * MIN),
        "azure.signinlogs.properties.userPrincipalName": victim.upn,
        "azure.signinlogs.properties.userDisplayName": victim.name,
        "azure.signinlogs.properties.userId": victim.userId,
        "azure.signinlogs.properties.sessionId": hostileSession,
        "azure.signinlogs.properties.appDisplayName": "Office 365 SharePoint Online",
        "azure.signinlogs.properties.clientAppUsed": "Mobile Apps and Desktop clients",
        "azure.signinlogs.properties.isInteractive": false,
        "azure.signinlogs.properties.ipAddress": sessionIp,
        "azure.signinlogs.properties.location.city": "Amsterdam",
        "azure.signinlogs.properties.location.state": "North Holland",
        "azure.signinlogs.properties.location.countryOrRegion": "NL",
        "azure.signinlogs.properties.deviceDetail.deviceId": device.id,
        "azure.signinlogs.properties.deviceDetail.displayName": device.name,
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Android 14.0",
        "azure.signinlogs.properties.deviceDetail.isCompliant": false,
        "azure.signinlogs.properties.deviceDetail.isManaged": true,
        "azure.signinlogs.properties.deviceDetail.trustType": "Azure AD registered",
        "azure.signinlogs.properties.authenticationRequirement": "singleFactorAuthentication",
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "high",
        "azure.signinlogs.properties.riskState": "atRisk",
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "primaryRefreshToken",
        "azure.signinlogs.resultType": "0",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "host",
      value: device.name, // AND-Okafor-Pixel7 — the compromised managed phone
      first_seen: T(0),
      last_seen: T(19 * MIN),
      reputation: "suspicious",
      tags: ["managed-device", "android", "affected"],
    },
    {
      type: "user",
      value: victim.sam, // d.okafor — the affected account
      first_seen: T(-40 * MIN),
      last_seen: T(19 * MIN),
      reputation: "suspicious",
      tags: ["regional-sales", "affected-account"],
    },
    {
      type: "email",
      value: victim.upn, // d.okafor@nexacorp.com — the mailbox reached from the device
      first_seen: T(-40 * MIN),
      last_seen: T(19 * MIN),
      reputation: "suspicious",
      tags: ["affected-mailbox", "sales"],
    },
    {
      type: "ip",
      value: sessionIp, // 45.148.10.62 — the foreign hosting session origin
      first_seen: T(14 * MIN),
      last_seen: T(19 * MIN),
      reputation: "malicious",
      tags: ["session-origin", "hosting-asn"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "This ticket did not open with a malware verdict on a laptop or a firewall block. Which event is the triggering detection, and what kind of source raised it?",
      hint: "Look at which event carries is_detection. Nothing walked a host process tree — one management-plane sensor reported the handset's health.",
      kind: "single",
      options: [
        { value: "mtd_signal", label: "evt_mmc_03_mtd_threat_signal — the Mobile-Threat-Defense connector reporting the phone rooted at a High device threat level: an MDM control-plane signal, not a host process detection" },
        { value: "edr_laptop", label: "An EDR agent on the user's laptop flagged a malicious binary in memory, and the case begins by walking that host's process tree back to its parent" },
        { value: "firewall_block", label: "A perimeter firewall denied the Amsterdam hosting IP on an outbound connection, and that single blocked session is what opened the ticket for triage" },
        { value: "dlp_block", label: "A DLP policy blocked a sensitive file leaving SharePoint Online toward the phone, and that blocked exfiltration attempt is what raised the alert" },
      ],
      answer: "mtd_signal",
      xp: 55,
      explanation:
        "The origin is a mobile control-plane signal. evt_mmc_03 carries is_detection: the Intune Mobile-Threat-Defense connector (Defender for Endpoint on Android) reported the handset at a High device threat level with a rooted finding. Its edr_scope is non_edr — there is no mobile endpoint console with a process tree to walk, so the case is worked from Intune and Entra telemetry. (b) is wrong: the affected asset is a phone, and no laptop EDR detection exists here. (c) and (d) describe signature/block events that never fired — nothing was blocked; the corporate access actually succeeded.",
    },
    {
      id: "q2",
      prompt:
        "You pivot to the two Exchange Online sign-ins (evt_mmc_01 baseline, evt_mmc_05 the later one). Which combination of Entra fields marks the later sign-in as the dangerous one?",
      hint: "Compare deviceDetail.isCompliant, the ipAddress / country, and conditionalAccessStatus between the 20:20 and 21:14 sign-ins.",
      kind: "single",
      options: [
        { value: "noncompliant_ca_gap", label: "It runs with deviceDetail.isCompliant false from a foreign hosting IP, yet its conditionalAccessStatus is still success — access allowed off a device the MDM had already failed" },
        { value: "resulttype", label: "The later sign-in carries resultType 0, and by definition any Entra sign-in that returns resultType 0 is a confirmed account takeover regardless of context" },
        { value: "ismanaged_false", label: "The later sign-in reports deviceDetail.isManaged false, which proves the phone had been unenrolled from Intune management just before the corporate access" },
        { value: "appdisplayname", label: "The appDisplayName differs between the two sign-ins, and a change of target application between logons is the field that identifies the compromise" },
      ],
      answer: "noncompliant_ca_gap",
      xp: 60,
      explanation:
        "The verdict comes from the fields, read against the baseline. evt_mmc_05 is isCompliant false, from 45.148.10.62 in the Netherlands, with riskState atRisk — and yet conditionalAccessStatus is success. That last pairing is the whole point: a require-compliant-device Conditional-Access policy did not cover this app, so the sign-in from a phone Intune had just failed was allowed anyway — a CA gap. The baseline (evt_mmc_01) is the opposite: isCompliant true, from the US carrier IP, risk none. (b) over-reads one field — resultType 0 only means the sign-in succeeded, and both did. (c) is false: isManaged is still true (the phone stayed enrolled; it went non-compliant, not unenrolled). (d) is noise.",
    },
    {
      id: "q3",
      prompt:
        "evt_mmc_00 shows s.mendel's managed phone going non-compliant the same night, yet it is benign. Reading it against d.okafor's device, what actually separates the compromise from the benign non-compliance?",
      hint: "If 'device went non-compliant' decided it, both would be incidents. Compare the reason, whether a threat signal fired, and whether a non-store app appeared.",
      kind: "single",
      options: [
        { value: "reason_and_threat", label: "The reason and its corroboration: s.mendel's phone only failed a pending OS-update check and self-remediated, with no threat signal or sideloaded app — d.okafor's flip followed a rooted-device signal" },
        { value: "severity_decides", label: "Severity magnitude decides it — s.mendel's record carries a lower severity than d.okafor's, so the severity value alone cleanly separates a benign blip from a real compromise" },
        { value: "same_verdict", label: "Nothing separates them — both managed phones went non-compliant on the same night, so both records must be treated as confirmed mobile device compromises until proven otherwise" },
        { value: "flagged_or_not", label: "Whether Intune recorded it at all — only d.okafor's phone produced a compliance record, so the mere presence of the record is what tells the two devices apart" },
      ],
      answer: "reason_and_threat",
      xp: 60,
      explanation:
        "The compliance flip on its own decides nothing — both phones show the same record shape, which rules out (b) and (d), and (d) is also factually wrong since BOTH produced compliance records. The difference is why each went non-compliant. s.mendel's phone failed a Minimum-OS-version check because a security patch was pending, carried no Mobile-Threat-Defense signal and no non-managed app, and returned to compliant after the update. d.okafor's flip was driven by a High device-threat-level (rooted) signal that arrived right after a sideloaded, unknown-publisher app appeared. (c) is exactly the failure the control exists to prevent: treating every non-compliant phone as an attack.",
    },
    {
      id: "q4",
      prompt:
        "Before the compliance flip, evt_mmc_02 recorded a new app on the phone. What does that record show, and how does it relate to the rooted-device signal that followed?",
      hint: "Look at mobileApp.publisher and intune.installStateDetail on evt_mmc_02, then at the timing against evt_mmc_03.",
      kind: "single",
      options: [
        { value: "sideload_then_root", label: "A non-managed app of unknown publisher, installed from outside the catalog, then a rooted-device signal six minutes later — the sideload is the plausible entry before the elevation" },
        { value: "store_update", label: "A routine managed-store update that Intune itself pushed to the device, entirely unrelated to the device-threat-level signal that happened to arrive a few minutes afterward" },
        { value: "mtd_agent", label: "The Defender for Endpoint threat-defense agent installing on the phone, which is exactly why the rooted-device signal appeared on the very next device sync" },
        { value: "os_patch", label: "The pending OS security update installing itself, the same benign cause that put s.mendel's managed phone into a non-compliant state earlier the same night" },
      ],
      answer: "sideload_then_root",
      xp: 55,
      explanation:
        "evt_mmc_02 is an Intune DiscoveredApps inventory record: mobileApp.publisher is unknown and installStateDetail is installedFromOutsideManagedApp, i.e. a sideload that did not come from the managed catalog — the classic result of a smishing link. Six minutes later the Mobile-Threat-Defense connector reported the handset rooted (evt_mmc_03), so the sideloaded app is the plausible foothold that abused an elevation weakness to root the device. (b) and (c) are contradicted by the unknown publisher and outside-managed-app source. (d) confuses this with the benign control — the OS-update cause belongs to s.mendel's phone, not this record.",
    },
    {
      id: "q5",
      prompt:
        "You are writing the verdict and the response. The evidence is a rooted managed phone, a non-store app, and corporate mail and file access from that non-compliant device. How should this be classified and handled?",
      kind: "single",
      options: [
        { value: "compromise_wipe_revoke", label: "Confirmed device compromise — retire the phone in Intune, revoke the user's sessions and tokens, reset the credential, review what was reached, and close the Conditional-Access gap" },
        { value: "benign_travel", label: "Benign — the phone merely went non-compliant for a moment and every sign-in used a valid account from an enrolled corporate device, so the ticket can be closed with no action taken" },
        { value: "reset_password_only", label: "Reset the user's password and treat the matter as closed, since a fresh password immediately ends the access without any need to touch the enrolled device or its session tokens" },
        { value: "wait_for_edr", label: "Hold the case open — without a corroborating endpoint EDR detection there is no confirmed intrusion yet, so wait for a host signal before escalating this as a real incident" },
      ],
      answer: "compromise_wipe_revoke",
      xp: 65,
      explanation:
        "The telemetry confirms a mobile compromise: a rooted device (T1626) after a sideloaded app (T1660), then corporate mail and file access from that non-compliant phone using its valid cloud account (T1078.004). Response must act on both the device and the identity: retire/wipe the handset in Intune, revoke the user's sessions and refresh tokens (a password reset alone does not kill an already-issued token, so (c) is insufficient), reset the credential, scope what mail and files were reached, and fix the Conditional-Access gap so a non-compliant device cannot reach those apps again. (b) is the benign-non-compliance trap the control disproves. (d) waits for a host signal that will never come — the affected asset is a phone with no EDR console. attack_kind is mobile_compromise: escalate.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Mobile in the Blind Spot — an Intune-Managed Phone Goes Rogue",
    threat_actor: "Mobile-phishing operator (smishing-led device takeover, no host foothold)",
    attack_kind: "mobile_compromise",
    briefing:
      "Overnight, Microsoft Intune flagged a corporate-enrolled Android phone belonging to d.okafor (Regional Sales Lead) as non-compliant, right after a new app appeared on the handset. Within the same window that same phone reached corporate mail and file storage. Work out what happened to the device and whether that corporate access should be trusted.",
    narrative: `Daniel Okafor, a regional sales lead who lives out of his phone, tapped a text that looked like a delivery notice. The link walked him into installing an app from outside the company's managed store — "SalesRoute Tracker", com.salesroute.tracker, publisher unknown. At 21:00 Intune's app inventory recorded it on his enrolled Android handset, AND-Okafor-Pixel7, installed from outside the managed catalog.

On the device the app abused an elevation weakness and rooted the phone. At 21:06 the Mobile-Threat-Defense connector — Microsoft Defender for Endpoint on Android — reported the handset at a High device threat level with a rooted-device finding. That signal, not any laptop, is where the case begins: there is no mobile endpoint console to walk, so the investigation lives in the Intune and Entra control planes. A minute later Intune acted on the signal and flipped the device's compliance state to non-compliant.

Then the impact. At 21:14 an Entra sign-in for Okafor reached Exchange Online from 45.148.10.62 in Amsterdam — from AND-Okafor-Pixel7, with deviceDetail.isCompliant false, riskState atRisk. And yet conditionalAccessStatus came back success: the require-compliant-device policy did not cover that app, so a phone the MDM had just failed was allowed straight into corporate mail. At 21:19 the same session reached SharePoint Online the same way. The valid cloud account was the disguise; the non-compliant device was the tell.

The instructive comparison sits two hours earlier: s.mendel's managed Galaxy also went non-compliant that night — but only because a security patch was pending, with no threat signal and no sideloaded app, and it returned to compliant on its next sync. Same "device went non-compliant" record, opposite verdict. The lesson of a mobile case is exactly that: the compliance flip is a reason to look, and the verdict is read from why it flipped and what the device did next — not from the flip itself.`,
    learning_objectives: [
      "Investigate a mobile / MDM compromise from the control plane — an Intune Mobile-Threat-Defense signal and the device-compliance flip it drives — when there is no mobile endpoint console or process tree to walk",
      "Read Entra sign-in fields to catch corporate access from a non-compliant device: deviceDetail.isCompliant false with conditionalAccessStatus success is a Conditional-Access gap, not a safe sign-in",
      "Trace a smishing-led sideload (T1660) to a rooted device (T1626) using Intune app-inventory (unknown publisher, installed-from-outside-managed-app) and the Mobile-Threat-Defense device-threat-level signal",
      "Distinguish a real mobile compromise from a benign non-compliance blip (a pending OS update that self-remediates) by the reason for the flip and whether a threat signal fired — not by the compliance record alone",
      "Scope response for a mobile identity compromise: retire/wipe the device in Intune, revoke sessions and refresh tokens, reset the credential, review what was reached, and close the Conditional-Access gap",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: `Sideloaded app "${rogueApp.display}" (${rogueApp.pkg}), unknown publisher, appears on ${device.name} (T1660)` },
      { ts: T(6 * MIN), phase: "Privilege Escalation", action: `Mobile-Threat-Defense reports ${device.name} rooted, High device threat level (T1626)` },
      { ts: T(7 * MIN), phase: "Detection", action: `Intune flips ${device.name} to complianceState noncompliant` },
      { ts: T(14 * MIN), phase: "Impact", action: `Entra sign-in into Exchange Online from ${sessionIp}, isCompliant false, conditionalAccessStatus success (T1078.004)` },
      { ts: T(19 * MIN), phase: "Impact", action: `Same session reaches SharePoint Online from the non-compliant device (T1078.004)` },
    ],
    questions,
  };
}
