/**
 * Scenario pack: "Mobile in the Blind Spot, an Intune-Managed Phone Goes Rogue"
 *
 * INTERMEDIATE tier. The platform is heavy on endpoint, identity and cloud but
 * thin on MOBILE, this pack fills that blind spot. A corporate-enrolled Android
 * phone (Microsoft Intune / Entra) belonging to a field sales lead is compromised:
 * a mobile-phishing (smishing) text lures the user to a flagged website, from
 * which he sideloads an app outside the managed store. On-device, that app abuses
 * an elevation weakness to root the handset. Microsoft Defender for Endpoint on
 * Android (the Intune Mobile-Threat-Defense connector) flags the app, then
 * reports the device as rooted, Intune flips the device's compliance state to
 * non-compliant, and then the SAME phone, now non-compliant, signs in to
 * corporate mail and file storage from a hosting address, replaying a refresh
 * token that carries the MFA claim, and reads mail and downloads a file.
 *
 * The teaching spine is deliberately mobile-shaped:
 *   (1) the ORIGIN is a control-plane chain, a SmartScreen web-protection alert,
 *       a Defender malicious-app alert and a rooted-device alert from the
 *       Mobile-Threat-Defense connector, plus the Intune compliance flip they
 *       drive, NOT a host EDR process tree (there is no mobile endpoint console
 *       to walk here);
 *   (2) the IMPACT is the corporate-resource access from that non-compliant device,
 *       visible as Entra sign-ins into Exchange Online and SharePoint Online whose
 *       deviceDetail.isCompliant is false and whose conditionalAccessStatus is
 *       notApplied (no policy evaluated them, the Conditional-Access gap the
 *       analyst has to name), and as Unified Audit Log reads and a download from
 *       the same hostile session.
 *
 * A BENIGN CONTROL is included and is the pedagogical crux: a second managed phone
 * trips the SAME "device went non-compliant" state earlier the same evening, but
 * for a pending OS security update that self-remediates (the later compliant
 * record is in the telemetry), with no threat signal and no sideloaded app. Same
 * device-compliance shape, opposite verdict. Not every non-compliant phone is a
 * compromise.
 *
 * MITRE (Mobile + Enterprise, pairings verified against current ATT&CK):
 *   T1660 Phishing (Mobile), Initial Access, the smishing-delivered sideload
 *   T1404 Exploitation for Privilege Escalation (Mobile), Privilege Escalation: rooting
 *   T1078.004 Valid Accounts: Cloud Accounts (Enterprise), the corporate access
 *
 * SOURCES (fields registry-valid for the declared vendor): Microsoft Defender for
 * Endpoint (the Android alerts), Microsoft Intune (app inventory and device
 * compliance state), Microsoft Entra ID (the mobile sign-ins and their
 * Conditional-Access evaluation) and the Microsoft 365 Unified Audit Log (mail
 * and file access). This pack fits the Microsoft-365 / Entra company profiles
 * (nexacorp, medcore, globallogis).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { mdeAlert } from "@/lib/sim/emitters/mde";
import { m365Operation } from "@/lib/sim/emitters/m365";

export function buildMobileMdmCompromiseScenario(
  scenarioId = "mobile-mdm-compromise-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T21:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const SEC = 1_000;
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // One incident, the whole case is a single mobile-compromise chain.
  const INCIDENT = "inc:mmc:1";

  const cx = "nexacorp" as const;

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
    homeIp: "81.174.62.30",     // his usual UK mobile-carrier egress (baseline)
  };

  // The foreign hosting/VPS egress the stolen token is replayed from.
  const sessionIp = "45.148.10.62";       // Amsterdam, NL, hosting ASN
  const hostileSession = "a83c0f16-7d24-4b9e-8c51-6f0a29d4e7b1";

  // The smishing landing site and the sideloaded (non-managed-store) application.
  const lureDomain = "salesroute-track.net";
  const lureUrl = `http://${lureDomain}/dl/SalesRouteTracker.apk`;
  const lureIp = "185.215.113.37"; // where the smishing landing site is hosted
  const rogueApp = {
    display: "SalesRoute Tracker",
    pkg: "com.salesroute.tracker",
    publisher: "unknown",
    version: "3.2.0",
    id: "e07b5c92-3a41-4d68-b019-7c2e6f84a5d3",
  };
  const apkHash = makeSha256("mobile_mdm_compromise_salesroute_tracker_apk_2026");

  // The BENIGN CONTROL: a second managed phone that trips the same
  // "device went non-compliant" state earlier that evening, a pending OS update.
  const benign = {
    upn: "s.mendel@nexacorp.com",
    sam: "s.mendel",
    deviceName: "AND-Mendel-GalaxyS23",
    deviceId: "3fa9c108-62d7-4e55-b8a0-1c9e5d720f38",
  };

  // One Intune managed-device compliance / app-inventory record (no shared emitter exists).
  const intune = (o: {
    id: string; ts: string; deviceName: string; deviceId: string; upn: string; osVersion: string;
    severity: TelemetryEvent["severity"]; eventType: TelemetryEvent["event_type"]; description: string;
    fields: Record<string, string>; incident?: string; expected?: TelemetryEvent["expected_verdict"]; fp?: string;
  }): TelemetryEvent => ({
    id: o.id, ts: o.ts, source: "cloud_azure", vendor: "Microsoft Intune", event_type: o.eventType,
    hostname: o.deviceName, user_email: o.upn, severity: o.severity, incident_id: o.incident,
    ...(o.expected ? { expected_verdict: o.expected } : {}), ...(o.fp ? { fp_explanation: o.fp } : {}),
    description: o.description,
    raw: {
      "intune.deviceName": o.deviceName,
      "intune.deviceId": o.deviceId,
      "intune.userPrincipalName": o.upn,
      "intune.platform": "Android",
      "intune.osVersion": o.osVersion,
      "intune.lastSyncDateTime": o.ts,
      ...o.fields,
    },
  });

  // Defender for Endpoint on Android reports mobile-threat alerts only: no process telemetry, so it is
  // filed as an anti-malware (av) source and never opens an EDR process-tree case.
  const androidMde = { vendor: "Microsoft Defender for Endpoint on Android", source: "av" } as const;

  // The Entra sign-in context shared by the baseline and the hostile replays.
  const signIn = {
    companyId: cx, user: victim.upn, userTitle: victim.title, displayName: victim.name, userId: victim.userId,
    deviceId: device.id, deviceName: device.name, os: "Android 14.0", browser: "Outlook Mobile", trustType: "Azure AD registered", managed: true,
  } as const;
  // No Conditional Access policy is in scope for these apps: the one device policy that exists
  // targets the finance apps, so it never evaluates a mail or file sign-in.
  const caNotApplied = {
    "azure.signinlogs.properties.conditionalAccessStatus": "notApplied",
    "azure.signinlogs.properties.appliedConditionalAccessPolicies": [
      { id: "3b8f1a46-0c97-4e25-a6d3-7f12e9c04b81", displayName: "Require compliant device - Finance apps", result: "notApplied", enforcedGrantControls: [] as string[], enforcedSessionControls: [] as string[] },
    ],
  };

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL, a managed phone goes non-compliant for a benign,
    //    self-remediating reason: a pending OS security update. Same device-
    //    compliance shape as the incident, opposite verdict. No threat signal,
    //    no sideloaded app; compliance returns on its own after the update.
    // ─────────────────────────────────────────────────────────────────────
    intune({
      id: "evt_mmc_00_benign_compliance", ts: T(-2 * HOUR), deviceName: benign.deviceName, deviceId: benign.deviceId, upn: benign.upn, osVersion: "13.0",
      severity: "low", eventType: "risk_score_change", expected: "fp",
      fp: "Benign. s.mendel's managed Galaxy went non-compliant only because a required OS security patch was pending; there is no Mobile-Threat-Defense signal on it, no sideloaded app, and the device returned to compliant (the later Intune record shows it) after the update installed on its next sync. Same 'device went non-compliant' record as the incident phone: the difference is the reason and the presence of a threat signal, not the compliance flip itself.",
      description: "Intune marked s.mendel's managed phone AND-Mendel-GalaxyS23 non-compliant against the OS-version policy, with a pending security update noted.",
      fields: { "intune.complianceState": "noncompliant", "intune.report": "Compliance policy: Minimum OS version, not compliant (security patch pending)" },
    }),
    intune({
      id: "evt_mmc_00b_benign_recovered", ts: T(-78 * MIN), deviceName: benign.deviceName, deviceId: benign.deviceId, upn: benign.upn, osVersion: "14.0",
      severity: "informational", eventType: "cloud_api_call",
      description: "After the OS update installed, Intune reported AND-Mendel-GalaxyS23 compliant on the next sync.",
      fields: { "intune.complianceState": "compliant", "intune.report": "Compliance policy: Minimum OS version, compliant" },
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 1. BASELINE, the victim's normal Entra sign-in earlier that evening from
    //    the SAME phone while it was still healthy: compliant, managed, MFA
    //    satisfied, from his usual UK carrier IP. The reference point.
    // ─────────────────────────────────────────────────────────────────────
    {
      ...entraSignIn({
        ...signIn, id: "evt_mmc_01_baseline_signin", ts: T(-40 * MIN), srcIp: device.homeIp, severity: "informational",
        app: "Office 365 Exchange Online", mfa: true, isInteractive: true, compliant: true, riskLevel: "none",
        extra: { ...caNotApplied },
        description:
          "A normal Entra sign-in for d.okafor at 20:20 from London (81.174.62.30) on his enrolled Android phone: compliant, managed, MFA satisfied, into the Outlook mobile app.",
      }),
      is_baseline: true,
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE LURE, Defender on the phone flags the website the smishing text sent
    //    him to (SmartScreen web protection). The user continues past the warning.
    // ─────────────────────────────────────────────────────────────────────
    {
      ...mdeAlert({
      companyId: cx, id: "evt_mmc_01b_web_protection", ts: T(-150 * SEC), host: device.name, user: victim.upn, incidentId: INCIDENT,
      alertTitle: "Unsafe website opened on an Android device", category: "InitialAccess", detectionSource: "SmartScreen",
      severity: "medium", alertSeverity: "Medium", mitre: "T1660", techniqueName: "Phishing", evidenceRole: "Related",
      extra: { "RemoteUrl": lureUrl },
      description: `Defender web protection on ${device.name} flagged ${lureDomain}, a site reached from a text message, and the user continued to it.`,
      }),
      dst_ip: lureIp, dst_port: 80, protocol: "tcp", network: { url: lureUrl, domain: lureDomain }, ...androidMde,
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE SIDELOAD, an app that did not come from the managed store appears
    //    on the phone: publisher unknown. Delivered by a smishing text (T1660).
    // ─────────────────────────────────────────────────────────────────────
    intune({
      id: "evt_mmc_02_app_sideload", ts: T(0), deviceName: device.name, deviceId: device.id, upn: victim.upn, osVersion: device.osVersion,
      severity: "medium", eventType: "cloud_api_call", incident: INCIDENT,
      description:
        "Intune app inventory for AND-Okafor-Pixel7 recorded a new app, \"SalesRoute Tracker\" (com.salesroute.tracker), publisher unknown: an app that is not in the managed app catalog.",
      fields: {
        "intune.report": "DiscoveredApps",
        "intune.appDisplayName": rogueApp.display,
        "intune.appId": rogueApp.pkg,
        "intune.appVersion": rogueApp.version,
        "mobileApp.displayName": rogueApp.display,
        "mobileApp.displayVersion": rogueApp.version,
        "mobileApp.publisher": rogueApp.publisher,
      },
    }),
    {
      ...mdeAlert({
      companyId: cx, id: "evt_mmc_02b_malicious_app", ts: T(3 * MIN), host: device.name, user: victim.upn, incidentId: INCIDENT,
      alertTitle: "Malicious app detected on an Android device", category: "Malware", detectionSource: "Antivirus", sha256: apkHash,
      severity: "high", alertSeverity: "High", mitre: "T1660", techniqueName: "Phishing", evidenceRole: "Impacted",
      remediation: "Warn", remediationStatus: "Notified",
      extra: { "FileName": "SalesRouteTracker.apk", "RemoteUrl": lureUrl },
      description: `Defender on ${device.name} detected SalesRouteTracker.apk (com.salesroute.tracker), installed from outside the managed store after the download from ${lureDomain}.`,
      }),
      file: { name: "SalesRouteTracker.apk", path: "/storage/emulated/0/Download/SalesRouteTracker.apk", sha256: apkHash }, ...androidMde,
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. THE THREAT SIGNAL, Microsoft Defender for Endpoint (the Intune Mobile-
    //    Threat-Defense connector) reports the phone as rooted. This is the
    //    case-opening detection: control-plane only (no mobile EDR console to
    //    walk), so is_detection + edr_scope "non_edr". Exploiting a vulnerability
    //    to root the device (T1404).
    // ─────────────────────────────────────────────────────────────────────
    {
      ...mdeAlert({
        companyId: cx, id: "evt_mmc_03_mtd_threat_signal", ts: T(6 * MIN), host: device.name, user: victim.upn, incidentId: INCIDENT,
        alertTitle: "Rooted Android device detected", category: "PrivilegeEscalation", detectionSource: "EDR",
        severity: "high", alertSeverity: "High", mitre: "T1404", techniqueName: "Exploitation for Privilege Escalation", evidenceRole: "Impacted",
        description:
          "The Mobile-Threat-Defense connector (Defender for Endpoint on Android) reported AND-Okafor-Pixel7 as rooted, with a High device threat level; Intune received the signal at 21:06.",
      }),
      edr_scope: "non_edr", // MDM / identity control-plane, no host process tree to pivot into
      ...androidMde,
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE COMPLIANCE FLIP, driven by the threat signal, Intune moves the
    //    device's compliance state to non-compliant. This is the state change
    //    Conditional Access is supposed to key off. An observation, no MITRE.
    // ─────────────────────────────────────────────────────────────────────
    intune({
      id: "evt_mmc_04_compliance_flip", ts: T(7 * MIN), deviceName: device.name, deviceId: device.id, upn: victim.upn, osVersion: device.osVersion,
      severity: "high", eventType: "risk_score_change", incident: INCIDENT,
      description:
        "Intune flipped AND-Okafor-Pixel7 to complianceState noncompliant against the device-threat-level policy, following the High threat-level signal on the handset.",
      fields: { "intune.complianceState": "noncompliant", "intune.report": "Compliance policy: Require the device to be at or under the machine risk score, failed" },
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE IMPACT (mail), the SAME phone, now non-compliant, signs in to
    //    Exchange Online by replaying its refresh token (MFA claim carried in the
    //    token) from a foreign hosting IP. deviceDetail.isCompliant is false and
    //    no Conditional Access policy was evaluated (notApplied): a gap.
    //    Valid Accounts: Cloud Accounts (T1078.004).
    // ─────────────────────────────────────────────────────────────────────
    {
      ...entraSignIn({
        ...signIn, id: "evt_mmc_05_mail_access_noncompliant", ts: T(14 * MIN), srcIp: sessionIp, severity: "critical",
        app: "Office 365 Exchange Online", mfa: true, isInteractive: false, compliant: false, sessionId: hostileSession,
        riskLevel: "high", riskEventTypes: ["unfamiliarFeatures", "anomalousToken"], incomingTokenType: "refreshToken",
        authStepResultDetail: "MFA requirement satisfied by claim in the token",
        mitre: "T1078.004", tactic: "Initial Access", incidentId: INCIDENT,
        extra: { ...caNotApplied },
        description:
          "An Entra sign-in for d.okafor into Exchange Online at 21:14 from 45.148.10.62 (Amsterdam, NL), from device AND-Okafor-Pixel7 with deviceDetail.isCompliant false, riskState atRisk, and no Conditional Access policy applied.",
      }),
      hostname: device.name,
    },
    m365Operation({
      id: "evt_mmc_05b_mail_items_accessed", ts: T(15 * MIN + 10 * SEC), companyId: cx, user: victim.upn, userTitle: victim.title, srcIp: sessionIp, incidentId: INCIDENT,
      operation: "MailItemsAccessed", workload: "Exchange", sessionId: hostileSession, userAgent: "Outlook-Android/2.0", severity: "high",
      mitre: "T1114.002", tactic: "Collection",
      extra: { "RecordType": "50", "ClientInfoString": "Client=REST;Client=RESTSystem;;" },
      description: "The Exchange audit log recorded MailItemsAccessed for d.okafor from 45.148.10.62 in the same session as the Exchange sign-in.",
    }),
    m365Operation({
      id: "evt_mmc_05c_mail_items_accessed", ts: T(16 * MIN + 40 * SEC), companyId: cx, user: victim.upn, userTitle: victim.title, srcIp: sessionIp, incidentId: INCIDENT,
      operation: "MailItemsAccessed", workload: "Exchange", sessionId: hostileSession, userAgent: "Outlook-Android/2.0", severity: "high",
      mitre: "T1114.002", tactic: "Collection",
      extra: { "RecordType": "50", "ClientInfoString": "Client=REST;Client=RESTSystem;;" },
      description: "A second MailItemsAccessed record for d.okafor from 45.148.10.62, same session.",
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 7. THE IMPACT (files), the same non-compliant phone reaches SharePoint
    //    Online moments later on the same hostile session, and a file is
    //    downloaded. Valid cloud account used to reach corporate data (T1078.004).
    // ─────────────────────────────────────────────────────────────────────
    {
      ...entraSignIn({
        ...signIn, id: "evt_mmc_06_sharepoint_access_noncompliant", ts: T(19 * MIN), srcIp: sessionIp, severity: "high",
        app: "Office 365 SharePoint Online", mfa: true, isInteractive: false, compliant: false, sessionId: hostileSession,
        riskLevel: "high", riskEventTypes: ["anomalousToken"], incomingTokenType: "refreshToken",
        authStepResultDetail: "MFA requirement satisfied by claim in the token",
        mitre: "T1078.004", tactic: "Stealth", incidentId: INCIDENT,
        extra: { ...caNotApplied },
        description:
          "A second Entra sign-in for d.okafor at 21:19 into SharePoint Online, same session and same 45.148.10.62 origin, from AND-Okafor-Pixel7 with deviceDetail.isCompliant false and no Conditional Access policy applied.",
      }),
      hostname: device.name,
    },
    m365Operation({
      id: "evt_mmc_06b_file_downloaded", ts: T(20 * MIN + 5 * SEC), companyId: cx, user: victim.upn, userTitle: victim.title, srcIp: sessionIp, incidentId: INCIDENT,
      operation: "FileDownloaded", workload: "SharePoint", sessionId: hostileSession, userAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36", severity: "high",
      fileName: "Q3-Pipeline.xlsx", fileExtension: "xlsx", objectId: "https://nexacorp.sharepoint.com/sites/Sales/Shared Documents/Q3-Pipeline.xlsx",
      siteUrl: "https://nexacorp.sharepoint.com/sites/Sales", mitre: "T1530", tactic: "Collection",
      description: "The SharePoint audit log recorded Q3-Pipeline.xlsx downloaded by d.okafor from 45.148.10.62 in the same session.",
    }),
  ];

  // The phone is the host on every device-side record, so the table pivots on it.
  for (const e of events) if (!e.hostname && e.incident_id === INCIDENT) e.hostname = device.name;

  const iocs: IOC[] = [
    {
      type: "host",
      value: device.name, // AND-Okafor-Pixel7, the compromised managed phone
      first_seen: T(-150 * SEC),
      last_seen: T(20 * MIN + 5 * SEC),
      reputation: "suspicious",
      tags: ["managed-device", "android", "affected"],
    },
    {
      type: "user",
      value: victim.sam, // d.okafor, the affected account
      first_seen: T(-40 * MIN),
      last_seen: T(20 * MIN + 5 * SEC),
      reputation: "suspicious",
      tags: ["regional-sales", "affected-account"],
    },
    {
      type: "email",
      value: victim.upn, // d.okafor@nexacorp.com, the mailbox reached from the device
      first_seen: T(-40 * MIN),
      last_seen: T(20 * MIN + 5 * SEC),
      reputation: "suspicious",
      tags: ["affected-mailbox", "sales"],
    },
    {
      type: "ip",
      value: sessionIp, // 45.148.10.62, the foreign hosting session origin
      first_seen: T(14 * MIN),
      last_seen: T(20 * MIN + 5 * SEC),
      reputation: "malicious",
      tags: ["session-origin", "hosting-asn"],
    },
    {
      type: "domain",
      value: lureDomain, // the smishing landing site that served the APK
      first_seen: T(-150 * SEC),
      last_seen: T(3 * MIN),
      reputation: "malicious",
      tags: ["smishing-landing", "apk-host"],
    },
    {
      type: "ip",
      value: lureIp, // where the smishing landing site is hosted
      first_seen: T(-150 * SEC),
      last_seen: T(-150 * SEC),
      reputation: "malicious",
      tags: ["external", "smishing-landing", "apk-host"],
    },
    {
      type: "sha256",
      value: apkHash, // SalesRouteTracker.apk
      first_seen: T(3 * MIN),
      last_seen: T(3 * MIN),
      reputation: "malicious",
      tags: ["android", "sideloaded-app"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "This ticket did not open with a malware verdict on a laptop or a firewall block. Which event is the triggering detection, and what kind of source raised it?",
      hint: "Nothing walked a host process tree. A mobile-threat sensor reported the handset's health to the device-management plane.",
      kind: "single",
      options: [
        { value: "mtd_signal", label: "The Mobile-Threat-Defense connector reporting the phone rooted at a High device threat level, an MDM control-plane signal, not a host detection" },
        { value: "edr_laptop", label: "An EDR agent on the user's laptop flagged a malicious binary in memory, and the case begins by walking that host's process tree back to its parent" },
        { value: "firewall_block", label: "A perimeter firewall denied the Amsterdam hosting IP on an outbound connection, and that single blocked session is what opened the ticket for triage" },
        { value: "dlp_block", label: "A DLP policy blocked a sensitive file leaving SharePoint Online toward the phone, and that blocked exfiltration attempt is what raised the alert" },
      ],
      answer: "mtd_signal",
      xp: 55,
      explanation:
        "The origin is a mobile control-plane signal. evt_mmc_03 is the Defender for Endpoint on Android alert (the Intune Mobile-Threat-Defense connector) reporting the handset as rooted at a High device threat level, and Intune acted on it a minute later (evt_mmc_04). There is no mobile endpoint console with a process tree to walk, so the case is worked from the Defender, Intune and Entra telemetry. (b) is wrong: the affected asset is a phone, and no laptop EDR detection exists here. (c) and (d) describe block events that never fired: nothing was blocked; the corporate access actually succeeded.",
    },
    {
      id: "q2",
      prompt:
        "You pivot to the two Exchange Online sign-ins (evt_mmc_01 baseline, evt_mmc_05 the later one). Which combination of Entra fields marks the later sign-in as the dangerous one, and what does conditionalAccessStatus tell you about why it was not stopped?",
      hint: "Compare deviceDetail.isCompliant, the ipAddress / country and the risk fields between the 20:20 and 21:14 sign-ins, then read appliedConditionalAccessPolicies.",
      kind: "single",
      options: [
        { value: "noncompliant_ca_gap", label: "isCompliant false from a foreign hosting IP, risk atRisk, and conditionalAccessStatus notApplied, no policy evaluated a sign-in from a device Intune had already failed" },
        { value: "resulttype", label: "The later sign-in carries resultType 0, the Entra code that marks a sign-in completed with a token replayed from another device" },
        { value: "ismanaged_false", label: "The later sign-in reports deviceDetail.isManaged false, showing the phone had been unenrolled from Intune just before the corporate access" },
        { value: "appdisplayname", label: "The appDisplayName differs between the two sign-ins, and a change of target application between logons is the field that identifies the compromise" },
      ],
      answer: "noncompliant_ca_gap",
      xp: 60,
      explanation:
        "The verdict comes from the fields, read against the baseline. evt_mmc_05 is isCompliant false, from 45.148.10.62 in the Netherlands, riskState atRisk with an anomalous-token risk detection, and a non-interactive refresh-token sign-in with the MFA claim carried in the token. The baseline (evt_mmc_01) is the opposite on compliance, IP and risk. conditionalAccessStatus is notApplied on both, and appliedConditionalAccessPolicies shows why: the only device policy, 'Require compliant device - Finance apps', is scoped to the finance apps and never evaluated Exchange Online. So a phone Intune had just failed was allowed into mail because no policy covered that app: a Conditional-Access gap. (b) over-reads one field: resultType 0 only means the sign-in succeeded, and both did. (c) is false: isManaged is still true (the phone stayed enrolled; it went non-compliant, not unenrolled). (d) is noise.",
    },
    {
      id: "q3",
      prompt:
        "evt_mmc_00 shows s.mendel's managed phone going non-compliant earlier the same evening, yet it is benign. Reading it against d.okafor's device, what actually separates the compromise from the benign non-compliance?",
      hint: "If 'device went non-compliant' decided it, both would be incidents. Compare the reason, whether a threat signal fired, whether a non-store app appeared, and what each device's compliance did next.",
      kind: "single",
      options: [
        { value: "reason_and_threat", label: "The reason behind each flip: s.mendel's phone failed a pending OS-update check and recovered on its own; d.okafor's followed a flagged app and a rooted-device signal" },
        { value: "severity_decides", label: "Severity magnitude decides it, s.mendel's record carries a lower severity than d.okafor's, so the severity value alone cleanly separates a benign blip from a real compromise" },
        { value: "same_verdict", label: "Nothing separates them, both managed phones went non-compliant on the same night, so both records must be treated as confirmed mobile device compromises until proven otherwise" },
        { value: "flagged_or_not", label: "Whether Intune recorded it at all, only d.okafor's phone produced a compliance record, so the mere presence of the record is what tells the two devices apart" },
      ],
      answer: "reason_and_threat",
      xp: 60,
      explanation:
        "The compliance flip on its own decides nothing: both phones show the same record shape, which rules out (b) and (d), and (d) is also factually wrong since BOTH produced compliance records. The difference is why each went non-compliant and what happened next. s.mendel's phone failed a Minimum-OS-version check because a security patch was pending, carried no Defender alert and no non-managed app, and Intune's own later record (evt_mmc_00b) shows it compliant again after the update. d.okafor's flip was driven by a rooted-device alert that arrived right after Defender flagged a sideloaded, unknown-publisher app, and it did not recover. (c) is exactly the failure the control exists to prevent: treating every non-compliant phone as an attack.",
    },
    {
      id: "q4",
      prompt:
        "Before the compliance flip, the telemetry shows a website alert (evt_mmc_01b), a new app in Intune's inventory (evt_mmc_02) and a Defender alert on that app (evt_mmc_02b). What do they show, and how do they relate to the rooted-device signal that followed?",
      hint: "Look at the URL and domain in the web alert, mobileApp.publisher on the inventory record, the file name in the app alert, and the timing against evt_mmc_03.",
      kind: "single",
      options: [
        { value: "sideload_then_root", label: "A flagged website served an APK, a non-managed app of unknown publisher then appeared and was flagged, and a rooted-device signal followed, the plausible entry point" },
        { value: "store_update", label: "A routine managed-store update that Intune itself pushed to the device, entirely unrelated to the device-threat-level signal that happened to arrive a few minutes afterward" },
        { value: "mtd_agent", label: "The Defender for Endpoint threat-defense agent installing on the phone, which is exactly why the rooted-device signal appeared on the very next device sync" },
        { value: "os_patch", label: "The pending OS security update installing itself, the same benign cause that put s.mendel's managed phone into a non-compliant state earlier the same evening" },
      ],
      answer: "sideload_then_root",
      xp: 55,
      explanation:
        "evt_mmc_01b shows Defender web protection flagging salesroute-track.net at 20:57, a site reached from a text message, with the user continuing to it. evt_mmc_02 is an Intune app-inventory record: mobileApp.publisher is unknown and the app is not part of the managed catalog, and evt_mmc_02b is Defender's malicious-app alert on SalesRouteTracker.apk (com.salesroute.tracker) three minutes later. Six minutes after the app appeared the Mobile-Threat-Defense connector reported the handset rooted (evt_mmc_03), so the sideloaded app is the plausible foothold that abused an elevation weakness to root the device. (b) and (c) are contradicted by the unknown publisher, the APK download and the malicious-app alert. (d) confuses this with the benign control: the OS-update cause belongs to s.mendel's phone, not this chain.",
    },
    {
      id: "q5",
      prompt:
        "You are writing the verdict and the response. The evidence is a rooted managed phone, a non-store app, and corporate mail and file access from that non-compliant device. How should this be classified and handled?",
      kind: "single",
      options: [
        { value: "compromise_wipe_revoke", label: "Confirmed device compromise, retire the phone in Intune, revoke sessions and tokens, reset the credential, review what was reached, and close the Conditional-Access gap" },
        { value: "benign_travel", label: "Benign, the phone merely went non-compliant for a moment and every sign-in used a valid account from an enrolled corporate device, so the ticket can be closed with no action taken" },
        { value: "reset_password_only", label: "Reset the user's password and treat the matter as closed, since a fresh password immediately ends the access without any need to touch the enrolled device or its session tokens" },
        { value: "wait_for_edr", label: "Hold the case open, without a corroborating endpoint EDR detection there is no confirmed intrusion yet, so wait for a host signal before escalating this as a real incident" },
      ],
      answer: "compromise_wipe_revoke",
      xp: 65,
      explanation:
        "The telemetry confirms a mobile compromise: a flagged sideloaded app (T1660), a rooted device (T1404), then corporate mail and file access from that non-compliant phone by replaying its refresh token from a hosting address (T1078.004), with mail items read and a workbook downloaded. Response must act on both the device and the identity: retire/wipe the handset in Intune, revoke the user's sessions and refresh tokens (a password reset alone does not kill an already-issued token, so (c) is insufficient), reset the credential, scope what mail and files were reached, and fix the Conditional-Access gap so a non-compliant device cannot reach those apps again. (b) is the benign-non-compliance trap the control disproves. (d) waits for a host signal that will never come: the affected asset is a phone with no EDR console, and the mobile-threat alerts already are the host signal. attack_kind is mobile_compromise: escalate.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Intune non-compliance for a corporate Android phone",
    threat_actor: "Mobile-phishing operator (smishing-led device takeover, no host foothold)",
    attack_kind: "mobile_compromise",
    briefing:
      "Intune marked d.okafor's corporate Android phone non-compliant after a threat-level signal from the Mobile Threat Defense connector. Determine what happened to the device and whether access from it should be trusted.",
    narrative: `Daniel Okafor, a regional sales lead who lives out of his phone, tapped a text that looked like a delivery notice. At 20:57 Defender web protection on his phone flagged the site it led to, salesroute-track.net, and he continued past the warning. The page served an APK, and he installed an app from outside the company's managed store: "SalesRoute Tracker", com.salesroute.tracker, publisher unknown. At 21:00 Intune's app inventory recorded it on his enrolled Android handset, AND-Okafor-Pixel7, and at 21:03 Defender flagged SalesRouteTracker.apk as malicious.

On the device the app exploited a vulnerability to root the phone. At 21:06 the Mobile-Threat-Defense connector, Microsoft Defender for Endpoint on Android, reported the handset as rooted. That signal, not any laptop, is where the case begins: there is no mobile endpoint console to walk, so the investigation lives in the Defender, Intune and Entra control planes. A minute later Intune acted on the signal and flipped the device's compliance state to non-compliant. With the phone rooted, the operator could lift the app's refresh token, including the MFA claim it carried.

Then the impact. At 21:14 an Entra sign-in for Okafor reached Exchange Online from 45.148.10.62 in Amsterdam, replaying that refresh token non-interactively, with the phone's own device id, deviceDetail.isCompliant false and riskState atRisk. And yet nothing stopped it: conditionalAccessStatus came back notApplied, because the only device policy ("Require compliant device - Finance apps") is scoped to the finance apps and never evaluated Exchange Online, so a phone the MDM had just failed was allowed straight into corporate mail. The audit log shows two MailItemsAccessed records in the same session. At 21:19 the same session reached SharePoint Online the same way and at 21:20 downloaded Q3-Pipeline.xlsx. The valid cloud account was the disguise; the non-compliant device was the tell.

The instructive comparison sits earlier that evening: s.mendel's managed Galaxy also went non-compliant, at 19:00, but only because a security patch was pending, with no threat signal and no sideloaded app, and Intune's own record at 19:42 shows it compliant again after the update. Same "device went non-compliant" record, opposite verdict. The lesson of a mobile case is exactly that: the compliance flip is a reason to look, and the verdict is read from why it flipped and what the device did next, not from the flip itself.`,
    learning_objectives: [
      "Investigate a mobile / MDM compromise from the control plane, Defender mobile-threat alerts and the Intune device-compliance flip they drive, when there is no mobile endpoint console or process tree to walk",
      "Read Entra sign-in fields to catch corporate access from a non-compliant device: deviceDetail.isCompliant false with conditionalAccessStatus notApplied is a Conditional-Access gap, not a safe sign-in",
      "Trace a smishing-led sideload (T1660) to a rooted device (T1404) using the web-protection alert, Intune app inventory (unknown publisher) and the Mobile-Threat-Defense alerts",
      "Distinguish a real mobile compromise from a benign non-compliance blip (a pending OS update that self-remediates) by the reason for the flip, whether a threat signal fired and whether the device recovered, not by the compliance record alone",
      "Scope response for a mobile identity compromise: retire/wipe the device in Intune, revoke sessions and refresh tokens, reset the credential, review what was reached, and close the Conditional-Access gap",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-150 * SEC), phase: "Initial Access", action: `Defender web protection flags ${lureDomain}, reached from a text message; the user continues to the page (T1660)` },
      { ts: T(0), phase: "Initial Access", action: `Sideloaded app "${rogueApp.display}" (${rogueApp.pkg}), unknown publisher, appears on ${device.name}; Defender flags the APK at 21:03 (T1660)` },
      { ts: T(6 * MIN), phase: "Privilege Escalation", action: `Mobile-Threat-Defense reports ${device.name} rooted, High device threat level (T1404)` },
      { ts: T(7 * MIN), phase: "Detection", action: `Intune flips ${device.name} to complianceState noncompliant` },
      { ts: T(14 * MIN), phase: "Impact", action: `Entra sign-in into Exchange Online from ${sessionIp} replaying a refresh token, isCompliant false, conditionalAccessStatus notApplied (T1078.004)` },
      { ts: T(15 * MIN + 10 * SEC), phase: "Collection", action: "Two MailItemsAccessed records in the same session (T1114.002)" },
      { ts: T(19 * MIN), phase: "Impact", action: `Same session reaches SharePoint Online from the non-compliant device (T1078.004)` },
      { ts: T(20 * MIN + 5 * SEC), phase: "Collection", action: "Q3-Pipeline.xlsx downloaded from SharePoint in the same session (T1530)" },
    ],
    questions,
  };
}
