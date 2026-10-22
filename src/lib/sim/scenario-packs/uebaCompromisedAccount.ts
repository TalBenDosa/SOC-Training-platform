/**
 * Scenario pack: "Sentinel risk score raised for a Finance manager"
 *
 * INTERMEDIATE tier. This is the platform's first ANOMALY-DRIVEN investigation:
 * it does not open with a signature alert (no malware verdict, no firewall block,
 * no DLP match). It opens with a NUMBER, Microsoft Sentinel UEBA raised the
 * entity risk score of a Finance manager, Jordan Almeida, after correlating three
 * behaviours that are each ordinary in isolation but wrong together: an atypical
 * sign-in from an unfamiliar location and a hosting ASN, a burst of file downloads
 * from OneDrive/SharePoint far above his own norm, and a newly-created mailbox
 * forwarding rule. None of those is a "this is an attack" event on its own; the
 * signal is the correlation, expressed as a risk score.
 *
 * The teaching arc is deliberately three-step: (1) start from the anomaly score,
 * (2) pivot DOWN into the primary telemetry, the Entra sign-in behind the
 * "impossible travel", the O365 audit records behind the "mass download" and the
 * "new inbox rule", and (3) reach a verdict from that primary evidence, not from
 * the score. A high UEBA score is a REASON TO LOOK, never a verdict by itself.
 *
 * That is exactly why a BENIGN CONTROL is included and is the pedagogical crux: a
 * second user, Renée Laurent, trips the SAME ImpossibleTravel anomaly the same
 * night, but her two Entra sign-ins (London, then Singapore over the corporate
 * VPN) are corroborated by a compliant managed device and a satisfied MFA
 * requirement, and an IT travel record confirms the trip. Same "risky sign-in anomaly" shape, opposite verdict. Not every
 * high score is a compromise, and the analyst has to learn to tell them apart
 * from the underlying sign-in, not from the alert title.
 *
 * Where the session came from is on the endpoint: an unsigned process on
 * Almeida's laptop copies the browser cookie database and uploads it to a hosting
 * address an hour before the replay (Defender for Endpoint, no detection fired).
 *
 * Covers T1078 (Valid Accounts, the compromised sign-in), T1539 (Steal Web
 * Session Cookie, the cookie theft and the replayed session token that skipped
 * the MFA prompt),
 * T1213.002 (Data from Information Repositories: SharePoint, the mass download)
 * and T1114.003 (Email Collection: Email Forwarding Rule, the hiding/forwarding
 * inbox rule).
 *
 * SOURCES (all fields registry-valid for their declared vendor): Microsoft
 * Sentinel (UEBA behaviour/anomaly indicators and the entity risk score that
 * opens the case), Microsoft Entra ID / Azure AD (the sign-in logs the anomalies
 * were derived from), the Microsoft 365 Unified Audit Log (the SharePoint
 * download burst and the Exchange New-InboxRule) and Microsoft Defender for
 * Endpoint (the cookie-stealing process on the victim's laptop). This pack fits the
 * Microsoft-365 / Entra company profiles (nexacorp, medcore, globallogis).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { sentinelUeba } from "@/lib/sim/emitters/sentinel";
import { mdeProcess, mdeFile, mdeDns, mdeNetwork } from "@/lib/sim/emitters/mde";

export function buildUebaCompromisedAccountScenario(
  scenarioId = "ueba-compromised-account-2026",
): ScenarioBundle {
  const B = new Date("2026-08-30T23:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // One incident, the whole hunt is a single account-compromise case.
  const INCIDENT = "inc:uca:1";

  // The compromised account and his normal working context.
  const victim = {
    email: "j.almeida@nexacorp.com",
    name: "Jordan Almeida",
    sam: "j.almeida",
    title: "Finance Manager",
    dept: "Finance",
    userId: "a7f3c210-9b64-4e18-8d02-51c9e4a7b330",
    homeIp: "81.174.71.19",           // his usual corporate/home egress (London)
    host: "FIN-LT-Almeida",
    deviceId: "3b9f6e24-7c10-4a85-9d3e-8f2a1c0b5e76",
  };

  // The cookie-stealing process on his laptop and its command-and-control address.
  const stealerHash = makeSha256("nexacorp_uca_cookie_stealer_svcupd_exe_2026");
  const STEALER = "C:\\Users\\j.almeida\\AppData\\Local\\Temp\\svcupd.exe";
  const c2Domain = "static-cdn-sync.net";
  const c2Ip = "185.225.73.141";

  // The attacker's session origin: a hosting/VPS ASN in Sofia, Bulgaria.
  const attackerIp = "45.135.232.71";
  const attackerAsn = 200651;         // a real-world hosting AS range
  const attackerAsnOrg = "Flokinet-Hosting";
  const hostileSession = "6f0b9d47-2a15-4c88-b3e1-7d92a4c0e6f5";

  // The external address the forwarding rule ships mail to.
  const dropAddress = "acct.archive.9y@gmail.com";

  // The marquee file of the download burst.
  const marqueeFile = "FY26_Budget_Consolidation.xlsx";
  const SP = "https://nexacorp.sharepoint.com/sites/Finance/Shared Documents";
  const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";

  // The BENIGN CONTROL: a Sales director who trips the SAME ImpossibleTravel
  // anomaly the same night, but legitimately, approved travel, corporate VPN
  // egress, compliant managed device, satisfied MFA.
  const benign = {
    email: "r.laurent@nexacorp.com",
    name: "Renée Laurent",
    sam: "r.laurent",
    title: "Sales Director",
    ip: "203.116.40.12",              // Singapore, corporate-VPN egress
    londonIp: "86.14.201.37",
    deviceId: "e6a1c9d4-2b57-4f03-b8a6-1d7e5c3f9a20",
    deviceName: "SAL-LT-Laurent",
  };

  // A SharePoint download is cloud-audit evidence, not a file the endpoint wrote: keep the file name
  // in the audit record's own fields (ObjectId, SourceFileName) and off the structured endpoint file slot.
  const dlRow = (e: TelemetryEvent): TelemetryEvent => ({ ...e, file: undefined });

  const events: TelemetryEvent[] = [
    // 0a. BENIGN CONTROL, primary telemetry: r.laurent signs in from London that morning ...
    { ...entraSignIn({
      companyId: "nexacorp", id: "evt_uca_00a_benign_london_signin", ts: "2026-08-30T09:05:00.000Z",
      user: benign.email, displayName: benign.name, userTitle: benign.title,
      srcIp: benign.londonIp, geo: { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 },
      result: "success", severity: "informational", app: "Office 365 Exchange Online",
      mfa: true, managed: true, compliant: true, os: "Windows 11", browser: "Edge 128.0", trustType: "Azure AD joined",
      deviceName: benign.deviceName, deviceId: benign.deviceId, asn: 2856, sessionId: "5c8e2a17-9b40-4d63-a1f7-30e6b9d4c852", isInteractive: true,
      riskLevel: "none", conditionalAccess: "success",
      description: "Interactive Entra sign-in for r.laurent from London on her compliant, managed laptop with MFA satisfied.",
    }), is_baseline: true },

    // 0b. ... and from Singapore that evening over the sanctioned corporate VPN, same device, MFA satisfied.
    { ...entraSignIn({
      companyId: "nexacorp", id: "evt_uca_00b_benign_singapore_signin", ts: "2026-08-30T20:38:00.000Z",
      user: benign.email, displayName: benign.name, userTitle: benign.title,
      srcIp: benign.ip, geo: { country: "Singapore", city: "Singapore", latitude: 1.3521, longitude: 103.8198 },
      result: "success", severity: "informational", app: "Office 365 Exchange Online",
      mfa: true, managed: true, compliant: true, os: "Windows 11", browser: "Edge 128.0", trustType: "Azure AD joined",
      deviceName: benign.deviceName, deviceId: benign.deviceId, asn: 3758, sessionId: "7d1f4b38-0c62-4e95-b2a8-41f7c0e5d963", isInteractive: true,
      riskLevel: "low", riskEventTypes: ["unlikelyTravel"], conditionalAccess: "success",
      extra: { "azure.signinlogs.properties.networkLocationDetails": [{ networkType: "trustedNamedLocation", networkNames: ["NexaCorp VPN Singapore"] }] },
      description: "Interactive Entra sign-in for r.laurent from 203.116.40.12 (Singapore) over the NexaCorp VPN Singapore named location, same managed laptop, MFA satisfied.",
    }), it_verify_result: "confirmed",
      it_verify_message: "Travel request TR-0418: Renée Laurent, Sales offsite in Singapore 30 Aug to 2 Sep, approved by her manager; the NexaCorp VPN Singapore gateway egresses at 203.116.40.12." },

    // 0. BENIGN CONTROL: the same ImpossibleTravel anomaly raised for r.laurent, resolves BENIGN.
    sentinelUeba({
      companyId: "nexacorp", id: "evt_uca_00_benign_impossible_travel", ts: T(-3 * HOUR),
      user: benign.email, userSam: benign.sam, userTitle: benign.title, srcIp: benign.ip,
      alertName: "Atypical travel", alertSeverity: "Informational", severity: "informational",
      indicators: ["ImpossibleTravelActivity"],
      anomaly: { type: "AtypicalTravel", score: 22, reason: "Sign-in from a new country for this account" },
      risk: { level: "low", state: "dismissed" },
      geoCountry: "Singapore", authStatus: "success", mfa: true, deviceCompliant: true,
      expectedVerdict: "fp",
      fpExplanation:
        "Benign. r.laurent tripped ImpossibleTravelActivity the same night, but her two Entra sign-ins (evt_uca_00a London, evt_uca_00b Singapore) are corroborated: the Singapore one came over the NexaCorp VPN Singapore named location on her compliant managed laptop with MFA satisfied, and IT confirms an approved travel request. The anomaly score is real, the verdict is not a compromise: a UEBA score is a reason to look, not a conclusion. Contrast with j.almeida, whose sign-in has none of that corroboration.",
      extendedProperties: {
        "Prior Sign-in Location": "London, GB",
        "Current Sign-in Location": "Singapore, SG",
      },
      description:
        "Sentinel raised an impossible-travel anomaly for r.laurent (London to Singapore); the underlying sign-ins are evt_uca_00a and evt_uca_00b.",
    }),

    // 0s. THE SOURCE OF THE SESSION: an unsigned process on FIN-LT-Almeida copies the Edge cookie
    //     database and sends it to a hosting address (Defender for Endpoint telemetry, no alert).
    mdeProcess({
      companyId: "nexacorp", id: "evt_uca_00s1_stealer_exec", ts: T(-49 * MIN), host: victim.host, user: victim.email,
      processName: "svcupd.exe", processPath: STEALER, cmdline: `"${STEALER}"`, parentName: "explorer.exe", parentPid: 5120, pid: 7412,
      sha256: stealerHash, signed: false, runAsUser: "NEXACORP\\j.almeida", accountName: victim.sam, accountDomain: "NEXACORP",
      severity: "medium", incidentId: INCIDENT,
      extra: { "InitiatingProcessFolderPath": "C:\\Windows", "InitiatingProcessFileName": "explorer.exe", "InitiatingProcessId": "5120" },
      description: "svcupd.exe started from the user's Temp folder (unsigned) on FIN-LT-Almeida.",
    }),
    mdeFile({
      companyId: "nexacorp", id: "evt_uca_00s2_cookie_db_copy", ts: T(-48 * MIN - 30_000), host: victim.host, user: victim.email,
      path: "C:\\Users\\j.almeida\\AppData\\Local\\Temp\\Cookies", sha256: null, size: 1_310_720, action: "file_create",
      initiatingProcess: "svcupd.exe", initiatingCmdline: `"${STEALER}"`,
      severity: "medium", incidentId: INCIDENT, mitre: "T1539", tactic: "Credential Access",
      description: "svcupd.exe created a 1.2 MB file named Cookies in the user's Temp folder.",
    }),
    mdeDns({
      companyId: "nexacorp", id: "evt_uca_00s3_c2_dns", ts: T(-48 * MIN - 5_000), host: victim.host, user: victim.email,
      domain: c2Domain, resolvedIp: c2Ip, severity: "medium", incidentId: INCIDENT,
      description: "FIN-LT-Almeida resolved static-cdn-sync.net to 185.225.73.141.",
    }),
    mdeNetwork({
      companyId: "nexacorp", id: "evt_uca_00s4_c2_connect", ts: T(-48 * MIN), host: victim.host, user: victim.email,
      remoteIp: c2Ip, remotePort: 443, domain: c2Domain, application: "tls", initiatingProcess: "svcupd.exe",
      severity: "medium", incidentId: INCIDENT,
      description: "svcupd.exe connected to 185.225.73.141:443 (static-cdn-sync.net).",
    }),

    // 1. THE BASELINE SIGN-IN, j.almeida's normal London logon.
    { ...entraSignIn({
      companyId: "nexacorp", id: "evt_uca_01_baseline_signin", ts: T(-40 * MIN),
      user: victim.email, displayName: victim.name, userTitle: victim.title, userId: victim.userId,
      srcIp: victim.homeIp, geo: { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 },
      result: "success", severity: "informational", app: "Office 365",
      mfa: true, managed: true, compliant: true, os: "Windows 11", browser: "Edge 128.0",
      trustType: "Azure AD joined", deviceName: victim.host, deviceId: victim.deviceId, asn: 2856,
      sessionId: "0d21b7a9-4e6c-41f8-90a3-2c5b8e14d7a2", isInteractive: true,
      riskLevel: "none", conditionalAccess: "success",
      description:
        "A normal interactive Entra sign-in for j.almeida at 23:00 from London (81.174.71.19), on his compliant, managed Windows workstation with MFA satisfied, his usual session.",
    }), is_baseline: true },

    // 2. THE ATYPICAL SIGN-IN, Sofia, hosting ASN, unmanaged, token-satisfied MFA.
    { ...entraSignIn({
      companyId: "nexacorp", id: "evt_uca_02_atypical_signin", ts: T(0),
      user: victim.email, displayName: victim.name, userTitle: victim.title, userId: victim.userId,
      srcIp: attackerIp, geo: { country: "Bulgaria", city: "Sofia", latitude: 42.6977, longitude: 23.3219 },
      result: "success", severity: "high", app: "Office 365 Exchange Online",
      mfa: false, managed: false, compliant: false, os: "Windows 10", browser: "Chrome 127.0",
      asn: attackerAsn, sessionId: hostileSession, isInteractive: false,
      riskLevel: "high", riskDetail: "none", riskEventTypes: ["unfamiliarFeatures", "anonymizedIPAddress"],
      incomingTokenType: "refreshToken", conditionalAccess: "success",
      authStepResultDetail: "MFA requirement satisfied by claim in the token",
      extra: { "azure.signinlogs.category": "NonInteractiveUserSignInLogs" },
      userAgent: UA,
      mitre: "T1078", tactic: "Initial Access", incidentId: INCIDENT,
      description:
        "A second Entra sign-in for j.almeida arrived at 23:40 from 45.135.232.71 in Sofia, Bulgaria (AS200651, a hosting provider), on an unmanaged device; the MFA requirement was met single-factor, satisfied by a claim already in the presented token.",
    }), authentication: { method: "Previously satisfied", result: "success" } },

    // 3. UEBA ANOMALY #1, impossible travel.
    sentinelUeba({
      companyId: "nexacorp", id: "evt_uca_03_ueba_impossible_travel", ts: T(3 * MIN),
      user: victim.email, userSam: victim.sam, srcIp: attackerIp,
      alertName: "Impossible travel to an atypical location", alertSeverity: "High", severity: "high",
      indicators: ["ImpossibleTravelActivity", "UnfamiliarSignInProperties"],
      anomaly: { type: "ImpossibleTravel", score: 78, reason: "Two sign-ins from distant locations within an impossible window" },
      geoCountry: "Bulgaria", mitre: "T1078", tactic: "Initial Access", incidentId: INCIDENT,
      extendedProperties: {
        "Prior Sign-in Time": T(-40 * MIN),
        "Prior Sign-in Location": "London, GB",
        "Current Sign-in Time": T(0),
        "Current Sign-in Location": "Sofia, BG",
        "Distance (km)": 2020,
        "Elapsed Minutes": 40,
        "Egress ASN": "AS200651 hosting provider (unmanaged device)",
        "Linked Sign-in IDs": ["evt_uca_01_baseline_signin", "evt_uca_02_atypical_signin"],
      },
      description:
        "Sentinel joined the 23:00 London sign-in and the 23:40 Sofia sign-in for j.almeida and raised an impossible-travel anomaly with unfamiliar sign-in properties: ~2,020 km in 40 minutes.",
    }),

    // 4. UEBA ANOMALY #2, anonymous-IP token replay (T1539).
    sentinelUeba({
      companyId: "nexacorp", id: "evt_uca_04_ueba_token_replay", ts: T(4 * MIN),
      user: victim.email, userSam: victim.sam, srcIp: attackerIp,
      alertName: "Sign-in from an anonymous IP address", alertSeverity: "High", severity: "high",
      indicators: ["AnonymousIPAccess", "RiskySignIn"],
      anomaly: { type: "AnonymousIPAddress", score: 74, confidence: "high", reason: "Session presented a pre-existing refresh token from an anonymized IP" },
      geoCountry: "Bulgaria", authStatus: "success", mfa: false, sessionId: hostileSession,
      mitre: "T1539", tactic: "Credential Access", incidentId: INCIDENT,
      extendedProperties: {
        "Incoming Token Type": "refreshToken",
        "Authentication Requirement": "singleFactorAuthentication",
        "Session ID": hostileSession,
      },
      description:
        "Sentinel flagged the Sofia session for j.almeida as an anonymized-IP sign-in that met MFA with a claim already in the token, the session was authenticated by a presented cookie, not a fresh credential prompt.",
    }),

    // 4b. THE SAME SESSION REACHES SHAREPOINT: a non-interactive sign-in under the hostile session id.
    entraSignIn({
      companyId: "nexacorp", id: "evt_uca_04b_sharepoint_signin", ts: T(10 * MIN),
      user: victim.email, displayName: victim.name, userTitle: victim.title, userId: victim.userId,
      srcIp: attackerIp, geo: { country: "Bulgaria", city: "Sofia", latitude: 42.6977, longitude: 23.3219 },
      result: "success", severity: "high", app: "Office 365 SharePoint Online",
      mfa: false, managed: false, compliant: false, os: "Windows 10", browser: "Chrome 127.0",
      asn: attackerAsn, sessionId: hostileSession, isInteractive: false,
      riskLevel: "high", riskDetail: "none", riskEventTypes: ["unfamiliarFeatures", "anonymizedIPAddress"],
      incomingTokenType: "refreshToken", conditionalAccess: "success",
      authStepResultDetail: "MFA requirement satisfied by claim in the token",
      extra: { "azure.signinlogs.category": "NonInteractiveUserSignInLogs" },
      userAgent: UA, incidentId: INCIDENT,
      description: "Non-interactive Entra sign-in for j.almeida to SharePoint Online from 45.135.232.71 under session 6f0b9d47.",
    }),

    // 5. THE MASS DOWNLOAD: a browser download burst from the Finance site (T1213.002).
    //    One FileDownloaded per file; the 10 rows below are the first 5.5 minutes of the burst.
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05_mass_download", ts: T(12 * MIN),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/Budget/${marqueeFile}`,
      fileName: marqueeFile, fileExtension: "xlsx", fileSize: 8_734_208,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/Budget" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description:
        "Beginning 23:52, the Finance site logged FileDownloaded for 340+ files from j.almeida's session at 45.135.232.71 in about six minutes; this and the rows below are the first ten.",
    })),
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05b_dl", ts: T(12 * MIN + 35 * 1_000),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/Forecast/FY26_Q3_Forecast_v4.xlsx`,
      fileName: "FY26_Q3_Forecast_v4.xlsx", fileExtension: "xlsx", fileSize: 6291456,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/Forecast" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "FileDownloaded: FY26_Q3_Forecast_v4.xlsx from the Finance site by j.almeida's session at 45.135.232.71.",
    })),
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05c_dl", ts: T(12 * MIN + 70 * 1_000),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/Treasury/Treasury_Cash_Position_Aug.xlsx`,
      fileName: "Treasury_Cash_Position_Aug.xlsx", fileExtension: "xlsx", fileSize: 2097152,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/Treasury" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "FileDownloaded: Treasury_Cash_Position_Aug.xlsx from the Finance site by j.almeida's session at 45.135.232.71.",
    })),
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05d_dl", ts: T(12 * MIN + 115 * 1_000),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/AP/AP_Vendor_Master_2026.xlsx`,
      fileName: "AP_Vendor_Master_2026.xlsx", fileExtension: "xlsx", fileSize: 11534336,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/AP" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "FileDownloaded: AP_Vendor_Master_2026.xlsx from the Finance site by j.almeida's session at 45.135.232.71.",
    })),
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05e_dl", ts: T(12 * MIN + 160 * 1_000),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/Payroll/Payroll_Summary_Jul26.xlsx`,
      fileName: "Payroll_Summary_Jul26.xlsx", fileExtension: "xlsx", fileSize: 3670016,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/Payroll" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "FileDownloaded: Payroll_Summary_Jul26.xlsx from the Finance site by j.almeida's session at 45.135.232.71.",
    })),
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05f_dl", ts: T(12 * MIN + 200 * 1_000),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/Board/Board_Pack_Q2_Finance.pptx`,
      fileName: "Board_Pack_Q2_Finance.pptx", fileExtension: "pptx", fileSize: 14680064,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/Board" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "FileDownloaded: Board_Pack_Q2_Finance.pptx from the Finance site by j.almeida's session at 45.135.232.71.",
    })),
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05g_dl", ts: T(12 * MIN + 245 * 1_000),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/Treasury/Wire_Approval_Matrix_2026.pdf`,
      fileName: "Wire_Approval_Matrix_2026.pdf", fileExtension: "pdf", fileSize: 905216,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/Treasury" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "FileDownloaded: Wire_Approval_Matrix_2026.pdf from the Finance site by j.almeida's session at 45.135.232.71.",
    })),
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05h_dl", ts: T(12 * MIN + 290 * 1_000),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/Audit/Audit_Workpapers_FY25.zip`,
      fileName: "Audit_Workpapers_FY25.zip", fileExtension: "zip", fileSize: 48234496,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/Audit" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "FileDownloaded: Audit_Workpapers_FY25.zip from the Finance site by j.almeida's session at 45.135.232.71.",
    })),
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05i_dl", ts: T(12 * MIN + 330 * 1_000),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/Intercompany/Intercompany_Recon_Aug.xlsx`,
      fileName: "Intercompany_Recon_Aug.xlsx", fileExtension: "xlsx", fileSize: 4718592,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/Intercompany" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "FileDownloaded: Intercompany_Recon_Aug.xlsx from the Finance site by j.almeida's session at 45.135.232.71.",
    })),
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_05j_dl", ts: T(12 * MIN + 335 * 1_000),
      user: victim.email, userTitle: victim.title, srcIp: attackerIp,
      operation: "FileDownloaded", workload: "SharePoint", eventType: "cloud_storage_access",
      objectId: `${SP}/Credit/Customer_Credit_Limits_2026.xlsx`,
      fileName: "Customer_Credit_Limits_2026.xlsx", fileExtension: "xlsx", fileSize: 2883584,
      siteUrl: "https://nexacorp.sharepoint.com/sites/Finance/", sessionId: hostileSession, userAgent: UA,
      extra: { RecordType: "6", UserType: "Regular", SourceRelativeUrl: "Shared Documents/Credit" },
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "FileDownloaded: Customer_Credit_Limits_2026.xlsx from the Finance site by j.almeida's session at 45.135.232.71.",
    })),

    // 6. THE FORWARDING RULE, New-InboxRule (T1114.003).
    dlRow(m365Operation({
      companyId: "nexacorp", id: "evt_uca_06_inbox_rule", ts: T(18 * MIN),
      user: victim.email, srcIp: attackerIp,
      operation: "New-InboxRule", workload: "Exchange", eventType: "account_modify",
      objectId: "nexacorp.com/Users/Jordan Almeida/Ext backup", sessionId: hostileSession,
      extra: {
        RecordType: "1", UserType: "Regular", ClientIPAddress: attackerIp,
        ClientInfoString: "Client=OWA;Action=ViaProxy", ExternalAccess: "false",
        "Parameters.Name": "Ext backup",
        "Parameters.SubjectOrBodyContainsWords": "invoice;wire;IBAN;remittance;budget",
        "Parameters.ForwardAsAttachmentTo": dropAddress,
        "Parameters.MoveToFolder": "RSS Subscriptions",
        "Parameters.MarkAsRead": "True",
        "Parameters.StopProcessingRules": "True",
      },
      mitre: "T1114.003", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description:
        "An inbox rule named \"Ext backup\" was created on the j.almeida mailbox from 45.135.232.71: mail whose subject or body mentions finance keywords is forwarded to acct.archive.9y@gmail.com and the originals moved to RSS Subscriptions and marked read.",
    })),

    // 7. THE ENTITY RISK SCORE, the case-opening anomaly-driven detection.
    sentinelUeba({
      companyId: "nexacorp", id: "evt_uca_07_entity_risk_score", ts: T(25 * MIN),
      user: victim.email, userSam: victim.sam, srcIp: attackerIp,
      alertName: "User risk level increased to High", alertSeverity: "High", severity: "critical",
      eventType: "risk_score_change", eventAction: "risk-score-update",
      indicators: ["RiskyUser", "ImpossibleTravelActivity", "AnonymousIPAccess", "MassDownloadActivity", "SuspiciousInboxRule", "UnfamiliarSignInProperties"],
      anomaly: { score: 94 },
      risk: { level: "high", score: 94, state: "atRisk" },
      behavior: { name: "account_takeover_pattern", category: "identity", score: 212 },
      department: victim.dept, title: victim.title,
      mitre: "T1078", tactic: "Initial Access", threatTactic: "Initial Access",
      isDetection: true, edrScope: "hybrid", incidentId: INCIDENT,
      extendedProperties: { "Score Window": "25 minutes", "Files Downloaded (SharePoint)": 342 },
      description:
        "Sentinel UEBA raised j.almeida to a high entity risk score, correlating four behaviours in 25 minutes: an impossible-travel sign-in, an anonymous-IP token session, a download burst from the Finance site, and a new mailbox forwarding rule.",
    }),
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 45.135.232.71, the hostile session's hosting-ASN origin
      first_seen: T(0),
      last_seen: T(25 * MIN),
      reputation: "malicious",
      tags: ["session-origin", "hosting-asn"],
    },
    {
      type: "user",
      value: victim.sam, // j.almeida, the compromised account
      first_seen: T(-49 * MIN),
      last_seen: T(25 * MIN),
      reputation: "suspicious",
      tags: ["finance"],
    },
    {
      type: "email",
      value: victim.email, // j.almeida@nexacorp.com, the compromised mailbox
      first_seen: T(-40 * MIN),
      last_seen: T(25 * MIN),
      reputation: "suspicious",
      tags: ["mailbox", "finance"],
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
      value: stealerHash, // svcupd.exe on FIN-LT-Almeida
      first_seen: T(-49 * MIN),
      last_seen: T(-48 * MIN),
      reputation: "malicious",
      tags: ["endpoint", "unsigned"],
    },
    {
      type: "ip",
      value: c2Ip, // where svcupd.exe connected
      first_seen: T(-48 * MIN),
      last_seen: T(-48 * MIN),
      reputation: "malicious",
      tags: ["external", "endpoint-connection"],
    },
    {
      type: "domain",
      value: c2Domain,
      first_seen: T(-48 * MIN - 5_000),
      last_seen: T(-48 * MIN),
      reputation: "malicious",
      tags: ["external", "endpoint-connection"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Unlike every prior case, this investigation does not open with a signature alert. What is the triggering detection here, and what kind of signal is it?",
      hint: "Nothing said 'malware' or 'blocked'. Find the one record that rolls several weak indicators into a single risky-user number.",
      kind: "single",
      options: [
        { value: "ueba_risk_score", label: "The Sentinel UEBA entity risk score reaching High from several weak indicators joined together, the aggregate is the detection, not any single line" },
        { value: "firewall_block", label: "A perimeter firewall denied an outbound session to the Sofia IP, and that single blocked connection is what opened the ticket for the analyst to work" },
        { value: "edr_malware", label: "An EDR endpoint detection flagged a malicious process on j.almeida's laptop, and that host alert is the root the rest of the case hangs off" },
        { value: "dlp_block", label: "A DLP policy blocked the SharePoint file download to the external session, and the blocked action raised the alert that started the investigation" },
      ],
      answer: "ueba_risk_score",
      xp: 55,
      explanation:
        "This is the pack's whole point: an anomaly-driven hunt. The detection is evt_uca_07, a Sentinel UEBA risky-user score that reached High by rolling four behaviours, impossible travel, an anonymous-IP token session, a download burst and a new inbox rule, into one number. No signature fired: there is no firewall block (b), no EDR detection (c) (the laptop's unsigned process was recorded as plain telemetry, nothing alerted on it), and nothing was DLP-blocked (d). The analyst starts from the score and pivots DOWN into the primary telemetry to confirm or dismiss it.",
    },
    {
      id: "q2",
      prompt:
        "You pivot from the score into the two Entra sign-ins (evt_uca_01 baseline, evt_uca_02 atypical). Which combination of sign-in fields confirms the Sofia session is a compromise rather than a benign anomaly?",
      hint: "Compare autonomousSystemNumber, deviceDetail.isManaged/isCompliant, and authenticationRequirement between the London and Sofia sign-ins.",
      kind: "single",
      options: [
        { value: "asn_device_token", label: "The Sofia sign-in is from a hosting ASN on an unmanaged, non-compliant device with MFA met single-factor by a token claim; the baseline is a UK ISP, managed device and full MFA" },
        { value: "resulttype", label: "The Sofia sign-in logs resultType 0 alongside a new location, and in Entra a resultType of 0 recorded from an unfamiliar country is by definition the status code for a compromised logon" },
        { value: "country_alone", label: "The Sofia sign-in is from Bulgaria while the baseline is from the UK, and a successful sign-in from a different country than the user's established baseline is on its own proof of compromise" },
        { value: "appdisplayname", label: "The appDisplayName differs between the two sign-ins, and a switch of client application between consecutive logons is the field-level signature that identifies account takeover" },
      ],
      answer: "asn_device_token",
      xp: 60,
      explanation:
        "The verdict comes from the primary telemetry, read against the baseline. The Sofia sign-in (evt_uca_02) originates from a hosting/VPS ASN, on a device that is neither managed nor compliant, and it sits in the non-interactive sign-in log with authenticationRequirement singleFactorAuthentication, an incoming refreshToken and the step detail 'MFA requirement satisfied by claim in the token': MFA was never re-prompted because a session token was replayed. The same session id then appears on the SharePoint sign-in and on every download. The baseline (evt_uca_01) is the opposite on every one of those fields. (b) over-reads a single field: resultType 0 just means the sign-in succeeded, both did. (c) is exactly the benign-anomaly trap the control disproves: a new country alone is not a verdict. (d) is noise. The compromise is the ASN + unmanaged device + token-satisfied MFA together.",
    },
    {
      id: "q3",
      prompt:
        "evt_uca_00 shows r.laurent tripping the SAME ImpossibleTravelActivity anomaly the same night, yet it is benign. Reading it against j.almeida, what actually separates a real compromise from a false anomaly here?",
      hint: "If the anomaly score decided it, both would be compromises. Compare corroboration in the underlying sign-ins: device compliance, named location, MFA, and what IT verifies about the travel.",
      kind: "single",
      options: [
        { value: "corroboration", label: "Corroboration: r.laurent signs in over the corporate VPN named location on her compliant managed device with MFA and approved travel; j.almeida uses a hosting ASN, an unmanaged device and a replayed token" },
        { value: "score_decides", label: "The score decides it, r.laurent's anomaly score is lower than j.almeida's, and UEBA thresholds are tuned so that score magnitude alone cleanly separates benign anomalies from real account takeovers" },
        { value: "same_verdict", label: "Nothing separates them, both are impossible-travel sign-ins raised the same night by the same anomaly rule, so both accounts should be escalated together and handled as confirmed account compromises" },
        { value: "flagged_or_not", label: "Whether UEBA flagged it, only j.almeida's sign-in was raised by Sentinel, so the presence of the anomaly alert alone distinguishes the two without needing any further sign-in or device context" },
      ],
      answer: "corroboration",
      xp: 60,
      explanation:
        "This is the core skill: a UEBA score is a reason to look, not a verdict. Both users trip ImpossibleTravelActivity, so the anomaly itself cannot decide, that rules out (b) and (d), and (d) is also factually wrong since BOTH were flagged. The difference is corroboration in the underlying sign-ins (evt_uca_00a, evt_uca_00b): r.laurent signs in from the NexaCorp VPN Singapore named location, on the same compliant managed laptop she used in London, with MFA satisfied, and IT confirms an approved travel request, so the anomaly resolves benign (risk.state dismissed). j.almeida has none of that, hosting ASN, unmanaged device, single-factor token session, so his resolves to compromise. (c) is the failure the control exists to prevent: treating every high score as an attack.",
    },
    {
      id: "q4",
      prompt:
        "Two of the behaviours in the score are the attacker acting on the mailbox and the data. Which event is the persistence/collection foothold that would keep feeding the attacker AFTER the session ends?",
      hint: "One event copies files out now; the other quietly re-routes future mail. Which one survives a password reset if left in place?",
      kind: "single",
      options: [
        { value: "inbox_rule", label: "The New-InboxRule forwarding finance mail to an external address and hiding the originals, which keeps exfiltrating new mail until the rule is removed" },
        { value: "mass_download", label: "The 340+ file SharePoint download burst, which staged the finance documents in the attacker's session and is how the stolen data keeps flowing out afterwards" },
        { value: "atypical_signin", label: "The Sofia sign-in from the hosting ASN on an unmanaged device, which is where the attacker got in and so is the foothold every later action depends on" },
        { value: "token_replay", label: "The UEBA anonymous-IP token anomaly, raised because the session ran through an anonymising exit that serves as the attacker's channel for later mailbox access" },
      ],
      answer: "inbox_rule",
      xp: 55,
      explanation:
        "The forwarding rule (evt_uca_06, T1114.003) is the durable foothold: it auto-forwards mail matching finance keywords to an external Gmail address and moves the originals to RSS Subscriptions marked read, so it keeps leaking new correspondence and stays invisible to the user, and it survives a password reset if not explicitly removed. The mass download (b) is collection, but a one-time pull of existing files (T1213.002). The sign-in (c) only establishes access. The token anomaly (d) is a Sentinel detection signal, not an attacker action. Remediation must explicitly delete the rule, not just reset the credential.",
    },
    {
      id: "q5",
      prompt:
        "You are writing the verdict and the response. The evidence is a token-replay sign-in, a download burst and a forwarding rule, all under j.almeida's valid account. How should this be classified and handled?",
      kind: "single",
      options: [
        { value: "compromise_revoke", label: "Confirmed account compromise, revoke j.almeida's sessions and refresh tokens, force a password reset with MFA re-registration, delete the forwarding rule, and review what was downloaded and forwarded" },
        { value: "benign_travel", label: "Benign, the sign-in is impossible travel explained by a trip, every action used his valid account, and the files are ones his role can open, so close it as a UEBA false positive" },
        { value: "reset_only", label: "Reset j.almeida's password and consider it done, a new password invalidates the stolen session and its tokens, so rule removal and token revocation add nothing further" },
        { value: "wait_for_malware", label: "Hold, with no malware, no EDR detection and no blocked action there is no confirmed intrusion, so keep monitoring the account and wait for an endpoint signal before escalating" },
      ],
      answer: "compromise_revoke",
      xp: 65,
      explanation:
        "The primary telemetry confirms takeover: an unsigned process on the laptop copied the browser cookie database and sent it to a hosting address (T1539), a token-replayed sign-in from a hosting ASN on an unmanaged device followed (T1078), then a 340+ file download burst (T1213.002) and a forwarding rule to an external address (T1114.003). Response must REVOKE the stolen session and refresh tokens (a password reset alone does not kill an already-issued token, so (c) is insufficient), force a reset with MFA re-registration, delete the inbox rule, and scope what left. (b) is the benign-anomaly trap the control disproves, the corroboration that cleared r.laurent is absent here. (d) waits for an alert on the endpoint, but the endpoint telemetry that matters is already in the case: the cookie theft happened silently, with no detection. attack_kind is account_compromise, escalate.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Sentinel risk score raised for a Finance manager",
    threat_actor: "External actor operating a stolen session (cloud identity takeover, no host foothold)",
    attack_kind: "account_compromise",
    briefing:
      "Microsoft Sentinel UEBA raised the risk score of j.almeida (Finance Manager) to High overnight. No malware verdict was reported and nothing was blocked, only a score. Pivot from the score into the underlying telemetry and decide whether the account is compromised or the anomalies are benign.",
    narrative: `This is the SOC's first anomaly-driven case: it opens not with a signature alert but with a number. At 00:05 Microsoft Sentinel UEBA raised Jordan Almeida, a Finance Manager, to a High entity risk score, a value built by correlating four behaviours from the preceding half hour, none of them alarming on its own.

At 22:51 an unsigned process, svcupd.exe, started from the Temp folder of his laptop FIN-LT-Almeida, copied the Edge cookie database to a file named Cookies and sent it to 185.225.73.141 (static-cdn-sync.net); Defender for Endpoint recorded the activity but raised nothing. At 23:00 Almeida signed in normally from London, on his compliant, managed workstation, MFA satisfied, the baseline. At 23:40 a second Entra sign-in for the same account arrived from 45.135.232.71 in Sofia, Bulgaria, on a hosting-provider ASN (AS200651), from an unmanaged device, and the MFA requirement was met single-factor, satisfied by a claim already inside a presented token. No password was typed and no push was sent: the stolen session was replayed. Sentinel joined the two sign-ins into an impossible-travel anomaly (~2,020 km in 40 minutes) and separately flagged the Sofia session as an anonymous-IP token replay.

From that session the attacker acted. A non-interactive SharePoint sign-in under the same session id came at 23:50, and from 23:52 the Finance site logged a burst of 340+ FileDownloaded operations (10 shown), far above Almeida's ~15-files-a-day norm. At 23:58 a new Exchange inbox rule, "Ext backup", was created: mail mentioning invoice, wire, IBAN, remittance or budget is forwarded to acct.archive.9y@gmail.com and the originals moved to RSS Subscriptions and marked read, a quiet, durable channel that survives a password reset. At 00:05 UEBA rolled all four signals into the risky-user score that opened this ticket.

The instructive comparison is Renée Laurent, a Sales director, who tripped the SAME impossible-travel anomaly the same night, London to Singapore. But her Singapore sign-in came over the NexaCorp VPN Singapore named location, on the same compliant managed laptop she used in London, with MFA satisfied, and IT holds an approved travel request, so her anomaly resolves benign. Same score-shape, opposite verdict. The lesson of a UEBA hunt is exactly that: a high score is a reason to look, and the verdict is reached from the primary sign-in and audit telemetry underneath it, not from the alert title.`,
    learning_objectives: [
      "Run an anomaly-driven (UEBA-led) investigation: start from a Sentinel entity risk score built by correlation, then pivot DOWN into the primary Entra and O365 telemetry to confirm or dismiss it",
      "Confirm a compromised sign-in (T1078) from Entra fields (hosting ASN, unmanaged/non-compliant device, an MFA requirement satisfied single-factor by a replayed session token) read against the account's own baseline sign-in, and find the cookie theft (T1539) that supplied the session on the victim's endpoint",
      "Recognise a mass download from a cloud information repository (T1213.002) and a malicious mailbox forwarding rule (T1114.003) as the primary telemetry behind MassDownloadActivity and SuspiciousInboxRule anomalies",
      "Distinguish a real account compromise from a benign UEBA anomaly using corroboration (device compliance, egress ASN, MFA, approved-travel context) rather than the anomaly score alone",
      "Scope response for a cloud identity takeover: revoke sessions and refresh tokens, reset with MFA re-registration, delete the forwarding rule, and review what was downloaded and forwarded",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-3 * HOUR), phase: "Context", action: "Benign control, r.laurent trips ImpossibleTravel but is corroborated (corporate VPN, compliant device, MFA, approved travel)" },
      { ts: T(-49 * MIN), phase: "Credential Access", action: "Unsigned svcupd.exe on FIN-LT-Almeida copies the Edge cookie database and sends it to 185.225.73.141 (T1539)" },
      { ts: T(-40 * MIN), phase: "Baseline", action: `Normal Entra sign-in for ${victim.sam} from London, compliant managed device, MFA satisfied` },
      { ts: T(0), phase: "Initial Access", action: `Atypical Entra sign-in for ${victim.sam} from Sofia (AS200651), unmanaged device, token-satisfied MFA (T1078)` },
      { ts: T(3 * MIN), phase: "Detection", action: "Sentinel raises impossible-travel + unfamiliar-properties anomaly" },
      { ts: T(4 * MIN), phase: "Credential Access", action: "Sentinel flags the Sofia session as an anonymous-IP replayed-token sign-in (T1539)" },
      { ts: T(10 * MIN), phase: "Initial Access", action: "Non-interactive SharePoint Online sign-in under the same hostile session id (T1078)" },
      { ts: T(12 * MIN), phase: "Collection", action: "340+ FileDownloaded from the Finance site: download burst above baseline (T1213.002)" },
      { ts: T(18 * MIN), phase: "Collection", action: `New Exchange inbox rule forwards finance mail to ${dropAddress} and hides originals (T1114.003)` },
      { ts: T(25 * MIN), phase: "Detection", action: "Sentinel UEBA rolls all four behaviours into a High risky-user score, the case opens" },
    ],
    questions,
  };
}
