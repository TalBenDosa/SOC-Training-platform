/**
 * Scenario pack: "Free Converter, Stolen Session — Infostealer Cookie Theft & Replay"
 *
 * CORE tier. One user, one laptop, then a hop onto the identity plane — no
 * lateral movement inside the network. This is the #1 real-world credential
 * source per the Verizon DBIR: a commodity infostealer (Lumma/StealC-style),
 * not a phishing email and not a compromised legitimate site.
 *
 * r.avidan looks for a free "PDF to Word" converter, downloads an unsigned
 * installer from a freeware aggregator, and runs it. It never installs
 * anything. In the seconds it runs it copies two files out of her Chrome
 * profile: Login Data (the saved-password SQLite database) and the Cookies
 * database under Network\ (her live session cookies) — copies, not reads,
 * because Chrome holds both files open and locked while it runs. Both are
 * POSTed to the stealer's collection endpoint as a small archive.
 *
 * Five minutes later the payoff: Entra ID logs a new, successful sign-in on
 * her account from an IP that has never appeared for her, on a device that
 * has never enrolled — with no password prompt and no Authenticator
 * approval, because a stolen session cookie already satisfies the MFA
 * requirement. No field anywhere says "stolen" or "replay". The tell is
 * built from three things read together: the EDR event that shows the
 * Cookies database being copied off her endpoint, the timing (minutes, not
 * hours, later), and the Entra sign-in's own authentication fields —
 * isInteractive: false, authenticationDetails showing no step performed,
 * incomingTokenType: "primaryRefreshToken" — none of which is an
 * "anomaly score", all of which are real fields Entra actually emits.
 *
 * Covers T1555.003 (Credentials from Web Browsers), T1539 (Steal Web
 * Session Cookie), T1204.002 (User Execution: Malicious File) and
 * T1550.004 (Use Alternate Authentication Material: Web Session Cookie).
 *
 * SOURCES: edr (CrowdStrike Falcon), firewall (Palo Alto Networks NGFW),
 * o365 (Microsoft Entra ID / Microsoft 365 Unified Audit Log).
 *
 * NOTE: `difficulty: "core"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildInfostealerSessionTheftScenario(
  scenarioId = "infostealer-session-theft-2026",
): ScenarioBundle {
  const B = new Date("2026-07-08T07:52:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;
  const SEC = 1_000;

  const host = { hostname: "LAP-6688", ip: "10.14.31.92" };
  const victim = { email: "r.avidan@nexacorp.com", name: "Reut Avidan", sam: "r.avidan" };
  const sensorId = "d81f6c204b3e4a97a1c85e0d2f7936ab";

  const lureDomain = "freeware-pdftools.net";
  const lureIp = "104.21.44.187";
  const c2Domain = "telemetry-cdn-relay.net";
  const c2Ip = "185.220.101.47";
  const corpEgress = "84.110.12.9";
  const replayIp = "91.243.24.19";

  const installerHash = makeSha256("pdf_converter_pro_setup_freeware_pdftools_2026");

  const userId = "9c4a2f18-5e73-4b06-8d91-2f7c4a6e9b35";
  const deviceIdBaseline = "b7f4a913-6c82-4e05-91a7-3d8c4f207b56";
  const sessionIdBaseline = "72d4f8a1-3b96-4e02-8c15-9a6d7e4f2b81";
  const sessionIdReplay = "e9c2a705-1f84-4b36-a927-6d0e5c3f819a";
  const correlationIdReplay = "b3e97a41-2c85-4d16-9f07-1a4c8e6d3b52";
  const officeAppId = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
  const mfaPolicyId = "1f0b6c93-7d24-4a5e-8b90-c3f27a641e58";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. Baseline. Her own morning sign-in — real MFA, her own device.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_01_baseline_signin",
      ts: T(0),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      severity: "informational",
      user_email: victim.email,
      user_title: "Account Executive",
      src_ip: corpEgress,
      geo: { country: "Israel", city: "Tel Aviv", latitude: 32.0853, longitude: 34.7818 },
      authentication: { method: "Password + Microsoft Authenticator", mfa_type: "push", result: "success" },
      description:
        "Entra ID recorded r.avidan's ordinary interactive sign-in at 07:52, MFA satisfied by a live Authenticator push, from her enrolled laptop LAP-6688 on the Tel Aviv corporate egress.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "1a7c9f04-3e82-4b16-9d05-7a4c2e8f6b91",
        "azure.signinlogs.properties.createdDateTime": T(0),
        "azure.signinlogs.properties.userPrincipalName": victim.email,
        "azure.signinlogs.properties.userDisplayName": victim.name,
        "azure.signinlogs.properties.userId": userId,
        "azure.signinlogs.properties.correlationId": "4a8f1c92-6d37-4e05-b8a1-9f2c6d4e7a13",
        "azure.signinlogs.properties.sessionId": sessionIdBaseline,
        "azure.signinlogs.properties.appDisplayName": "Microsoft Office",
        "azure.signinlogs.properties.appId": officeAppId,
        "azure.signinlogs.properties.resourceDisplayName": "Microsoft Graph",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": true,
        "azure.signinlogs.properties.ipAddress": corpEgress,
        "azure.signinlogs.properties.autonomousSystemNumber": 8551,
        "azure.signinlogs.properties.location.city": "Tel Aviv",
        "azure.signinlogs.properties.location.state": "Tel Aviv",
        "azure.signinlogs.properties.location.countryOrRegion": "IL",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 32.0853,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": 34.7818,
        "azure.signinlogs.properties.deviceDetail.deviceId": deviceIdBaseline,
        "azure.signinlogs.properties.deviceDetail.displayName": "LAP-6688",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 11",
        "azure.signinlogs.properties.deviceDetail.browser": "Edge 125.0.2535",
        "azure.signinlogs.properties.deviceDetail.isCompliant": true,
        "azure.signinlogs.properties.deviceDetail.isManaged": true,
        "azure.signinlogs.properties.deviceDetail.trustType": "Azure AD joined",
        "azure.signinlogs.properties.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.51",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationStepDateTime: T(0 - 12 * SEC),
            authenticationMethod: "Password",
            authenticationMethodDetail: "Password in the cloud",
            succeeded: true,
            authenticationStepResultDetail: "Correct password",
            authenticationStepRequirement: "Primary authentication",
          },
          {
            authenticationStepDateTime: T(0 - 3 * SEC),
            authenticationMethod: "Mobile app notification",
            authenticationMethodDetail: "Microsoft Authenticator",
            succeeded: true,
            authenticationStepResultDetail: "MFA completed in Azure AD",
            authenticationStepRequirement: "Multifactor authentication",
          },
        ],
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.appliedConditionalAccessPolicies": [
          {
            id: mfaPolicyId,
            displayName: "Require MFA for all users",
            result: "success",
            enforcedGrantControls: ["Mfa"],
            enforcedSessionControls: [],
          },
        ],
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "none",
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.resultType": "0",
      },
    },

    // ---------------------------------------------------------------------
    // 2. She downloads a free converter from a freeware aggregator.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_02_lure_download",
      ts: T(3 * HOUR + 41 * MIN),
      source: "firewall",
      vendor: "Palo Alto Networks NGFW",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      description:
        "At 11:33 LAP-6688 downloaded PDF_Converter_Pro_Setup.exe from freeware-pdftools.net, referred by a Google search for a free PDF-to-Word converter.",
      file: { name: "PDF_Converter_Pro_Setup.exe", path: "/download/PDF_Converter_Pro_Setup.exe", extension: "exe", size: 2_894_336, sha256: installerHash },
      network: {
        url: `https://${lureDomain}/download/PDF_Converter_Pro_Setup.exe`,
        domain: lureDomain,
        method: "GET",
        status: 200,
        bytes_in: 2_894_336,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "file",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": lureIp,
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "shareware-download",
        "pan.url": `${lureDomain}/download/PDF_Converter_Pro_Setup.exe`,
        "pan.referer": "https://www.google.com/search?q=free+pdf+to+word+converter+download",
        "pan.filename": "PDF_Converter_Pro_Setup.exe",
        "pan.filetype": "pe",
        "pan.file_hash": installerHash,
        "pan.direction": "download",
        "pan.session_id": "551204",
        "source.ip": host.ip,
        "url.domain": lureDomain,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 3. The file lands in Downloads, as the endpoint saw it.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_03_file_write",
      ts: T(3 * HOUR + 41 * MIN + 6 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "low",
      description: "chrome.exe wrote C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe at 11:33:06.",
      file: {
        name: "PDF_Converter_Pro_Setup.exe",
        path: "C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe",
        extension: "exe",
        size: 2_894_336,
        sha256: installerHash,
      },
      raw: {
        "crowdstrike.event_simpleName": "NewExecutableWritten",
        "crowdstrike.sensor.id": sensorId,
        "event.action": "file_created",
        "file.name": "PDF_Converter_Pro_Setup.exe",
        "file.path": "C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe",
        "file.extension": "exe",
        "file.size": "2894336",
        "file.hash.sha256": installerHash,
        "process.name": "chrome.exe",
        "process.pid": "6204",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 4. She runs it. Unsigned, from Downloads, parent explorer.exe.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_04_execute",
      ts: T(3 * HOUR + 47 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1204.002",
      mitre_tactic: "Execution",
      description: "At 11:39:00 explorer.exe started the unsigned PDF_Converter_Pro_Setup.exe from Downloads.",
      process: {
        name: "PDF_Converter_Pro_Setup.exe",
        pid: 7188,
        path: "C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe",
        parent_name: "explorer.exe",
        parent_pid: 3844,
        cmdline: '"C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe"',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: installerHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.name": "PDF_Converter_Pro_Setup.exe",
        "process.pid": "7188",
        "process.executable": "C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe",
        "process.command_line": '"C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe"',
        "process.hash.sha256": installerHash,
        "process.signed": "false",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3844",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 5. Login Data copied out of the locked Chrome profile — passwords.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_05_logindata_copy",
      ts: T(3 * HOUR + 47 * MIN + 4 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1555.003",
      mitre_tactic: "Credential Access",
      description:
        "PDF_Converter_Pro_Setup.exe created C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Login Data, 104 KB — the same filename Chrome uses for its own saved-password SQLite database, which was still open and locked in the running browser. Local State, which holds the key Chrome uses to decrypt that database, was written to the same folder seconds earlier.",
      file: {
        name: "Login Data",
        path: "C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Login Data",
        size: 106_496,
      },
      raw: {
        "crowdstrike.sensor.id": sensorId,
        "event.action": "file_created",
        "file.name": "Login Data",
        "file.path": "C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Login Data",
        "file.size": "106496",
        "process.name": "PDF_Converter_Pro_Setup.exe",
        "process.pid": "7188",
        "process.parent.name": "explorer.exe",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 6. Cookies database copied — this is the session, not just passwords.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_06_cookies_copy",
      ts: T(3 * HOUR + 47 * MIN + 9 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1539",
      mitre_tactic: "Credential Access",
      description:
        "Five seconds later the same process created C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Network\\Cookies, 60 KB — Chrome's own cookie store, copied out of its locked location in the same staging folder as Login Data.",
      file: {
        name: "Cookies",
        path: "C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Network\\Cookies",
        size: 61_440,
      },
      raw: {
        "crowdstrike.sensor.id": sensorId,
        "event.action": "file_created",
        "file.name": "Cookies",
        "file.path": "C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Network\\Cookies",
        "file.size": "61440",
        "process.name": "PDF_Converter_Pro_Setup.exe",
        "process.pid": "7188",
        "process.parent.name": "explorer.exe",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 7. It leaves the building.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_07_exfil",
      ts: T(3 * HOUR + 47 * MIN + 24 * SEC),
      source: "firewall",
      vendor: "Palo Alto Networks NGFW",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1041",
      mitre_tactic: "Exfiltration",
      description:
        "At 11:39:24 the host POSTed a 178 KB archive to telemetry-cdn-relay.net/api/v2/upload, allowed under the category unknown.",
      network: {
        url: `https://${c2Domain}/api/v2/upload`,
        domain: c2Domain,
        method: "POST",
        status: 200,
        bytes_out: 182_304,
        bytes_in: 54,
      },
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": c2Ip,
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "unknown",
        "pan.url": `${c2Domain}/api/v2/upload`,
        "pan.http_method": "POST",
        "pan.bytes_sent": "182304",
        "pan.bytes_received": "54",
        "pan.session_id": "551247",
        "source.ip": host.ip,
        "url.domain": c2Domain,
        "http.request.method": "POST",
        "action_result": "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 8. THE CRUX — a new session, five minutes later, no MFA interaction.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_08_session_replay",
      ts: T(3 * HOUR + 52 * MIN + 40 * SEC),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      severity: "critical",
      mitre_technique: "T1550.004",
      mitre_tactic: "Defense Evasion",
      user_email: victim.email,
      user_title: "Account Executive",
      src_ip: replayIp,
      geo: { country: "Russia", city: "Moscow", latitude: 55.7558, longitude: 37.6173 },
      description:
        "A second, non-interactive Entra sign-in for r.avidan completed from 91.243.24.19 in Moscow on an unmanaged Windows 10 / Chrome 124 device — five minutes after Falcon saw her Cookies database copied on LAP-6688. Multifactor was satisfied by a claim already present in the token.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "6d1c8f30-9a54-4b27-8e16-3c7a2d5f804b",
        "azure.signinlogs.properties.createdDateTime": T(3 * HOUR + 52 * MIN + 40 * SEC),
        "azure.signinlogs.properties.userPrincipalName": victim.email,
        "azure.signinlogs.properties.userDisplayName": victim.name,
        "azure.signinlogs.properties.userId": userId,
        "azure.signinlogs.properties.correlationId": correlationIdReplay,
        "azure.signinlogs.properties.sessionId": sessionIdReplay,
        "azure.signinlogs.properties.appDisplayName": "Microsoft Office",
        "azure.signinlogs.properties.appId": officeAppId,
        "azure.signinlogs.properties.resourceDisplayName": "Microsoft Graph",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": false,
        "azure.signinlogs.properties.ipAddress": replayIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 197695,
        "azure.signinlogs.properties.location.city": "Moscow",
        "azure.signinlogs.properties.location.state": "Moscow",
        "azure.signinlogs.properties.location.countryOrRegion": "RU",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 55.7558,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": 37.6173,
        "azure.signinlogs.properties.deviceDetail.deviceId": "",
        "azure.signinlogs.properties.deviceDetail.displayName": "",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 10",
        "azure.signinlogs.properties.deviceDetail.browser": "Chrome 124.0.6367",
        "azure.signinlogs.properties.deviceDetail.isCompliant": false,
        "azure.signinlogs.properties.deviceDetail.isManaged": false,
        "azure.signinlogs.properties.deviceDetail.trustType": "",
        "azure.signinlogs.properties.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationStepDateTime: T(3 * HOUR + 52 * MIN + 40 * SEC),
            authenticationMethod: "Previously satisfied",
            authenticationMethodDetail: "",
            succeeded: true,
            authenticationStepResultDetail: "MFA requirement satisfied by claim in the token",
            authenticationStepRequirement: "Multifactor authentication",
          },
        ],
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.appliedConditionalAccessPolicies": [
          {
            id: mfaPolicyId,
            displayName: "Require MFA for all users",
            result: "success",
            enforcedGrantControls: ["Mfa"],
            enforcedSessionControls: [],
          },
        ],
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.riskEventTypes_v2": [],
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "primaryRefreshToken",
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.resultType": "0",
      },
    },

    // ---------------------------------------------------------------------
    // 9. The endpoint verdict, arriving after the transfer and the replay.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_09_edr_alert",
      ts: T(3 * HOUR + 53 * MIN + 10 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1555.003",
      mitre_tactic: "Credential Access",
      description:
        "Falcon raised a Critical detection on LAP-6688 for browser-credential-store staging and killed PDF_Converter_Pro_Setup.exe — after the archive had already left the host and the stolen session had already been used.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "BrowserCredentialStoreStagingAndTransfer",
        "crowdstrike.detection.description":
          "An unsigned process copied Chrome's Login Data and Cookies databases out of the browser profile and transferred data to external infrastructure shortly afterward.",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.severity_name": "Critical",
        "crowdstrike.detection.confidence": "85",
        "crowdstrike.detection.tactic": "Credential Access",
        "crowdstrike.detection.technique": "Credentials from Web Browsers",
        "crowdstrike.detection.technique_id": "T1555.003",
        "crowdstrike.detection.pattern_disposition_description": "Detection, Process Killed",
        "crowdstrike.detection.parent_process": "explorer.exe",
        "crowdstrike.detection.process_tree": "explorer.exe > PDF_Converter_Pro_Setup.exe",
        "crowdstrike.sensor.id": sensorId,
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.falcon_host_link": "https://falcon.crowdstrike.com/activity/detections/detail/9e21a7c4",
        "event.action": "alert",
        "event.outcome": "blocked",
        "host.name": host.hostname,
        "host.ip": host.ip,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 10. The replayed session reaches into SharePoint.
    // ---------------------------------------------------------------------
    {
      id: "evt_ist_10_sharepoint_access",
      ts: T(3 * HOUR + 53 * MIN + 55 * SEC),
      source: "o365",
      vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call",
      severity: "high",
      mitre_technique: "T1213.002",
      mitre_tactic: "Collection",
      user_email: victim.email,
      src_ip: replayIp,
      geo: { country: "Russia", city: "Moscow" },
      cloud: { provider: "Microsoft", service: "SharePoint Online", api_call: "FileAccessed", resource: "sites/Sales/Shared Documents/Q3_Pipeline_Forecast.xlsx" },
      description:
        "The replayed session opened Q3_Pipeline_Forecast.xlsx under /sites/Sales/Shared Documents from 91.243.24.19 — the same account, the same unmanaged Chrome 124 session that signed in a minute earlier.",
      raw: {
        "data.office365.Operation": "FileAccessed",
        "data.office365.RecordType": "6",
        "data.office365.Workload": "SharePoint",
        "data.office365.UserId": victim.email,
        "data.office365.UserType": "0",
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ClientIP": replayIp,
        "data.office365.UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "data.office365.SiteUrl": "https://nexacorp.sharepoint.com/sites/Sales",
        "data.office365.SourceRelativeUrl": "Shared Documents",
        "data.office365.SourceFileName": "Q3_Pipeline_Forecast.xlsx",
        "data.office365.ObjectId": "https://nexacorp.sharepoint.com/sites/Sales/Shared Documents/Q3_Pipeline_Forecast.xlsx",
        "data.office365.ItemType": "File",
        "data.office365.EventSource": "SharePoint",
        "data.office365.SessionId": sessionIdReplay,
        "data.office365.CorrelationId": correlationIdReplay,
        "source.ip": replayIp,
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "domain",
      value: lureDomain,
      first_seen: T(3 * HOUR + 41 * MIN),
      last_seen: T(3 * HOUR + 41 * MIN),
      reputation: "suspicious",
      tags: ["freeware-aggregator", "infostealer-lure"],
    },
    {
      type: "domain",
      value: c2Domain,
      first_seen: T(3 * HOUR + 47 * MIN + 24 * SEC),
      last_seen: T(3 * HOUR + 47 * MIN + 24 * SEC),
      reputation: "malicious",
      tags: ["c2", "exfil"],
    },
    {
      type: "sha256",
      value: installerHash,
      first_seen: T(3 * HOUR + 41 * MIN),
      last_seen: T(3 * HOUR + 53 * MIN + 10 * SEC),
      reputation: "malicious",
      tags: ["infostealer", "unsigned"],
    },
    {
      type: "ip",
      value: replayIp,
      first_seen: T(3 * HOUR + 52 * MIN + 40 * SEC),
      last_seen: T(3 * HOUR + 53 * MIN + 55 * SEC),
      reputation: "malicious",
      tags: ["account-takeover", "unrecognised-device"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(3 * HOUR + 53 * MIN + 10 * SEC),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
    {
      type: "user",
      value: victim.email,
      first_seen: T(0),
      last_seen: T(3 * HOUR + 53 * MIN + 55 * SEC),
      reputation: "suspicious",
      tags: ["compromised-account", "session-hijacked"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Two file-creation events copy files out of the Chrome profile seconds apart. Which one shows that the attacker got more than saved passwords?",
      hint: "Compare the filename and path in evt_ist_05 against evt_ist_06 — what does each database actually store?",
      kind: "single",
      options: [
        { value: "cookies", label: "evt_ist_06_cookies_copy — the Cookies database under Network\\, which holds live session state, not passwords" },
        { value: "logindata", label: "evt_ist_05_logindata_copy — Login Data is Chrome's full credential vault, so it already covers everything" },
        { value: "execute", label: "evt_ist_04_execute — running an unsigned installer is itself proof that all site sessions are exposed" },
        { value: "alert", label: "evt_ist_09_edr_alert — Falcon's detection name is what confirms session data was taken" },
      ],
      answer: "cookies",
      xp: 50,
      explanation:
        "Login Data (evt_ist_05) is Chrome's saved-password store — serious, but it only ever contained credentials the user chose to save, and taking it is squarely T1555.003. Cookies (evt_ist_06), copied five seconds later from the Network\\ subfolder, is a different asset entirely: it holds the session tokens that are currently keeping her signed in everywhere, including sites with no saved password at all. That is T1539, Steal Web Session Cookie, and it is what makes evt_ist_08 possible without the attacker ever needing her password. Running the installer (option c) is necessary but not sufficient — plenty of unsigned installers don't touch the browser profile at all, so the execution event alone doesn't tell you what was taken. Falcon's detection name (option d) is a human-readable label built by the vendor after the fact; it names the technique but isn't itself the evidence — the two file paths are.",
    },
    {
      id: "q2",
      prompt:
        "The Moscow sign-in for r.avidan shows conditionalAccessStatus: success and riskLevelDuringSignIn: none. What specifically marks it as a replayed session rather than an ordinary new-device login?",
      hint: "Look at what authenticationDetails contains on evt_ist_08 versus what it contains on evt_ist_01 — and what happened on the endpoint five minutes earlier.",
      kind: "single",
      options: [
        {
          value: "correlation",
          label: "authenticationDetails shows no password or MFA step at all — just a prior-token claim — on an unmanaged device, arriving five minutes after Falcon saw her Cookies file staged on LAP-6688",
        },
        { value: "risk_field", label: "riskLevelDuringSignIn should read \"high\" for any sign-in from Russia, so this record is clearly mislabelled" },
        { value: "geo_alone", label: "The IP resolves outside Israel, and any sign-in from a country she has never visited is a takeover by definition" },
        { value: "ca_status", label: "conditionalAccessStatus only reads \"success\" on legitimate sign-ins — a hijacked session would show \"failure\"" },
      ],
      answer: "correlation",
      xp: 60,
      explanation:
        "This is the marquee distinction of the whole scenario. Nothing on evt_ist_08 is individually alarming — riskLevelDuringSignIn is none and conditionalAccessStatus is success, exactly like the benign baseline in evt_ist_01. What differs is structural: evt_ist_01's authenticationDetails carries a real Password step followed by a real Microsoft Authenticator approval, seconds apart, on a compliant Azure-AD-joined device; evt_ist_08's authenticationDetails has a single entry, authenticationMethod 'Previously satisfied', on a device with no deviceId and no compliance state at all — nobody authenticated, a token already carried the MFA claim (incomingTokenType: primaryRefreshToken). Layer on the timing: this sign-in lands five minutes after evt_ist_06 shows the same account's Cookies database being copied off her endpoint by an unrelated process. That combination — no interactive auth step, unrecognised unmanaged device, immediately downstream of a browser-cookie theft — is the tell. Option (b) is a trap: the risk engine did not flag this sign-in at all, which is the point being taught, not a bug to explain away. Option (c) would also flag every legitimate business trip. Option (d) misunderstands the field: conditionalAccessStatus reports whether the configured policy's grant controls were satisfied, and a stolen token that already carries an MFA claim satisfies them just fine.",
    },
    {
      id: "q3",
      prompt: "The 178 KB archive left LAP-6688 for telemetry-cdn-relay.net without ever being blocked. Why?",
      kind: "single",
      options: [
        {
          value: "no_signal",
          label: "pan.category is \"unknown\" — an unrated destination — and a sub-200 KB outbound POST has nothing in the raw fields that distinguishes it from routine web traffic",
        },
        { value: "tls_off", label: "TLS inspection was disabled for this session, so the firewall never saw the request at all" },
        { value: "monitor_mode", label: "CORP-WEB-OUTBOUND was set to monitor-only for every category, so nothing on this firewall ever blocks" },
        { value: "allowlist", label: "telemetry-cdn-relay.net was already on an explicit corporate allowlist" },
      ],
      answer: "no_signal",
      xp: 40,
      explanation:
        "pan.category: 'unknown' means the domain simply hasn't been rated yet — a brand-new or low-traffic host, which describes most C2 infrastructure at first contact. pan.action: 'allow' on this rule for an unrated category is a policy choice, the same log-not-block posture seen on newly-registered domains elsewhere in this platform's scenarios: the false-positive cost of hard-blocking every unrated site is high. Nothing else in the record helps either — 182,304 bytes is an unremarkable size for an image, a document, or an API call, so there's no volume-based signal to catch it on. Option (b) is contradicted by the log itself, which has a full URL, method and byte counts — TLS inspection was clearly active. Option (c) is disproven by evt_ist_02, where the same rule set logged a shareware-download category distinctly. Option (d) has nothing supporting it and doesn't fit a domain the log itself still treats as unrated.",
    },
    {
      id: "q4",
      prompt:
        "Given that both Login Data and the Cookies database were copied before Falcon quarantined the installer, what does full containment actually require?",
      kind: "single",
      options: [
        {
          value: "full_scope",
          label: "Revoke r.avidan's active sessions and refresh tokens, reset her password, and treat every site saved in that Chrome profile — not only her corporate account — as exposed",
        },
        { value: "password_only", label: "Resetting her domain password is sufficient, because both stolen files were local artifacts on the laptop" },
        { value: "reimage_only", label: "Reimaging LAP-6688 resolves the exposure; nothing that already left the host needs to be revoked or reset" },
        { value: "ip_block_only", label: "Block replayIp and c2Domain at the firewall — that removes the attacker's access to the account" },
      ],
      answer: "full_scope",
      xp: 60,
      explanation:
        "evt_ist_08 already shows why option (b) fails: the sign-in there needed no password at all, because the stolen session cookie carried its own valid token — a password reset does nothing to a session that has already been issued and is already in use, which is exactly why evt_ist_10 (SharePoint access) still succeeds after the fact. Revoking sessions and refresh tokens is what actually invalidates the token the attacker is holding; the password reset matters for the credential that was also taken in evt_ist_05, but on its own it's not containment. Option (c) fixes the endpoint but ignores that the data, and the live session built from it, are already off the host — reimaging LAP-6688 does not reach into Entra ID. Option (d) blocks two indicators the attacker can trivially rotate; it does nothing about the token already issued to their current session. And because Login Data holds every saved password in that Chrome profile, not just the corporate one, scope has to extend past the domain account to whatever personal or third-party sites she had saved there.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Free Converter, Stolen Session — Infostealer Cookie Theft & Replay",
    threat_actor: "Commodity infostealer distributor (Lumma/StealC-style MaaS)",
    attack_kind: "infostealer_session_theft",
    briefing:
      "CrowdStrike Falcon raised a Critical detection on LAP-6688 at 11:45 for a process copying files out of r.avidan's Chrome profile and transferring data externally. Around the same time, Entra ID logged a new sign-in on her account from an IP address that has never appeared for her before. Work out what was taken, whether the two events are connected, and what — if anything — an attacker can still do with it.",
    narrative: `r.avidan's morning starts normally: an ordinary interactive sign-in at 07:52 from her own laptop, password plus a live Authenticator approval, nothing about it worth a second look.

At 11:33 she searches for a free PDF-to-Word converter and downloads PDF_Converter_Pro_Setup.exe from freeware-pdftools.net. Chrome writes it to her Downloads folder six seconds later. At 11:39:00 she runs it — unsigned, launched by explorer.exe, nothing unusual to see in the process tree by itself.

What it does next is the whole incident. Four seconds in, it creates a copy of Chrome's Local State and Login Data — the saved-password database — inside a Temp staging folder, because the real files are locked open by the running browser. Five seconds after that it copies the Cookies database too, from Network\\, the file that holds her live, already-authenticated session state for every site she's signed into. At 11:39:24 both are POSTed as a small archive to telemetry-cdn-relay.net, allowed through the firewall under the category unknown — nothing about a 178 KB outbound request stands out.

Five minutes later, at 11:44:40, Entra ID logs a second sign-in for r.avidan. This one comes from 91.243.24.19 in Moscow, on a Windows 10 machine running Chrome 124 that has never enrolled anywhere in the tenant. There is no password prompt and no Authenticator push — the sign-in's own authenticationDetails records a single step, 'Previously satisfied', because the session cookie the attacker is holding already carries a valid MFA claim. Conditional Access reports success. Risk scoring reports none. A minute later that session opens a sales forecast on SharePoint.

Falcon's behavioural engine catches up at 11:45:10, quarantining PDF_Converter_Pro_Setup.exe — a full six minutes after the credential archive left the building, and thirty seconds after the stolen session had already been used.`,
    learning_objectives: [
      "Recognise infostealer credential harvesting as a distinct chain from phishing or a compromised legitimate site — a cracked/freeware lure that never installs anything",
      "Identify local browser-credential-store theft (T1555.003) and session-cookie theft (T1539) from copied database filenames appearing outside Chrome's own locked profile",
      "Read Entra sign-in fields — isInteractive, authenticationDetails, incomingTokenType — to recognise a session satisfied by a replayed token rather than a fresh interactive logon",
      "Correlate an EDR credential-theft event with an identity-plane sign-in by account and timing, not by a shared technical identifier",
      "Scope containment correctly when both a password store and a session cookie were stolen: revoke sessions and tokens before — not instead of — resetting the password",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(3 * HOUR + 41 * MIN), phase: "Resource Development", action: `r.avidan downloads a cracked/freeware installer from ${lureDomain}` },
      { ts: T(3 * HOUR + 47 * MIN), phase: "Execution", action: "User runs the unsigned installer (T1204.002)" },
      { ts: T(3 * HOUR + 47 * MIN + 4 * SEC), phase: "Credential Access", action: "Chrome's Login Data (saved passwords) copied out of the locked profile (T1555.003)" },
      { ts: T(3 * HOUR + 47 * MIN + 9 * SEC), phase: "Credential Access", action: "Chrome's Cookies database (live session state) copied out of the locked profile (T1539)" },
      { ts: T(3 * HOUR + 47 * MIN + 24 * SEC), phase: "Exfiltration", action: `Harvested archive POSTed to ${c2Domain} (T1041)` },
      { ts: T(3 * HOUR + 52 * MIN + 40 * SEC), phase: "Defense Evasion", action: "Stolen session replayed from Moscow on an unmanaged device — MFA satisfied by a primary refresh token, no interactive step (T1550.004)" },
      { ts: T(3 * HOUR + 53 * MIN + 10 * SEC), phase: "Detection", action: "Falcon raises a Critical detection and quarantines the installer — after the transfer and the replay" },
      { ts: T(3 * HOUR + 53 * MIN + 55 * SEC), phase: "Collection", action: "Replayed session opens a sales forecast on SharePoint" },
    ],
    questions,
  };
}
