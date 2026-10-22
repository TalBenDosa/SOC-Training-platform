/**
 * Events-only half of the ./infostealerSessionTheft.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./infostealerSessionTheft.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { panWeb, panConnection } from "@/lib/sim/emitters/paloalto";
import { csProcess, csFile, csAlert, csDns, csNetwork } from "@/lib/sim/emitters/crowdstrike";
import { m365Operation } from "@/lib/sim/emitters/m365";

/** Telemetry half of `buildInfostealerSessionTheftScenario`: the events and the story title, no answer key. */
export function infostealerSessionTheftScenarioEvents() {
  const B = new Date("2026-07-08T07:52:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;
  const SEC = 1_000;

  const host = { hostname: "LAP-6688", ip: "10.14.31.92" };
  const victim = { email: "r.avidan@nexacorp.com", name: "Reut Avidan", sam: "r.avidan" };

  const lureDomain = "freeware-pdftools.net";
  const lureIp = "104.21.44.187";
  const c2Domain = "telemetry-cdn-relay.net";
  const c2Ip = "45.88.97.214";
  const corpEgress = "81.174.55.21"; // London corporate egress
  const replayIp = "91.243.24.19";

  const installerHash = makeSha256("pdf_converter_pro_setup_freeware_pdftools_2026");

  const userId = "9c4a2f18-5e73-4b06-8d91-2f7c4a6e9b35";
  const deviceIdBaseline = "b7f4a913-6c82-4e05-91a7-3d8c4f207b56";
  const sessionIdBaseline = "72d4f8a1-3b96-4e02-8c15-9a6d7e4f2b81";
  const sessionIdReplay = "e9c2a705-1f84-4b36-a927-6d0e5c3f819a";
  const correlationIdReplay = "b3e97a41-2c85-4d16-9f07-1a4c8e6d3b52";
  const officeAppId = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
  const mfaPolicyId = "1f0b6c93-7d24-4a5e-8b90-c3f27a641e58";

  // EDR↔scenario integration (Phase 1b): ONE incident that spans two planes —
  // the infostealer on the host (EDR: file/process/credential-copy) AND the
  // stolen session cookie replayed against Entra/M365 (o365 identity events).
  // That makes it edr_scope "hybrid": the Falcon detection surfaces the endpoint
  // side and the analyst pivots to EDR for the host, while the Entra sign-in
  // replay is investigated on the identity plane — correlated by the shared
  // incident_id + account + timing. The Entra and SharePoint rows are control-plane
  // evidence: they carry no process or file object, so no endpoint process can own them.
  const INCIDENT = "inc:ist:1";

  const cx = "nexacorp" as const;
  const caPolicy = [{ id: mfaPolicyId, displayName: "Require MFA for all users", result: "success", enforcedGrantControls: ["Mfa"], enforcedSessionControls: [] }];

  // The stealer and the browser as the endpoint sees them. Chrome pre-exists the story.
  const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const STEALER = "C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe";
  const STAGE = "C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19";
  const UA_BASE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";
  const UA_REPLAY = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

  /** Falcon's actor fields for a file write by the stealer (pid 7188, child of explorer.exe 3844). */
  const byStealer = { actorProcess: "PDF_Converter_Pro_Setup.exe", actorPid: 7188, actorPath: STEALER, actorParentName: "explorer.exe", actorParentPid: 3844 } as const;

  const events: TelemetryEvent[] = [
    // 1. Baseline — her own morning sign-in: real MFA, her enrolled device.
    { ...entraSignIn({
      companyId: cx, id: "evt_ist_01_baseline_signin", ts: T(0), srcIp: corpEgress, user: victim.email,
      displayName: victim.name, userTitle: "Account Executive", userId, correlationId: "4a8f1c92-6d37-4e05-b8a1-9f2c6d4e7a13",
      sessionId: sessionIdBaseline, app: "Microsoft Office", appId: officeAppId, resource: "Microsoft Graph",
      mfa: true, isInteractive: true, managed: true, compliant: true, deviceId: deviceIdBaseline, deviceName: "LAP-6688",
      os: "Windows 11", browser: "Chrome 150.0.7339", trustType: "Azure AD joined", asn: 5378,
      userAgent: UA_BASE,
      tokenIssuerType: "AzureAD", incomingTokenType: "none", riskLevel: "none", conditionalAccess: "success",
      geo: { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 }, severity: "informational",
      extra: {
        "azure.signinlogs.properties.location.state": "England",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.authenticationDetails": [
          { authenticationStepDateTime: T(0 - 12 * SEC), authenticationMethod: "Password", authenticationMethodDetail: "Password in the cloud", succeeded: true, authenticationStepResultDetail: "Correct password", authenticationStepRequirement: "Primary authentication" },
          { authenticationStepDateTime: T(0 - 3 * SEC), authenticationMethod: "Mobile app notification", authenticationMethodDetail: "Microsoft Authenticator", succeeded: true, authenticationStepResultDetail: "MFA completed in Azure AD", authenticationStepRequirement: "Multifactor authentication" },
        ],
        "azure.signinlogs.properties.appliedConditionalAccessPolicies": caPolicy,
      },
      description: "Entra ID recorded r.avidan's ordinary interactive sign-in at 07:52, MFA satisfied by a live Authenticator push, from her enrolled laptop LAP-6688 on the London corporate egress.",
    }), is_baseline: true },

    // 2a. Chrome resolves the freeware site (Falcon DnsRequest).
    csDns({
      companyId: cx, id: "evt_ist_02a_dns_lure", ts: T(3 * HOUR + 41 * MIN - 2 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      domain: lureDomain, resolvedIp: lureIp, processName: "chrome.exe", processPath: CHROME, pid: 6204, parentName: "explorer.exe", parentPid: 3844,
      severity: "low", incidentId: INCIDENT,
      description: "chrome.exe on LAP-6688 resolved freeware-pdftools.net two seconds before the firewall logged the download.",
    }),

    // 2. She downloads a free converter from a freeware aggregator (PAN).
    panWeb({
      companyId: cx, id: "evt_ist_02_lure_download", ts: T(3 * HOUR + 41 * MIN), host: host.hostname, srcIp: host.ip, user: victim.email,
      url: `https://${lureDomain}/download/PDF_Converter_Pro_Setup.exe`, domain: lureDomain, category: "shareware-and-freeware",
      method: "GET", action: "alert", dstIp: lureIp, bytesIn: 2_894_336,
      referer: "https://www.google.com/search?q=free+pdf+to+word+converter+download",
      file: { name: "PDF_Converter_Pro_Setup.exe", path: "/download/PDF_Converter_Pro_Setup.exe", sha256: installerHash, size: 2_894_336 }, fileType: "pe",
      severity: "medium", incidentId: INCIDENT,
      description: "At 11:33 LAP-6688 downloaded PDF_Converter_Pro_Setup.exe from freeware-pdftools.net, referred by a Google search for a free PDF-to-Word converter.",
    }),

    // 3. The installer lands in Downloads (chrome writes it).
    csFile({
      companyId: cx, id: "evt_ist_03_file_write", ts: T(3 * HOUR + 41 * MIN + 6 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: STEALER, sha256: installerHash, size: 2_894_336, action: "file_create",
      actorProcess: "chrome.exe", actorPid: 6204, actorPath: CHROME, actorParentName: "explorer.exe", actorParentPid: 3844, severity: "low", incidentId: INCIDENT,
      description: "chrome.exe wrote C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe at 11:33:06.",
    }),

    // 4. She runs it — unsigned, from Downloads, parent explorer.exe.
    csProcess({
      companyId: cx, id: "evt_ist_04_execute", ts: T(3 * HOUR + 47 * MIN), host: host.hostname, srcIp: host.ip, user: victim.email,
      processName: "PDF_Converter_Pro_Setup.exe", processPath: STEALER,
      cmdline: '"C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe"', parentName: "explorer.exe", parentPid: 3844, pid: 7188,
      sha256: installerHash, signed: false, integrity: "medium", mitre: "T1204.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      description: "At 11:39:00 explorer.exe started the unsigned PDF_Converter_Pro_Setup.exe from Downloads.",
    }),

    // 4a. Local State copied — it holds the key Chrome uses to decrypt the credential databases.
    csFile({
      companyId: cx, id: "evt_ist_04a_localstate_copy", ts: T(3 * HOUR + 47 * MIN + 2 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: `${STAGE}\\Chrome\\Local State`, sha256: null, size: 87_342, action: "file_create", ...byStealer,
      mitre: "T1555.003", tactic: "Credential Access", severity: "high", incidentId: INCIDENT,
      description: "Two seconds after starting, PDF_Converter_Pro_Setup.exe created a copy of Chrome's Local State file in a Temp staging folder.",
    }),

    // 5. Login Data copied out of the locked Chrome profile — saved passwords (T1555.003).
    csFile({
      companyId: cx, id: "evt_ist_05_logindata_copy", ts: T(3 * HOUR + 47 * MIN + 4 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: `${STAGE}\\Chrome\\Default\\Login Data`, sha256: null, size: 106_496, action: "file_create", ...byStealer,
      mitre: "T1555.003", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
      description: "PDF_Converter_Pro_Setup.exe created C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Login Data, 104 KB — the same filename Chrome uses for its own saved-password SQLite database, which was still open and locked in the running browser. Local State, which holds the key Chrome uses to decrypt that database, was written to the same folder seconds earlier.",
    }),

    // 6. Cookies database copied — the live session, not just passwords (T1539). The crux.
    csFile({
      companyId: cx, id: "evt_ist_06_cookies_copy", ts: T(3 * HOUR + 47 * MIN + 9 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: `${STAGE}\\Chrome\\Default\\Network\\Cookies`, sha256: null, size: 61_440, action: "file_create", ...byStealer,
      isDetection: true, mitre: "T1539", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
      description: "Five seconds later the same process created C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Network\\Cookies, 60 KB — Chrome's own cookie store, copied out of its locked location in the same staging folder as Login Data.",
    }),

    // 6a. The three files are packed into one archive. Deflate on SQLite + JSON: roughly half the 255,278 bytes staged.
    csFile({
      companyId: cx, id: "evt_ist_06a_archive", ts: T(3 * HOUR + 47 * MIN + 16 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: `${STAGE}\\upload.zip`, sha256: null, size: 124_516, action: "file_create", ...byStealer,
      mitre: "T1560.001", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      description: "Seven seconds after the Cookies copy the same process created upload.zip, 121 KB, in the staging folder.",
    }),

    // 6b. The stealer resolves its collection endpoint, then connects (Falcon DnsRequest + NetworkConnectIP4).
    csDns({
      companyId: cx, id: "evt_ist_06b_dns_c2", ts: T(3 * HOUR + 47 * MIN + 20 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      domain: c2Domain, resolvedIp: c2Ip, processName: "PDF_Converter_Pro_Setup.exe", processPath: STEALER, pid: 7188, parentName: "explorer.exe", parentPid: 3844,
      sha256: installerHash, severity: "high", incidentId: INCIDENT,
      description: "PDF_Converter_Pro_Setup.exe resolved telemetry-cdn-relay.net at 11:39:20.",
    }),
    csNetwork({
      companyId: cx, id: "evt_ist_06c_net_c2", ts: T(3 * HOUR + 47 * MIN + 22 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      remoteIp: c2Ip, remotePort: 443, domain: c2Domain, application: "tls", processName: "PDF_Converter_Pro_Setup.exe", processPath: STEALER, pid: 7188,
      parentName: "explorer.exe", parentPid: 3844, sha256: installerHash, severity: "high", incidentId: INCIDENT,
      description: "PDF_Converter_Pro_Setup.exe opened a TCP/443 connection to 45.88.97.214.",
    }),

    // 7. It leaves the building — a POST to the collection endpoint (T1041).
    panWeb({
      companyId: cx, id: "evt_ist_07_exfil", ts: T(3 * HOUR + 47 * MIN + 24 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      url: `https://${c2Domain}/api/v2/upload`, domain: c2Domain, category: "unknown", method: "POST", action: "allow",
      dstIp: c2Ip, bytesOut: 125_128, bytesIn: 54, mitre: "T1041", tactic: "Exfiltration", severity: "critical", incidentId: INCIDENT,
      description: "At 11:39:24 the host POSTed a 122 KB archive to telemetry-cdn-relay.net/api/v2/upload, allowed under the category unknown.",
    }),

    // 7a. The firewall's session summary for the same flow carries the volume.
    panConnection({
      companyId: cx, id: "evt_ist_07a_exfil_session", ts: T(3 * HOUR + 47 * MIN + 27 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      domain: c2Domain, dstIp: c2Ip, remotePort: 443, app: "web-browsing", transport: "tcp", action: "allow", end: true, decrypted: true,
      bytesOut: 127_340, bytesIn: 5_912, elapsedSec: 4, sessionEndReason: "tcp-fin", category: "unknown",
      severity: "high", incidentId: INCIDENT,
      description: "Firewall session summary for the 11:39:23 connection from LAP-6688 to 45.88.97.214:443, closed by FIN.",
    }),

    // 8. THE CRUX — a new session five minutes later, no password or MFA step (T1550.004).
    { ...entraSignIn({
      companyId: cx, id: "evt_ist_08_session_replay", ts: T(3 * HOUR + 52 * MIN + 40 * SEC), srcIp: replayIp, user: victim.email,
      displayName: victim.name, userTitle: "Account Executive", userId, correlationId: correlationIdReplay, sessionId: sessionIdReplay,
      app: "Microsoft Office", appId: officeAppId, resource: "Microsoft Graph", mfa: true, isInteractive: true,
      managed: false, compliant: false, deviceId: "", os: "Windows 10", browser: "Chrome 149.0.7286", asn: 197695,
      userAgent: UA_REPLAY,
      tokenIssuerType: "AzureAD", incomingTokenType: "none", riskLevel: "none", conditionalAccess: "success", riskEventTypes: [],
      geo: { country: "Russia", city: "Moscow", latitude: 55.7558, longitude: 37.6173 },
      mitre: "T1550.004", tactic: "Lateral Movement", severity: "critical", incidentId: INCIDENT,
      extra: {
        "azure.signinlogs.properties.location.state": "Moscow",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.authenticationDetails": [
          { authenticationStepDateTime: T(3 * HOUR + 52 * MIN + 40 * SEC), authenticationMethod: "Previously satisfied", authenticationMethodDetail: null, succeeded: true, authenticationStepResultDetail: "First factor requirement satisfied by claim in the token", authenticationStepRequirement: "Primary authentication" },
          { authenticationStepDateTime: T(3 * HOUR + 52 * MIN + 40 * SEC), authenticationMethod: "Previously satisfied", authenticationMethodDetail: null, succeeded: true, authenticationStepResultDetail: "MFA requirement satisfied by claim in the token", authenticationStepRequirement: "Multifactor authentication" },
        ],
        "azure.signinlogs.properties.appliedConditionalAccessPolicies": caPolicy,
      },
      description: "A second Entra sign-in for r.avidan completed from 91.243.24.19 in Moscow on an unmanaged Windows 10 / Chrome 149 device — five minutes after Falcon saw her Cookies database copied on LAP-6688. Both the first factor and multifactor were satisfied by claims already present in the token.",
    }) },

    // 9. The endpoint verdict, arriving after the transfer and the replay.
    {
      ...csAlert({
        companyId: cx, id: "evt_ist_09_edr_alert", ts: T(3 * HOUR + 53 * MIN + 10 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
        threatName: "BrowserCredentialStoreStagingAndTransfer", action: "killed",
        mitre: "T1555.003", tactic: "Credential Access", technique: "Credentials from Web Browsers",
        processTree: "explorer.exe > PDF_Converter_Pro_Setup.exe", processName: "PDF_Converter_Pro_Setup.exe", processPath: STEALER,
        cmdline: '"C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe"', sha256: installerHash, pid: 7188,
        severity: "critical", incidentId: INCIDENT,
        detail: "An unsigned process copied Chrome's Login Data and Cookies databases out of the browser profile and transferred data to external infrastructure shortly afterward.",
        description: "Falcon raised a Critical detection on LAP-6688 for browser-credential-store staging and killed PDF_Converter_Pro_Setup.exe — after the archive had already left the host and the stolen session had already been used.",
      }),
      edr_scope: "hybrid",
    },

    // 10. The replayed session reaches into SharePoint (T1213.002).
    { ...m365Operation({
      companyId: cx, id: "evt_ist_10_sharepoint_access", ts: T(3 * HOUR + 53 * MIN + 55 * SEC), srcIp: replayIp, user: victim.email,
      operation: "FileAccessed", workload: "SharePoint", objectId: "https://nexacorp.sharepoint.com/sites/Sales/Shared Documents/Q3_Pipeline_Forecast.xlsx",
      fileName: "Q3_Pipeline_Forecast.xlsx", siteUrl: "https://nexacorp.sharepoint.com/sites/Sales", sessionId: sessionIdReplay,
      userAgent: UA_REPLAY,
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      extra: { "RecordType": "6", "UserType": "0", "ResultStatus": "Succeeded", "SourceRelativeUrl": "Shared Documents", "EventSource": "SharePoint", "CorrelationId": correlationIdReplay, "ItemType": "File" },
      description: "The replayed session opened Q3_Pipeline_Forecast.xlsx under /sites/Sales/Shared Documents from 91.243.24.19 — the same account, the same unmanaged Chrome 149 session that signed in a minute earlier.",
    }), file: undefined },
  ];

  // Every event — host EDR and identity-plane alike — belongs to the one
  // infostealer→session-replay incident (this is the SIEM↔EDR correlation key).
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Killed process and a new sign-in for one user", events, T, MIN, HOUR, SEC, host, victim, lureDomain, c2Domain, c2Ip, replayIp, installerHash };
}
