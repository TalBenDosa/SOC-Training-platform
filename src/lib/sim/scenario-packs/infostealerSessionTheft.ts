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
 * SOURCES: edr (CrowdStrike Falcon), firewall (Palo Alto Networks PAN-OS),
 * o365 (Microsoft Entra ID / Microsoft 365 Unified Audit Log).
 *
 * NOTE: `difficulty: "core"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { panWeb } from "@/lib/sim/emitters/paloalto";
import { csProcess, csFile, csAlert } from "@/lib/sim/emitters/crowdstrike";
import { m365Operation } from "@/lib/sim/emitters/m365";

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
  // incident_id + account + timing. Alert-grade EDR rows: the Cookies (session)
  // theft crux and the Falcon detection; the rest of the EDR events are pivot-only.
  const INCIDENT = "inc:ist:1";

  const cx = "nexacorp" as const;
  const caPolicy = [{ id: mfaPolicyId, displayName: "Require MFA for all users", result: "success", enforcedGrantControls: ["Mfa"], enforcedSessionControls: [] }];

  const events: TelemetryEvent[] = [
    // 1. Baseline — her own morning sign-in: real MFA, her enrolled device.
    entraSignIn({
      companyId: cx, id: "evt_ist_01_baseline_signin", ts: T(0), srcIp: corpEgress, user: victim.email,
      displayName: victim.name, userTitle: "Account Executive", userId, correlationId: "4a8f1c92-6d37-4e05-b8a1-9f2c6d4e7a13",
      sessionId: sessionIdBaseline, app: "Microsoft Office", appId: officeAppId, resource: "Microsoft Graph",
      mfa: true, isInteractive: true, managed: true, compliant: true, deviceId: deviceIdBaseline, deviceName: "LAP-6688",
      os: "Windows 11", browser: "Edge 125.0.2535", trustType: "Azure AD joined", asn: 5378,
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.51",
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
    }),

    // 2. She downloads a free converter from a freeware aggregator (PAN).
    panWeb({
      companyId: cx, id: "evt_ist_02_lure_download", ts: T(3 * HOUR + 41 * MIN), host: host.hostname, srcIp: host.ip, user: victim.email,
      url: `https://${lureDomain}/download/PDF_Converter_Pro_Setup.exe`, domain: lureDomain, category: "shareware-download",
      method: "GET", action: "alert", dstIp: lureIp, bytesIn: 2_894_336,
      referer: "https://www.google.com/search?q=free+pdf+to+word+converter+download",
      file: { name: "PDF_Converter_Pro_Setup.exe", path: "/download/PDF_Converter_Pro_Setup.exe", sha256: installerHash, size: 2_894_336 }, fileType: "pe",
      severity: "medium", incidentId: INCIDENT,
      description: "At 11:33 LAP-6688 downloaded PDF_Converter_Pro_Setup.exe from freeware-pdftools.net, referred by a Google search for a free PDF-to-Word converter.",
    }),

    // 3. The installer lands in Downloads (chrome writes it).
    csFile({
      companyId: cx, id: "evt_ist_03_file_write", ts: T(3 * HOUR + 41 * MIN + 6 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: "C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe", sha256: installerHash, size: 2_894_336, action: "file_create",
      actorProcess: "chrome.exe", actorPid: 6204, severity: "low", incidentId: INCIDENT,
      description: "chrome.exe wrote C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe at 11:33:06.",
    }),

    // 4. She runs it — unsigned, from Downloads, parent explorer.exe.
    csProcess({
      companyId: cx, id: "evt_ist_04_execute", ts: T(3 * HOUR + 47 * MIN), host: host.hostname, srcIp: host.ip, user: victim.email,
      processName: "PDF_Converter_Pro_Setup.exe", processPath: "C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe",
      cmdline: '"C:\\Users\\r.avidan\\Downloads\\PDF_Converter_Pro_Setup.exe"', parentName: "explorer.exe", parentPid: 3844, pid: 7188,
      sha256: installerHash, signed: false, integrity: "medium", mitre: "T1204.002", tactic: "Execution", severity: "high", incidentId: INCIDENT,
      description: "At 11:39:00 explorer.exe started the unsigned PDF_Converter_Pro_Setup.exe from Downloads.",
    }),

    // 5. Login Data copied out of the locked Chrome profile — saved passwords (T1555.003).
    csFile({
      companyId: cx, id: "evt_ist_05_logindata_copy", ts: T(3 * HOUR + 47 * MIN + 4 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: "C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Login Data", sha256: null, size: 106_496, action: "file_create",
      actorProcess: "PDF_Converter_Pro_Setup.exe", actorPid: 7188, mitre: "T1555.003", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
      description: "PDF_Converter_Pro_Setup.exe created C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Login Data, 104 KB — the same filename Chrome uses for its own saved-password SQLite database, which was still open and locked in the running browser. Local State, which holds the key Chrome uses to decrypt that database, was written to the same folder seconds earlier.",
    }),

    // 6. Cookies database copied — the live session, not just passwords (T1539). The crux.
    csFile({
      companyId: cx, id: "evt_ist_06_cookies_copy", ts: T(3 * HOUR + 47 * MIN + 9 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      path: "C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Network\\Cookies", sha256: null, size: 61_440, action: "file_create",
      actorProcess: "PDF_Converter_Pro_Setup.exe", actorPid: 7188, isDetection: true, mitre: "T1539", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
      description: "Five seconds later the same process created C:\\Users\\r.avidan\\AppData\\Local\\Temp\\7zSC3A19\\Chrome\\Default\\Network\\Cookies, 60 KB — Chrome's own cookie store, copied out of its locked location in the same staging folder as Login Data.",
    }),

    // 7. It leaves the building — a small POST to the collection endpoint (T1041).
    panWeb({
      companyId: cx, id: "evt_ist_07_exfil", ts: T(3 * HOUR + 47 * MIN + 24 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
      url: `https://${c2Domain}/api/v2/upload`, domain: c2Domain, category: "unknown", method: "POST", action: "allow",
      dstIp: c2Ip, bytesOut: 182_304, bytesIn: 54, mitre: "T1041", tactic: "Exfiltration", severity: "critical", incidentId: INCIDENT,
      description: "At 11:39:24 the host POSTed a 178 KB archive to telemetry-cdn-relay.net/api/v2/upload, allowed under the category unknown.",
    }),

    // 8. THE CRUX — a new session five minutes later, no interactive MFA (T1550.004).
    entraSignIn({
      companyId: cx, id: "evt_ist_08_session_replay", ts: T(3 * HOUR + 52 * MIN + 40 * SEC), srcIp: replayIp, user: victim.email,
      displayName: victim.name, userTitle: "Account Executive", userId, correlationId: correlationIdReplay, sessionId: sessionIdReplay,
      app: "Microsoft Office", appId: officeAppId, resource: "Microsoft Graph", mfa: true, isInteractive: false,
      managed: false, compliant: false, deviceId: "", os: "Windows 10", browser: "Chrome 124.0.6367", asn: 197695,
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      tokenIssuerType: "AzureAD", incomingTokenType: "primaryRefreshToken", riskLevel: "none", conditionalAccess: "success", riskEventTypes: [],
      geo: { country: "Russia", city: "Moscow", latitude: 55.7558, longitude: 37.6173 },
      mitre: "T1550.004", tactic: "Defense Evasion", severity: "critical", incidentId: INCIDENT,
      extra: {
        "azure.signinlogs.properties.location.state": "Moscow",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.authenticationDetails": [
          { authenticationStepDateTime: T(3 * HOUR + 52 * MIN + 40 * SEC), authenticationMethod: "Previously satisfied", authenticationMethodDetail: "", succeeded: true, authenticationStepResultDetail: "MFA requirement satisfied by claim in the token", authenticationStepRequirement: "Multifactor authentication" },
        ],
        "azure.signinlogs.properties.appliedConditionalAccessPolicies": caPolicy,
      },
      description: "A second, non-interactive Entra sign-in for r.avidan completed from 91.243.24.19 in Moscow on an unmanaged Windows 10 / Chrome 124 device — five minutes after Falcon saw her Cookies database copied on LAP-6688. Multifactor was satisfied by a claim already present in the token.",
    }),

    // 9. The endpoint verdict, arriving after the transfer and the replay.
    {
      ...csAlert({
        companyId: cx, id: "evt_ist_09_edr_alert", ts: T(3 * HOUR + 53 * MIN + 10 * SEC), host: host.hostname, srcIp: host.ip, user: victim.email,
        threatName: "BrowserCredentialStoreStagingAndTransfer", action: "killed", confidence: 85,
        mitre: "T1555.003", tactic: "Credential Access", technique: "Credentials from Web Browsers",
        processTree: "explorer.exe > PDF_Converter_Pro_Setup.exe", severity: "critical", incidentId: INCIDENT,
        detail: "An unsigned process copied Chrome's Login Data and Cookies databases out of the browser profile and transferred data to external infrastructure shortly afterward.",
        description: "Falcon raised a Critical detection on LAP-6688 for browser-credential-store staging and killed PDF_Converter_Pro_Setup.exe — after the archive had already left the host and the stolen session had already been used.",
      }),
      edr_scope: "hybrid",
    },

    // 10. The replayed session reaches into SharePoint (T1213.002).
    m365Operation({
      companyId: cx, id: "evt_ist_10_sharepoint_access", ts: T(3 * HOUR + 53 * MIN + 55 * SEC), srcIp: replayIp, user: victim.email,
      operation: "FileAccessed", workload: "SharePoint", objectId: "https://nexacorp.sharepoint.com/sites/Sales/Shared Documents/Q3_Pipeline_Forecast.xlsx",
      fileName: "Q3_Pipeline_Forecast.xlsx", siteUrl: "https://nexacorp.sharepoint.com/sites/Sales", sessionId: sessionIdReplay,
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      mitre: "T1213.002", tactic: "Collection", severity: "high", incidentId: INCIDENT,
      extra: { "RecordType": "6", "UserType": "0", "ResultStatus": "Succeeded", "SourceRelativeUrl": "Shared Documents", "EventSource": "SharePoint", "CorrelationId": correlationIdReplay, "ItemType": "File" },
      description: "The replayed session opened Q3_Pipeline_Forecast.xlsx under /sites/Sales/Shared Documents from 91.243.24.19 — the same account, the same unmanaged Chrome 124 session that signed in a minute earlier.",
    }),
  ];

  // Every event — host EDR and identity-plane alike — belongs to the one
  // infostealer→session-replay incident (this is the SIEM↔EDR correlation key).
  for (const e of events) e.incident_id = INCIDENT;

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
      tags: ["c2", "outbound-post-target"],
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
        { value: "geo_alone", label: "The IP resolves outside the United Kingdom, and any sign-in from a country she has never visited is a takeover by definition" },
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
