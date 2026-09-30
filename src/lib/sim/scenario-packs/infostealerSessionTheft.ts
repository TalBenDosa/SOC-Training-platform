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

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { infostealerSessionTheftScenarioEvents } from "./infostealerSessionTheft.events";

export function buildInfostealerSessionTheftScenario(
  scenarioId = "infostealer-session-theft-2026",
): ScenarioBundle {
  const { title, events, T, MIN, HOUR, SEC, host, victim, lureDomain, c2Domain, replayIp, installerHash } = infostealerSessionTheftScenarioEvents();
  const sensorId = "d81f6c204b3e4a97a1c85e0d2f7936ab";

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
        { value: "cookies", label: "Cookies copy — the Cookies file under Network\\, which holds live session state rather than saved passwords" },
        { value: "logindata", label: "Login Data copy — Chrome's full credential vault, which already covers every site session the user had open" },
        { value: "execute", label: "Installer execution — running an unsigned installer is itself proof that all browser sessions are exposed" },
        { value: "alert", label: "Falcon detection — the vendor's detection name is what confirms that session data was actually taken" },
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
          label: "authenticationDetails has only a prior-token claim — no password or MFA step — on an unmanaged device, minutes after her Cookies file was copied",
        },
        { value: "risk_field", label: "riskLevelDuringSignIn should read \"high\" for any sign-in from Russia, so the record is mislabelled and the risk engine missed a known-bad location" },
        { value: "geo_alone", label: "The IP resolves outside the United Kingdom, to a country she has never signed in from, which on its own is sufficient to declare a takeover" },
        { value: "ca_status", label: "conditionalAccessStatus only reads \"success\" when the legitimate user completed the grant controls — a hijacked session would show \"failure\"" },
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
          label: "pan.category is \"unknown\" (unrated), and a sub-200 KB outbound POST has nothing in its raw fields to set it apart from routine web traffic",
        },
        { value: "tls_off", label: "TLS inspection was disabled for this session, so the firewall only saw an encrypted SNI and could not inspect the POST body or its size" },
        { value: "monitor_mode", label: "CORP-WEB-OUTBOUND was running in monitor-only mode for every category, so the upload was logged as a hit but the enforcement action was skipped" },
        { value: "allowlist", label: "telemetry-cdn-relay.net was already on an explicit corporate allowlist, because it mimics a telemetry service that endpoint agents contact" },
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
          label: "Revoke her sessions and refresh tokens, reset her password, and treat every site saved in that Chrome profile as exposed, corporate or not",
        },
        { value: "password_only", label: "Reset her domain password and force MFA re-registration, which is sufficient because both stolen files were local artifacts on the laptop" },
        { value: "reimage_only", label: "Reimage LAP-6688 to remove the stealer and its staged archive; with the host rebuilt, nothing that already left it needs to be revoked or reset" },
        { value: "ip_block_only", label: "Block the replay IP and the C2 domain at the firewall, which cuts the attacker off from both the exfiltrated data and her Microsoft 365 account" },
      ],
      answer: "full_scope",
      xp: 60,
      explanation:
        "evt_ist_08 already shows why option (b) fails: the sign-in there needed no password at all, because the stolen session cookie carried its own valid token — a password reset does nothing to a session that has already been issued and is already in use, which is exactly why evt_ist_10 (SharePoint access) still succeeds after the fact. Revoking sessions and refresh tokens is what actually invalidates the token the attacker is holding; the password reset matters for the credential that was also taken in evt_ist_05, but on its own it's not containment. Option (c) fixes the endpoint but ignores that the data, and the live session built from it, are already off the host — reimaging LAP-6688 does not reach into Entra ID. Option (d) blocks two indicators the attacker can trivially rotate; it does nothing about the token already issued to their current session. And because Login Data holds every saved password in that Chrome profile, not just the corporate one, scope has to extend past the domain account to whatever personal or third-party sites she had saved there.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
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
