/**
 * Learning Rooms — Batch 41
 *
 * Closes a P0 coverage gap: MFA fatigue/push bombing (T1621), AiTM
 * reverse-proxy session-cookie theft (T1539 + T1550.004), Windows OS
 * access-token impersonation (T1134.001), stolen OAuth application tokens
 * (T1528), and Golden SAML forgery (T1606.002) are practised repeatedly across
 * this platform's scenarios but were never taught in any room. Companion to
 * the theory lesson "MFA Attacks & Session/Token Theft" in newTopicLessons.ts
 * — every task here is built on that lesson's reading, not on outside
 * knowledge.
 *
 * Rooms in this batch:
 *  1. mfa-session-token-attacks
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — MFA Attacks & Session/Token Theft
// ===========================================================================

// A single accidental push denial, immediately corrected — the false-positive
// control case for the fatigue-detection readings.
const singleDeniedPushEvent: TelemetryEvent = {
  id: "evt-mfast-ac1-001",
  ts: "2026-07-14T09:14:02.000Z",
  source: "okta",
  vendor: "Okta",
  event_type: "mfa_denied",
  severity: "low",
  mitre_technique: "T1621",
  hostname: "okta-idp.castellanrisk.com",
  user_email: "r.aldana@castellanrisk.com",
  user_title: "Senior Claims Adjuster",
  src_ip: "70.114.22.89",
  geo: { country: "United States", city: "Denver" },
  description:
    "r.aldana denied one Okta Verify push at 09:14:02 local time, then approved a second push 41 seconds later from the same device and IP address, completing a normal morning sign-in.",
  it_verify_result: "confirmed",
  it_verify_message:
    "r.aldana confirmed by phone: opened the wrong notification first (a calendar reminder was on top) and dismissed it before re-approving the real Okta prompt. Device and network match her registered laptop and home ISP.",
  raw: {
    "okta.eventType": "user.mfa.okta_verify.push_response",
    "okta.outcome.result": "DENIED",
    "okta.actor.displayName": "Rosa Aldana",
    "okta.actor.alternateId": "r.aldana@castellanrisk.com",
    "okta.client.ipAddress": "70.114.22.89",
    "okta.client.geographicalContext.country": "United States",
    "okta.client.geographicalContext.city": "Denver",
    "okta.client.userAgent.rawUserAgent": "Okta Verify/4.12.1 iOS/17.5",
    "okta.debugContext.debugData.factor": "OKTA_VERIFY_PUSH",
    "okta.displayMessage": "MFA push notification denied",
    "event.outcome": "failure",
    "source.ip": "70.114.22.89",
    "user.email": "r.aldana@castellanrisk.com",
  },
};

// The session-cookie replay sign-in for the log_analysis task. The genuine,
// preceding interactive sign-in is described in the task's `context` field,
// not as a second event — the student reads the replay event's raw fields
// against that narrated baseline, exactly as an analyst would read one alert
// against what the sign-in history already shows.
const sessionReplaySignInEvent: TelemetryEvent = {
  id: "evt-mfast-la1-001",
  ts: "2026-08-03T14:52:17.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "auth_success",
  severity: "critical",
  mitre_technique: "T1550.004",
  mitre_tactic: "Lateral Movement",
  hostname: "login.microsoftonline.com",
  user_email: "d.okafor@castellanrisk.com",
  user_title: "Senior Underwriter",
  src_ip: "141.98.11.203",
  geo: { country: "Netherlands", city: "Amsterdam" },
  description:
    "A second Entra ID sign-in for d.okafor was recorded at 14:52:17, eleven minutes after her genuine morning sign-in, from an address in Amsterdam rather than her usual Chicago office network.",
  raw: {
    "azure.signinlogs.category": "SignInLogs",
    "azure.signinlogs.operationName": "Sign-in activity",
    "azure.signinlogs.properties.id": "7f4c2a91-8e05-4b3a-9c17-2d6f8a10b453",
    "azure.signinlogs.properties.createdDateTime": "2026-08-03T14:52:17.000Z",
    "azure.signinlogs.properties.userPrincipalName": "d.okafor@castellanrisk.com",
    "azure.signinlogs.properties.userDisplayName": "Deja Okafor",
    "azure.signinlogs.properties.userId": "5c9e2b40-71af-4d86-9013-5b7a2c9e04d1",
    "azure.signinlogs.properties.correlationId": "a30f8c17-4d92-46b0-8f21-9c05e7a13b64",
    "azure.signinlogs.properties.sessionId": "3d8a6f21-0c47-4e91-b3d0-7f2e9a541c86",
    "azure.signinlogs.properties.appDisplayName": "Microsoft Office",
    "azure.signinlogs.properties.appId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "azure.signinlogs.properties.resourceDisplayName": "Microsoft Graph",
    "azure.signinlogs.properties.clientAppUsed": "Browser",
    "azure.signinlogs.properties.isInteractive": false,
    "azure.signinlogs.properties.ipAddress": "141.98.11.203",
    "azure.signinlogs.properties.autonomousSystemNumber": 202422,
    "azure.signinlogs.properties.location.city": "Amsterdam",
    "azure.signinlogs.properties.location.countryOrRegion": "NL",
    "azure.signinlogs.properties.deviceDetail.deviceId": "",
    "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 10",
    "azure.signinlogs.properties.deviceDetail.browser": "Chrome 124.0.0",
    "azure.signinlogs.properties.deviceDetail.isCompliant": false,
    "azure.signinlogs.properties.deviceDetail.isManaged": false,
    "azure.signinlogs.properties.userAgent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
    "azure.signinlogs.properties.authenticationDetails": [
      {
        authenticationStepDateTime: "2026-08-03T14:52:17.000Z",
        authenticationMethod: "Previously satisfied",
        succeeded: true,
        authenticationStepResultDetail: "MFA requirement satisfied by claim in the token",
        authenticationStepRequirement: "Multifactor authentication",
      },
    ],
    "azure.signinlogs.properties.conditionalAccessStatus": "success",
    "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
    "azure.signinlogs.properties.riskDetail": "none",
    "azure.signinlogs.properties.riskState": "none",
    "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
    "azure.signinlogs.properties.incomingTokenType": "none",
    "azure.signinlogs.properties.status.errorCode": 0,
    "azure.signinlogs.resultType": "0",
  },
};

const mfaSessionTokenAttacksRoom = {
  id: "mfa-session-token-attacks",
  title: "MFA Attacks & Session/Token Theft: When 'MFA Enabled' Isn't 'Solved'",
  description:
    "MFA fatigue and push bombing (T1621), adversary-in-the-middle reverse-proxy phishing that steals a session cookie after a genuine login (T1539 + T1550.004), Windows OS access-token impersonation (T1134.001), stolen OAuth application tokens (T1528), and Golden SAML assertion forgery (T1606.002) — five real ATT&CK techniques that all defeat MFA without ever cracking a password. Grounded in the CISA/FBI Scattered Spider advisory, Microsoft and Okta identity documentation, and NIST SP 800-63B.",
  difficulty: "advanced" as const,
  category: "Identity",
  estimatedMinutes: 80,
  xp: 195,
  icon: "🔑",
  prerequisites: ["identity-basics", "auth-identity-monitoring", "okta-identity-fundamentals"],
  tasks: [
    // ── Reading 1: framing ──────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "mfast-r1",
      heading: "Why 'MFA Enabled' Doesn't Mean 'Solved'",
      content:
        "For years the standard SOC answer to a phished password was simple: turn on multi-factor authentication (MFA — proving identity with more than one type of evidence, such as a password plus a code or approval on a phone) and the account is safe. Real intrusions keep proving that answer incomplete. The 2022 Uber and Cisco breaches, and the ongoing campaigns CISA and the FBI track under the name Scattered Spider (joint advisory AA23-320A, most recently updated in 2025), all took over accounts that had MFA switched on the entire time.\n\n" +
        "This room teaches five real MITRE ATT&CK techniques that each defeat MFA in a different way, without ever needing to crack a password: **T1621** (Multi-Factor Authentication Request Generation — MFA fatigue / push bombing), **T1539** (Steal Web Session Cookie) paired with **T1550.004** (Use Alternate Authentication Material: Web Session Cookie), **T1134.001** (Access Token Manipulation: Token Impersonation/Theft), **T1528** (Steal Application Access Token), and **T1606.002** (Forge Web Credentials: SAML Tokens — 'Golden SAML').\n\n" +
        "### The one idea that ties all five together\n\n" +
        "MFA is a control that fires once, at the moment of login, and its result is then baked into whatever gets issued afterward — a session cookie, an access token, a signed SAML assertion. Nothing at the application layer re-checks that MFA genuinely happened on every later request; it trusts the artifact. Every technique in this room attacks that gap in one of two ways:\n\n" +
        "- **MFA is bypassed by tricking a human** — the attacker never has the real second factor and wears the victim down until they hand it over (T1621).\n" +
        "- **MFA is made irrelevant by stealing or forging what it produces** — the login ceremony either happens correctly and the resulting artifact is stolen (T1539/T1550.004), or an artifact is duplicated/forged directly with no fresh login at all (T1134.001, T1528, T1606.002).\n\n" +
        "### Two identity providers you'll see throughout\n\n" +
        "**Microsoft Entra ID** (Microsoft's cloud identity platform, formerly Azure AD) and **Okta** are the two identity providers (IdPs — the authoritative service that proves who a user is) whose real log fields this room reads directly. Both platforms publish the exact same underlying vulnerability in different vocabulary, which is exactly why precise technique attribution — not just 'the account was compromised' — is the skill this room builds toward.",
      diagram:
        "flowchart TD\n" +
        "  A[Attacker wants the account] --> B{Does the attacker\\nhave the real 2nd factor?}\n" +
        "  B -->|No| C[Wear the human down\\nT1621 MFA fatigue]\n" +
        "  B -->|Never needs it| D{Steal or forge the\\npost-login artifact}\n" +
        "  D --> E[Steal a session cookie\\nafter a real login\\nT1539 / T1550.004]\n" +
        "  D --> F[Duplicate a Windows\\nOS token on the endpoint\\nT1134.001]\n" +
        "  D --> G[Steal an OAuth\\napp access token\\nT1528]\n" +
        "  D --> H[Forge a SAML assertion\\noffline with a stolen key\\nT1606.002]\n",
      diagramCaption: "Two structurally different ways every technique in this room defeats MFA",
      checkpoint: {
        question: "What single property of MFA does every technique in this room actually exploit?",
        options: [
          "MFA is checked once at login and its result is trusted for everything issued afterward -- nothing re-verifies MFA on later requests",
          "MFA is only available on mobile devices, so desktop logins are never protected by it",
          "MFA requires an internet connection, so offline attacks always succeed automatically",
          "MFA is disabled by default on every enterprise identity provider",
        ],
        answer: 0,
        explanation: "This is the throughline of the whole room: MFA is a one-time gate. Once passed, whatever artifact gets issued (session cookie, access token, SAML assertion) is trusted on its own from then on, with no re-check of MFA. Every technique that follows attacks that trust in a different way.",
      },
      xp: 5,
    },

    // ── Reading 2: MFA fatigue mechanics ────────────────────────────────────
    {
      type: "reading" as const,
      id: "mfast-r2",
      heading: "MFA Fatigue / Push Bombing (T1621): Wearing Down the Human",
      content:
        "MITRE ATT&CK tracks this as **T1621, Multi-Factor Authentication Request Generation**, filed under the **Credential Access** tactic. It is the most-practised technique in this room's family because it needs no exploit at all — just a password the attacker already has, and a human tired or distracted enough to tap 'Approve.'\n\n" +
        "### How it's executed\n\n" +
        "The attacker already holds a valid username and password, typically from credential stuffing (trying passwords leaked from unrelated breaches), a phishing kit, or a purchased infostealer log. Push-based MFA (Okta Verify, Microsoft Authenticator, Duo) normally sends one push per login attempt and waits for Approve/Deny. The exploit is a simple asymmetry: **the attacker can trigger a fresh push as many times as they like, for free, with no lockout — the victim only has to make one mistake, ever.**\n\n" +
        "1. Resubmit the known-correct password repeatedly, generating a fresh push each time.\n" +
        "2. Send pushes in a burst (dozens within minutes) or spread over hours, often overnight when the victim is groggy.\n" +
        "3. Sometimes follow up with a phone call or message impersonating IT support asking the victim to 'approve so we can fix the issue' — documented in the 2022 Uber breach, where the attacker messaged the victim on WhatsApp claiming to be IT after a barrage of pushes.\n" +
        "4. Eventually the victim approves one push — out of habit, confusion, or a genuine belief they're helping IT — and the attacker holds a fully legitimate, MFA-satisfied session.\n\n" +
        "### Why 'unsophisticated' doesn't mean 'easy to filter'\n\n" +
        "There is no exploit, no malware, no code execution. Every single push is completely legitimate — it really was generated by a real login attempt against the real IdP. The only thing separating an attack from a confused user hitting the wrong button once is **volume and pattern over time**, which is a detection problem, not a blocking problem: you cannot simply refuse to send a push just because a password was typed correctly.\n\n" +
        "CISA and the FBI's 2025 update to the Scattered Spider advisory (AA23-320A) names push bombing explicitly as one of that group's standard techniques, used alongside SIM-swapping and help-desk social engineering in some of the highest-profile breaches of the past several years.",
      codeExample:
        "Simplified timeline of a push-bombing takeover:\n\n" +
        "  01:20:00  correct password submitted -> push #1 sent\n" +
        "  01:21:17  password submitted again    -> push #2 sent\n" +
        "  01:26:17  ... push #7 denied by user\n" +
        "  01:27:xx  ... repeated roughly every 30-60s ...\n" +
        "  01:32:17  push #12 (or later) -> user APPROVES, exhausted/confused\n" +
        "  01:32:44  attacker enrolls a NEW device on the account (persistence)\n",
      xp: 5,
    },

    // ── Question 1 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mfast-q1",
      question:
        "Why is a burst of 11 denied Okta pushes followed by one accepted push, all within 12 minutes, treated as far more significant than a single accidental approval on its own?",
      options: [
        "It isn't more significant -- one approval is one approval, regardless of what came before it",
        "The pattern over time -- many denials tied to the same source, then one acceptance -- is the actual evidence; every individual push looked completely legitimate on its own",
        "Okta automatically blocks accounts after exactly 10 denials, so an 11th denial should be technically impossible",
        "MFA fatigue only works if the attacker also already knows the victim's home address",
      ],
      answer: 1,
      explanation:
        "Every single push in the sequence is genuinely legitimate -- it really came from a correct-password login attempt. What flags the pattern is the burst shape over time: many denials from one correlated source followed by an acceptance, which an isolated accidental tap would never produce. Option c is false (no such automatic block exists at that count), and option d misunderstands the attack entirely -- it requires only a working password, not any personal address information.",
      xp: 15,
    },

    // ── Reading 3: fatigue detection ────────────────────────────────────────
    {
      type: "reading" as const,
      id: "mfast-r3",
      heading: "Detecting MFA Fatigue: Okta Fields and the Number-Matching Fix",
      content:
        "### Signs an analyst looks for\n\n" +
        "- **A burst of MFA push events for one account in a short window** — several denials then one acceptance, correlated to the same source.\n" +
        "- **Off-hours timing** — a real Uber-style incident often lands at 1-3 AM local to the victim, exploiting drowsiness.\n" +
        "- **Geographic or network mismatch** — the attempts originate from an IP, country, or autonomous system (AS — a block of internet address space under one organization's control, useful for flagging known hosting/VPN ranges) inconsistent with the user's normal pattern.\n" +
        "- **A new device or auth method registered immediately after the accepted push** — attackers commonly enroll their own device within seconds of getting in, so they can pass MFA again even after a password reset.\n\n" +
        "### Reading the Okta System Log\n\n" +
        "Okta writes every authentication action to its System Log using a dot-notation `eventType` taxonomy. The push-response event is `user.mfa.okta_verify.push_response`, with the outcome in `okta.outcome.result` (DENIED or SUCCESS):\n\n" +
        "```\n" +
        "okta.eventType: user.mfa.okta_verify.push_response\n" +
        "okta.outcome.result: DENIED\n" +
        "okta.client.ipAddress: 91.108.4.33\n" +
        "... (repeated 11 times over several minutes) ...\n" +
        "okta.eventType: user.mfa.okta_verify.push_response\n" +
        "okta.outcome.result: SUCCESS\n" +
        "okta.client.ipAddress: 91.108.4.33\n" +
        "okta.debugContext.debugData.pushApprovedAt: 2026-06-15T01:32:17Z\n" +
        "```\n\n" +
        "A single `push_response` record proves nothing on its own. The detection is a correlation rule: count DENIED `push_response` events for the same actor within a window (commonly 15 minutes), and alert when the count exceeds a threshold (commonly 5-10) AND is immediately followed by one SUCCESS from the same source.\n\n" +
        "### The mitigation that removes the attack surface: number matching\n\n" +
        "Both Microsoft (Entra ID / Microsoft Authenticator) and Okta ship **number matching**: instead of a simple Approve/Deny button, the sign-in screen shows a two-digit number that the user must type into the Authenticator app to complete the login. This closes the reflex-tap failure mode directly — an exhausted user tapping 'Approve' out of habit can no longer succeed by accident, because completing the login now requires reading a number off a separate screen and actively typing it. Microsoft made number matching mandatory tenant-wide after widespread fatigue-attack abuse; Okta's equivalent, delivered through Okta Verify, is called Number Challenge.\n\n" +
        "### The limit to remember (this comes back later in the room)\n\n" +
        "Number matching stops fatigue specifically. It does **not** stop a reverse-proxy phishing kit that simply relays the real number to the victim in real time, and it does nothing against a stolen session cookie, where no new authentication — and no push at all — ever happens.\n\n" +
        "### False-positive discipline\n\n" +
        "A single denied push is common and usually benign — a phone buzzed in a pocket, or a reflex tap before recognizing the login attempt. **Never escalate on one denial alone.** Escalate on the pattern.",
      checkpoint: {
        question: "An org has fully deployed Okta Number Challenge. What is NOT protected by this control alone?",
        options: [
          "Reflex-tap push bombing itself, since number matching directly and completely stops exactly that specific failure mode",
          "A reverse-proxy phishing kit relaying the real number to the victim, or any technique reusing an already-issued session cookie with no new push generated at all",
          "Nothing at all -- Number Challenge fully closes every single technique and attack family this entire room covers",
          "SMS-based one-time codes specifically, a factor type Number Challenge was never designed to interact with in any way",
        ],
        answer: 1,
        explanation: "Number Challenge (or number matching) closes the specific reflex-tap failure mode of push bombing. It does nothing against a proxy that simply forwards the real number to the victim, or against a stolen session cookie, since no push is generated during a replay at all.",
      },
      xp: 5,
    },

    // ── Question 2 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mfast-q2",
      question:
        "In the Okta System Log, which field pair together confirm a push notification was genuinely APPROVED by the user, as opposed to merely sent?",
      options: [
        "okta.eventType: user.session.start, paired with okta.outcome.reason: MFA_REQUIRED",
        "okta.eventType: user.mfa.okta_verify.push_response, paired with okta.outcome.result: SUCCESS",
        "okta.eventType: device.enrollment.create, paired with okta.outcome.result: SUCCESS",
        "okta.eventType: system.api_token.create, paired with okta.debugContext.debugData.factor: OKTA_VERIFY_PUSH",
      ],
      answer: 1,
      explanation:
        "user.mfa.okta_verify.push_response is specifically the push-response event, and outcome.result: SUCCESS on that event confirms the user approved it -- DENIED would mean the same event type recorded a rejection instead. user.session.start with MFA_REQUIRED only shows the password stage was satisfied and a challenge is now pending, not that it was answered. device.enrollment.create and system.api_token.create are both later persistence actions, unrelated to confirming the push response itself.",
      xp: 15,
    },

    // ── Reading 4: AiTM mechanics ────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "mfast-r4",
      heading: "Adversary-in-the-Middle Phishing and Session-Cookie Theft (T1539 + T1550.004)",
      content:
        "This technique family makes MFA fatigue look almost quaint, because it defeats MFA even when the user does everything right — the real password is entered, a genuine push is approved deliberately, and the account is still taken over. ATT&CK tracks the theft as **T1539, Steal Web Session Cookie** (Credential Access), and the reuse as **T1550.004, Use Alternate Authentication Material: Web Session Cookie** (Lateral Movement) — two IDs for two moments in one attack.\n\n" +
        "### The mechanism: adversary-in-the-middle (AiTM) reverse-proxy phishing\n\n" +
        "**Adversary-in-the-middle (AiTM)** describes any attack where the attacker's infrastructure sits transparently between the victim and the real service, relaying traffic both ways while secretly recording it. Applied to phishing, this is a **reverse-proxy phishing kit** — public toolkits in this category include Evilginx, Tycoon 2FA, and EvilProxy. CISA's 2025 update to the Scattered Spider advisory names this class of tooling as the mechanism behind the group's 'near-universal' MFA bypass.\n\n" +
        "1. The victim clicks a link to a look-alike domain (e.g. `login.company-sso-secure.com` instead of the real IdP domain).\n" +
        "2. That domain is not a fake page — it is a **reverse proxy** transparently forwarding every request and response between the victim's browser and the genuine IdP, in real time, both ways.\n" +
        "3. The victim types their real password into what functionally is the real login page (via the proxy). The proxy relays it straight to the real IdP.\n" +
        "4. The real IdP, seeing a correct password, does exactly what it should: sends a real MFA push to the victim's real phone.\n" +
        "5. The victim approves the real push, believing they are logging into the real service — because, functionally, they are; the proxy is just watching.\n" +
        "6. The real IdP, satisfied both factors were presented, issues a genuine, valid session cookie back through the proxy toward the victim's browser.\n" +
        "7. The proxy, sitting in the middle of that final step, **copies the session cookie for itself** before passing it along.\n\n" +
        "### The replay\n\n" +
        "With the stolen cookie, the attacker imports it into their own browser and presents it directly to the real service. Because a session cookie is a bearer credential (whoever holds it is treated as the logged-in user), the service accepts it exactly as it would from the original device — **no password, no MFA push, no authentication step of any kind runs on the attacker's side.** The replay is often from a completely different country, IP address, autonomous system, and even browser than the victim ever used, because none of that is checked by a bearer-credential model.\n\n" +
        "### The distinction this room keeps returning to\n\n" +
        "Contrast this against fatigue: in push bombing, the attacker never had the real second factor and had to trick a human into supplying it. Here, **MFA was performed completely correctly, by the real, willing user** — the failure is in what happened to the artifact afterward, not in the authentication ceremony itself. This is 'MFA made irrelevant' rather than 'MFA bypassed.'",
      codeExample:
        "AiTM reverse-proxy phishing, request flow:\n\n" +
        "  Victim's browser        Attacker's reverse proxy         Real IdP\n" +
        "  ----------------        ------------------------        --------\n" +
        "  GET login page  ------> forwards request        ------> \n" +
        "                  <------ forwards real page      <------ real login page\n" +
        "  POST password   ------> forwards password       ------> validates, sends\n" +
        "                  <------ relays real MFA push     <----- real push to phone\n" +
        "  user taps APPROVE (real push, real phone, real IdP)\n" +
        "                                                          issues session cookie\n" +
        "                  <------ ** COPIES cookie **      <----- \n" +
        "  <------ forwards cookie to victim, login 'succeeds' normally\n\n" +
        "  Attacker separately replays the copied cookie later:\n" +
        "  Attacker's browser --[stolen cookie, no login at all]--> Real IdP: ACCEPTED\n",
      xp: 5,
    },

    // ── Analyst choice 1: single accidental deny (FP control) ───────────────
    {
      type: "analyst_choice" as const,
      id: "mfast-ac1",
      heading: "Triage: One Denied Push at 9:14 AM",
      scenario:
        "An alert fires on a single denied Okta Verify push for r.aldana, Senior Claims Adjuster at Castellan Risk Partners. The alert rule watches for any MFA denial. Checking the account's recent history shows only this one denial, followed 41 seconds later by an approved push from the same IP address and the same registered device, at a normal mid-morning hour local to the user.",
      event: singleDeniedPushEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is exactly the pattern the fatigue-detection reading warned against escalating on reflex: ONE denial, immediately followed by a correct approval, from the same IP and the same registered device, at a normal working hour. There is no burst, no off-hours timing, and no geographic mismatch -- none of the signature elements of push bombing are present. IT verification confirms a mundane cause (a notification mix-up). This is the control case: a real MFA denial event that is not an attack.",
      fp_trap:
        "The alert rule that fired here watches for ANY denial, which is exactly the kind of overly broad rule that trains analysts to escalate reflexively. A single denial immediately corrected by the same device and network is common, ordinary user behavior -- treating it as a true positive without checking for the burst pattern (multiple denials, then acceptance, from a mismatched source) is the mistake this task is built to catch.",
      xp: 20,
    },

    // ── Reading 5: session replay detection ──────────────────────────────────
    {
      type: "reading" as const,
      id: "mfast-r5",
      heading: "Detecting Session Replay: Reading Entra ID Sign-In Logs Side by Side",
      content:
        "Session-cookie replay cannot be caught by watching for a 'bad login' — there usually isn't one on the attacker's side at all. It is detected by comparing two sign-in records against each other.\n\n" +
        "### The single strongest field: sessionId\n\n" +
        "Microsoft Entra ID's sign-in logs carry a `sessionId` field on every interactive sign-in. Because a session cookie is one specific artifact, **the same sessionId value should never legitimately appear on two sign-ins from two different IP addresses, autonomous systems (ASNs), and browser fingerprints.** This is the single strongest, most precise tell available for T1550.004:\n\n" +
        "```\n" +
        "Sign-in #1 (victim's real login, via the proxy without her knowing):\n" +
        "  sessionId: 3d8a6f21-0c47-4e91-...\n" +
        "  ipAddress: <proxy IP>\n" +
        "  isInteractive: true\n" +
        "  authenticationDetails: [Password: succeeded, MFA push: succeeded]\n\n" +
        "Sign-in #2 (the replay, minutes later):\n" +
        "  sessionId: 3d8a6f21-0c47-4e91-...   <-- IDENTICAL to sign-in #1\n" +
        "  ipAddress: <a different country/ASN entirely>\n" +
        "  isInteractive: false\n" +
        "  authenticationDetails: [\"Previously satisfied\" -- \"MFA requirement satisfied by claim in the token\"]\n" +
        "```\n\n" +
        "That last line — an authentication step whose detail literally reads 'satisfied by a claim in the token,' with no challenge actually presented — is the log's own admission that no fresh authentication occurred.\n\n" +
        "### The trap: risk score and Conditional Access both stay green\n\n" +
        "`riskLevelDuringSignIn` and `conditionalAccessStatus` frequently read 'none' and 'success' on the replayed sign-in, because the risk engine and Conditional Access both see a technically valid, MFA-satisfied token and have no independent way to know it was stolen rather than freshly issued. **A clean risk score is not proof of a clean sign-in for this technique** — which is exactly why the sessionId correlation matters more than any single risk field.\n\n" +
        "### Reading device and location fields as supporting, not primary, evidence\n\n" +
        "`deviceDetail.isCompliant`, `deviceDetail.browser`, and `location.city`/`autonomousSystemNumber` are useful corroboration — a replay commonly shows an unmanaged, non-compliant device and a different browser than the user's known baseline — but geography alone is fragile (a legitimate VPN or business trip produces the same kind of change). The sessionId match is what turns a plausible travel story into confirmed replay.",
      checkpoint: {
        question: "Why is a 'none' riskLevelDuringSignIn on the replayed sign-in specifically dangerous to trust?",
        options: [
          "It genuinely isn't dangerous at all -- a 'none' risk level always and reliably means the sign-in in question is completely safe",
          "The risk engine evaluates the token's own claims, which already assert MFA was satisfied, with no independent way to detect the token itself was stolen -- a clean score is not proof of a clean sign-in here",
          "riskLevelDuringSignIn is a fully deprecated field and is no longer populated by Entra ID on any sign-in record at all",
          "A 'none' risk level is a value that only ever appears on sign-ins originating from outside the signed-in user's own home country",
        ],
        answer: 1,
        explanation: "This is the specific trap the reading calls out: the risk engine and Conditional Access both trust the token's claims, and a stolen token still carries a genuine 'MFA satisfied' claim. That is exactly why the sessionId correlation, not the risk score, is the primary evidence for session replay.",
      },
      xp: 5,
    },

    // ── Log analysis 1 ────────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "mfast-la1",
      heading: "Investigate: A Second Sign-In for d.okafor",
      context:
        "d.okafor, Senior Underwriter at Castellan Risk Partners, signed in interactively at 14:41 this morning from her usual Chicago office network on her Entra-joined laptop: that sign-in carried sessionId 3d8a6f21-0c47-4e91-b3d0-7f2e9a541c86, isInteractive true, a fresh Microsoft Authenticator push approval in its authenticationDetails, and deviceDetail.isCompliant true. Eleven minutes later, the event below was recorded for the same account. d.okafor is currently at her desk in Chicago and has not travelled recently.",
      event: sessionReplaySignInEvent,
      questions: [
        {
          question:
            "Comparing this event to the interactive sign-in described above, which single fact proves this is the same session being replayed rather than a second legitimate logon?",
          options: [
            "The appDisplayName field happens to read 'Microsoft Office' identically on both of the two separate sign-in records",
            "The sessionId is identical across both sign-ins despite a completely different IP address, ASN, and browser fingerprint each time",
            "The resultType field reads the value '0' on both sign-in records, which simply means each one individually succeeded",
            "The conditionalAccessStatus field happens to read 'success' consistently on both of the two sign-in records",
          ],
          answer: 1,
          explanation:
            "A shared sessionId is the one field that is architecturally supposed to be unique to a single browser session -- two sign-ins carrying the identical value from a different IP, ASN and browser cannot be two separate legitimate logons, only one artifact used twice. appDisplayName being shared just means both used the same application, which many unrelated logins do. resultType '0' and conditionalAccessStatus 'success' both just mean 'this sign-in succeeded' -- they say nothing about whether it was a fresh authentication or a replay, which is exactly the trap this room's reading warned about.",
          xp: 15,
        },
        {
          question:
            "This event's riskLevelDuringSignIn reads 'none' and conditionalAccessStatus reads 'success'. What should the analyst conclude from that pair of fields alone?",
          options: [
            "The sign-in is definitely benign, since both signals are green and Entra's risk engine would have flagged anything genuinely malicious",
            "Conditional Access failed to apply any policy at all to this sign-in, which is itself the security gap that needs fixing",
            "Nothing conclusive either way -- the risk engine and Conditional Access both evaluate the token's own claims, which already assert MFA was satisfied, so a clean score here is expected for a replayed token and does not clear it",
            "riskLevelDuringSignIn only populates for sign-ins originating outside the tenant's home country, so this field should be disregarded entirely",
          ],
          answer: 2,
          explanation:
            "This is the central trap taught in this room: both fields evaluate the SIGNED TOKEN's claims, and a replayed token still carries a genuine MFA-satisfied claim from the original login. Neither field has visibility into whether the token itself was stolen. Option a repeats exactly the mistake the room warns against. Option b is factually wrong -- conditionalAccessStatus: success means a policy DID evaluate and pass, not that none applied. Option d is not how the field behaves; it is populated on domestic sign-ins too.",
          xp: 15,
        },
      ],
    },

    // ── Reading 6: token theft two layers ────────────────────────────────────
    {
      type: "reading" as const,
      id: "mfast-r6",
      heading: "Token Theft on Two Layers: Windows OS Tokens (T1134.001) vs Stolen OAuth Tokens (T1528)",
      content:
        "These two techniques are frequently confused because both are called 'token theft' in casual conversation — but they sit on entirely different layers, with entirely different telemetry.\n\n" +
        "### T1134.001 — a Windows endpoint technique, not a cloud one\n\n" +
        "**Access Token Manipulation: Token Impersonation/Theft** is mapped by MITRE ATT&CK to the **Privilege Escalation** and **Defense Evasion (TA0005)** tactics (ATT&CK v19, April 2026, relabeled TA0005 'Stealth' while keeping the same ID; most tooling and this platform's other rooms still use the long-established name Defense Evasion). It has nothing to do with a browser cookie or an IdP: it abuses Windows APIs (`DuplicateToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`) to copy an existing Windows security token already present on a compromised machine.\n\n" +
        "The classic pattern is a 'potato'-family tool that coerces a SYSTEM-level Windows service (commonly the Print Spooler) into connecting to an attacker-controlled named pipe, then impersonates the resulting SYSTEM token. This is detected entirely through **endpoint telemetry**: Sysmon Event ID 18 (Pipe Connected) showing a SYSTEM process connecting to a suspicious pipe, Sysmon Event ID 10 (ProcessAccess) showing a GrantedAccess value like `0x1410` against that SYSTEM process, and Windows Event IDs 4672/4673 showing `SeImpersonatePrivilege` assigned and then exercised. **If a case file shows a browser, a phishing link, or an IdP sign-in log, it is not T1134.001** — it is almost certainly one of the cloud-identity techniques below.\n\n" +
        "### T1528 — the cloud-native cousin, detected through sign-in and consent logs\n\n" +
        "**Steal Application Access Token** (Credential Access tactic) is the technique actually detected through identity-provider telemetry. Its most common real-world form is **illicit OAuth consent grant**: an attacker registers a malicious application with an innocuous name, then phishes the victim with a link asking them to 'sign in with Microsoft' and grant that application permissions (read mail, read files) — a real, working OAuth consent screen, not a fake login page. If the victim clicks Accept, the malicious app receives a genuine access token and refresh token, valid until the grant is revoked, requiring no password or MFA ever again — OAuth delegated access was never designed to be re-challenged on every use.\n\n" +
        "Detection means auditing **application consent events** (in Entra ID: the 'Consent to application' audit log operation) for unusual publishers, newly registered apps, or overly broad requested scopes — such as full mailbox read access requested by an app with no plausible reason to need it.\n\n" +
        "### The one-sentence rule for telling them apart\n\n" +
        "Ask: is the evidence sitting in Sysmon/Windows Security on one endpoint (T1134.001), or in an identity provider's sign-in/consent log spanning the whole tenant (T1528)? The answer determines which log source, which team, and which containment action apply.",
      xp: 5,
    },

    // ── Question 3 ─────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mfast-q3",
      question:
        "A ticket is labeled 'T1134.001' but its only evidence is an Entra ID audit log entry titled 'Consent to application' showing a newly registered app requesting full mailbox read access. What is the most accurate assessment?",
      options: [
        "The label is correct -- any token-related finding appearing anywhere in a cloud audit log automatically qualifies as T1134.001 by definition",
        "The label is likely wrong -- T1134.001 needs endpoint Sysmon/Windows Security telemetry, while this consent-grant evidence actually matches T1528, Steal Application Access Token",
        "The label is correct, but only in the specific case where the requesting application also happens to be unsigned by any recognized publisher",
        "Neither T1134.001 nor T1528 apply here -- this specific evidence can only ever indicate T1606.002, the Golden SAML technique",
      ],
      answer: 1,
      explanation:
        "T1134.001's telemetry lives entirely on the endpoint (Sysmon Event 10/18, Windows 4672/4673) -- it has no relationship to a cloud consent-grant event. A 'Consent to application' entry describing a newly registered app requesting broad mailbox permissions is the textbook signature of T1528's illicit-consent-grant variant, not T1134.001. Signing status is irrelevant to which technique ID applies. T1606.002 (Golden SAML) is a different technique again, identified by a federated sign-in with no matching on-prem token issuance -- not by a consent-grant record.",
      xp: 20,
    },

    // ── Reading 7: Golden SAML ────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "mfast-r7",
      heading: "Golden SAML (T1606.002): Forging Trust Itself",
      content:
        "### What it is\n\n" +
        "**SAML (Security Assertion Markup Language)** is a federation protocol: an on-premises server — commonly Microsoft's AD FS (Active Directory Federation Services) — vouches for a user's identity to a cloud service by signing a cryptographic assertion with a private key both sides trust. **T1606.002, Forge Web Credentials: SAML Tokens** (Credential Access tactic) describes an attacker who has stolen that private signing key and can now mint a valid-looking SAML assertion for ANY user — including a Global Administrator — entirely offline, with no interaction with the federation server at all.\n\n" +
        "### How it's executed\n\n" +
        "The attacker must already control the on-premises AD FS server (the initial foothold is a separate, earlier step). From there: (1) read the AD FS DKM (Distributed Key Manager) master key out of Active Directory — the secret that decrypts the token-signing certificate; (2) export the token-signing certificate's private key using that DKM key; (3) with the private key in hand, sign a brand-new SAML assertion claiming to be any user, on the attacker's own machine, with no request ever sent to the real AD FS server; (4) present that forged assertion directly to the cloud service, which accepts it because it is validly signed by a key it trusts.\n\n" +
        "### The tell: an absence, not a presence\n\n" +
        "This is one of the hardest cases in identity security because there is no 'loud' malicious artifact — the whole case turns on something MISSING. **A genuine federated login always leaves a token-issuance audit record on the AD FS server** (Windows Event ID 1200 on AD FS). A forged assertion, minted entirely offline with the stolen key, is never seen by the federation server at all, so it leaves **no matching issuance record**. A cloud sign-in that claims `tokenIssuerType: ADFSFederated` while the AD FS server shows no corresponding issuance for that session cannot have come from the identity provider — it was minted offline.\n\n" +
        "Reinforcing tells: forged sign-ins for privileged accounts, at odd hours, from external addresses, each carrying an MFA claim 'satisfied by a claim in the token' though no challenge was ever presented — the same MFA-by-claim pattern seen in session replay, but here explained by a forged assertion rather than a stolen cookie.\n\n" +
        "### Why MFA and a password reset don't help\n\n" +
        "The cloud delegates the entire authentication decision — including how strongly the user was verified — to the federation server, and reads that verdict from the signed token's own claims. Whoever holds the signing key controls those claims. A minted token simply asserts MFA was completed, and the cloud accepts it without ever contacting the user. Because the forged token carries no password at all, resetting the victim's password changes nothing the attacker used.\n\n" +
        "### The correct containment\n\n" +
        "Trust is anchored on the signing certificate, so recovery means retiring the stolen key everywhere it is honored: roll the AD FS token-signing certificate twice (AD FS keeps a primary and secondary certificate specifically to allow this), revoke live sessions and refresh tokens for every potentially affected identity, and treat all federated accounts as exposed until the new key is fully in force.",
      xp: 5,
    },

    // ── Ordering task ──────────────────────────────────────────────────────
    {
      type: "ordering" as const,
      id: "mfast-o1",
      heading: "Order the AiTM Reverse-Proxy Kill Chain",
      instructions:
        "Place these eight steps of a session-cookie-theft attack (T1539 + T1550.004) in the order they actually occur, from the initial lure to the attacker establishing persistence.",
      items: [
        { id: "step-lure", text: "A phishing lure delivers a link to a look-alike domain fronting a reverse proxy" },
        { id: "step-click", text: "The victim clicks the link; their browser reaches the attacker's reverse proxy" },
        { id: "step-password", text: "The victim submits their real password, which the proxy relays to the genuine identity provider" },
        { id: "step-push", text: "The genuine identity provider sends a real MFA push to the victim's real phone" },
        { id: "step-approve", text: "The victim approves the genuine push, believing the login is proceeding normally" },
        { id: "step-copy", text: "The identity provider issues a valid session cookie, which the proxy copies while relaying it onward" },
        { id: "step-replay", text: "The attacker replays the stolen session cookie from separate infrastructure, with no authentication step at all" },
        { id: "step-persist", text: "The attacker registers a new authentication method or device on the account for persistence" },
      ],
      correct_order: [
        "step-lure",
        "step-click",
        "step-password",
        "step-push",
        "step-approve",
        "step-copy",
        "step-replay",
        "step-persist",
      ],
      explanation:
        "The defining property of this kill chain is that the theft (copying the cookie) happens DURING a completely genuine login -- the victim's password and MFA approval are both real, and the proxy is simply relaying them while secretly keeping a copy of what comes back. Everything after the copy is pure replay, requiring no further interaction with the victim at all. Persistence (registering a new device) typically comes last, so the attacker can pass MFA again even after the original session or password is invalidated.",
      xp: 20,
    },

    // ── Reading 8: defense in depth ──────────────────────────────────────────
    {
      type: "reading" as const,
      id: "mfast-r8",
      heading: "Defense in Depth: From Number Matching to Phishing-Resistant FIDO2",
      content:
        "Every mitigation here sits on a ladder of increasing strength. Knowing exactly what rung each one occupies — and what it does NOT cover — is what separates a checklist-following analyst from one who can explain a security posture to a stakeholder.\n\n" +
        "### Rung 1 — Number matching / Number Challenge: stops fatigue only\n\n" +
        "Closes the reflex-tap failure mode of push bombing. Does nothing against AiTM (the proxy relays the real number) or any form of token/cookie theft (there is no push at all in a replay).\n\n" +
        "### Rung 2 — Conditional Access and device compliance: raises the bar, doesn't eliminate it\n\n" +
        "Requiring a compliant, managed device or restricting sign-ins to named network locations meaningfully narrows an attacker's options — but a replayed session in T1550.004 can still pass Conditional Access with a 'success' result, because the policy engine trusts the token's own claims about what already happened.\n\n" +
        "### Rung 3 — Token Protection: binds the token to the requesting device\n\n" +
        "Microsoft's **Token Protection** (a Conditional Access session control) cryptographically binds certain sign-in session tokens — most importantly the Primary Refresh Token (PRT) — to the specific device that requested them. If enforced, a stolen bound token simply cannot be used from a different device: the binding check fails. Native-app coverage (Windows, iOS/iPadOS, macOS) is Generally Available for major Microsoft resources (Exchange Online, SharePoint Online, Teams); browser-based coverage remains in Preview with narrower scope — meaningful but not yet universal closure of the replay path.\n\n" +
        "### Rung 4 — Phishing-resistant MFA (FIDO2/WebAuthn): the control that actually stops AiTM\n\n" +
        "CISA's fact sheet on phishing-resistant MFA names exactly two qualifying technologies: **FIDO2/WebAuthn** security keys and **PIV/CAC** smart cards. Everything else — SMS, app push, even push with number matching — is explicitly named by CISA as still vulnerable to phishing and AiTM relay. The structural reason FIDO2 is different: **origin binding**. A FIDO2 credential cryptographically signs a challenge together with the exact domain (origin) the browser is talking to. If a reverse-proxy kit presents `login.company-sso-secure.com` instead of the real IdP domain, the security key detects the mismatch and refuses to sign anything — the attack fails at the protocol level, automatically, with no reliance on human vigilance. This matches NIST SP 800-63B's formal concept of **verifier impersonation resistance**: an authenticator that cryptographically binds its output to the specific channel it is negotiating, so a fraudulent verifier (a phishing proxy) cannot successfully relay a real approval.\n\n" +
        "### Rung 5 — Shorter token lifetimes and Continuous Access Evaluation\n\n" +
        "Shortening how long a stolen session or refresh token stays valid limits the damage window even when theft succeeds. Microsoft's Continuous Access Evaluation (CAE) re-checks critical signals (a disabled user, a password reset) near-real-time rather than waiting for natural token expiry.\n\n" +
        "### Protecting the signing key, for Golden SAML\n\n" +
        "Golden SAML has no MFA rung at all, because it never touches authentication — it forges the OUTPUT of authentication. The only real mitigation is protecting the AD FS signing key with domain-controller-level rigor, and rolling the signing certificate plus revoking sessions if compromise is suspected.\n\n" +
        "### The analyst decision framework\n\n" +
        "When handed an identity-compromise alert, ask in order: (1) Did MFA actually run on this sign-in, or does the authentication detail say 'satisfied by a claim in the token' with no real challenge? — that distinguishes fatigue (a human was tricked) from artifact theft (something was stolen or forged). (2) If a fresh challenge ran, could a reverse proxy have relayed it? (3) If nothing ran at all, which artifact was reused — a session cookie, an OAuth token, a Windows OS token, or a wholly forged SAML assertion with no issuance record anywhere?",
      xp: 5,
    },

    // ── Question 4 ─────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mfast-q4",
      question:
        "A tenant has deployed Microsoft's Token Protection, binding Primary Refresh Tokens to the requesting device, but has NOT deployed FIDO2 security keys. Which of this room's attacks would still most plausibly succeed?",
      options: [
        "T1621 MFA fatigue -- Token Protection has no effect on it, since fatigue never involves stealing a token at all; the human being worn down is the entire attack surface",
        "None of the room's attacks would succeed, since Token Protection closes every technique that relies on a stolen artifact",
        "T1550.004 session replay -- Token Protection binds tokens to a device, so it would fully prevent this specific technique with no exceptions",
        "T1621 MFA fatigue would be fully prevented, since Token Protection also enforces number matching as part of the same feature",
      ],
      answer: 0,
      explanation:
        "Token Protection addresses artifact theft (binding a token to a device so a stolen copy fails elsewhere) -- it has nothing to do with fatigue, which targets the HUMAN during a live authentication attempt, not a token afterward. Option c overstates Token Protection's coverage: browser-based scenarios and non-covered resources remain exposed even with it deployed. Option d incorrectly bundles two unrelated features -- Token Protection and number matching are separate controls addressing separate techniques.",
      xp: 20,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "mfast-f1",
      prompt:
        "This room covered five ATT&CK techniques. Which exact technique ID (format Txxxx) covers an attacker stealing an OAuth access token through a malicious application's illicit consent grant -- the cloud-native cousin of Windows OS token impersonation?",
      answer: "T1528",
      hint: "Covered in the reading titled 'Token Theft on Two Layers: Windows OS Tokens (T1134.001) vs Stolen OAuth Tokens (T1528)' -- it is explicitly named as the technique detected through sign-in and consent logs, not endpoint telemetry.",
      xp: 15,
    },
  ],
};

export const roomsBatch41 = [mfaSessionTokenAttacksRoom];
