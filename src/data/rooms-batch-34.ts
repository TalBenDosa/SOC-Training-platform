/**
 * Learning Rooms — Batch 34
 *
 * One capstone-style room closing a documented, high-priority coverage gap:
 * Business Email Compromise (BEC) is the single costliest reported cybercrime
 * category year after year, yet prior rooms only taught BEC in fragments
 * (a phishing-analysis reading, a remote-email-collection inbox-rule deep
 * dive, an AiTM token-theft scenario pack). No room walked a BEC case
 * end to end — account takeover through Entra ID sign-in logs, the inbox
 * rule that conceals it, the actual wire-transfer fraud it enables, and the
 * full analyst response, financial and technical.
 *
 * Room in this batch:
 *  1. bec-investigation — T1078 (via T1566.002), T1078.004, T1114.003,
 *     T1534, T1656, T1199, T1098.005. Entra ID sign-in log fields
 *     (isInteractive, incomingTokenType, tokenIssuerType,
 *     conditionalAccessStatus, riskLevelDuringSignIn, deviceDetail,
 *     correlationId), O365 Unified Audit Log New-InboxRule concealment
 *     (MoveToFolder/StopProcessingRules variant, distinct from the
 *     ForwardTo/DeleteMessage pattern already taught in
 *     remote-email-collection), the four BEC vectors (ATO, lookalike domain,
 *     thread hijacking, vendor email compromise), wire-fraud timeline
 *     reconstruction, bank-recall urgency, and full analyst response.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Business Email Compromise (BEC): End-to-End Investigation
// ===========================================================================

const becSigninReplayEvent: TelemetryEvent = {
  id: "evt-bec-la1-001",
  ts: "2026-04-14T14:22:07.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "auth_success",
  severity: "critical",
  mitre_technique: "T1078.004",
  mitre_tactic: "Initial Access",
  user_email: "p.nair@meridianstructural.com",
  user_title: "Accounts Payable Lead",
  src_ip: "154.72.18.63",
  geo: { country: "Nigeria", city: "Lagos", latitude: 6.5244, longitude: 3.3792 },
  description:
    "A non-interactive Entra ID sign-in for p.nair, sourced from Lagos, carries the same correlationId as an interactive sign-in from Denver nine minutes earlier. MFA shows as satisfied by a claim already present in the token rather than a fresh challenge.",
  raw: {
    "azure.signinlogs.category": "NonInteractiveUserSignInLogs",
    "azure.signinlogs.operationName": "Sign-in activity",
    "azure.signinlogs.properties.id": "e2d5b804-97c1-4a3f-8e26-3b0f9c5a71d8",
    "azure.signinlogs.properties.createdDateTime": "2026-04-14T14:22:07.000Z",
    "azure.signinlogs.properties.userPrincipalName": "p.nair@meridianstructural.com",
    "azure.signinlogs.properties.userDisplayName": "Priya Nair",
    "azure.signinlogs.properties.userId": "a7c4e91b-3d58-4f02-8b16-9a2c7f4b6e03",
    "azure.signinlogs.properties.correlationId": "9f4a2c68-3e15-4d70-8b92-6c1a5f8e0937",
    "azure.signinlogs.properties.sessionId": "c15e7d02-4b89-4f3a-9d16-2e8c6a1f5b74",
    "azure.signinlogs.properties.appDisplayName": "Office 365 Exchange Online",
    "azure.signinlogs.properties.appId": "00000002-0000-0ff1-ce00-000000000000",
    "azure.signinlogs.properties.resourceDisplayName": "Office 365 Exchange Online",
    "azure.signinlogs.properties.clientAppUsed": "Browser",
    "azure.signinlogs.properties.isInteractive": false,
    "azure.signinlogs.properties.ipAddress": "154.72.18.63",
    "azure.signinlogs.properties.autonomousSystemNumber": 37282,
    "azure.signinlogs.properties.location.city": "Lagos",
    "azure.signinlogs.properties.location.countryOrRegion": "NG",
    "azure.signinlogs.properties.location.geoCoordinates.latitude": 6.5244,
    "azure.signinlogs.properties.location.geoCoordinates.longitude": 3.3792,
    "azure.signinlogs.properties.deviceDetail.deviceId": "",
    "azure.signinlogs.properties.deviceDetail.displayName": "",
    "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 10",
    "azure.signinlogs.properties.deviceDetail.browser": "Chrome 123.0.6312",
    "azure.signinlogs.properties.deviceDetail.isCompliant": false,
    "azure.signinlogs.properties.deviceDetail.isManaged": false,
    "azure.signinlogs.properties.deviceDetail.trustType": "",
    "azure.signinlogs.properties.userAgent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
    "azure.signinlogs.properties.authenticationDetails": [
      {
        authenticationStepDateTime: "2026-04-14T14:22:07.000Z",
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
        id: "4a7c1e93-8d25-4b6f-9c01-d3f28b752f69",
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
    "azure.signinlogs.properties.incomingTokenType": "refreshToken",
    "azure.signinlogs.properties.status.errorCode": 0,
    "azure.signinlogs.resultType": "0",
  },
};

const becInboxRuleEvent: TelemetryEvent = {
  id: "evt-bec-la2-001",
  ts: "2026-04-14T14:31:55.000Z",
  source: "o365",
  vendor: "Microsoft 365 Unified Audit Log",
  event_type: "policy_modification",
  severity: "critical",
  mitre_technique: "T1114.003",
  mitre_tactic: "Collection",
  user_email: "p.nair@meridianstructural.com",
  src_ip: "154.72.18.63",
  geo: { country: "Nigeria", city: "Lagos" },
  description:
    "A New-InboxRule operation created a rule on p.nair's mailbox nine minutes after the non-interactive sign-in from the same IP address, moving specific incoming mail into a folder and marking it read rather than forwarding or deleting it.",
  raw: {
    "data.office365.Operation": "New-InboxRule",
    "data.office365.RecordType": "1",
    "data.office365.Workload": "Exchange",
    "data.office365.UserId": "p.nair@meridianstructural.com",
    "data.office365.UserType": "0",
    "data.office365.ResultStatus": "Succeeded",
    "data.office365.ClientIP": "154.72.18.63",
    "data.office365.Id": "d8a3f612-6c05-4e2b-9f47-1a5d8e3c9046",
    "data.office365.OrganizationId": "5c8a2f19-4d63-4b8e-9c07-1e83a5f26d94",
    "data.office365.CreationTime": "2026-04-14T14:31:55",
    "data.office365.Parameters[0].Name": "Name",
    "data.office365.Parameters[0].Value": ".",
    "data.office365.Parameters[1].Name": "MoveToFolder",
    "data.office365.Parameters[1].Value": "RSS Feeds",
    "data.office365.Parameters[2].Name": "MarkAsRead",
    "data.office365.Parameters[2].Value": "True",
    "data.office365.Parameters[3].Name": "SubjectOrBodyContainsWords",
    "data.office365.Parameters[3].Value": "cascadefab.com,wire,bank details,ACH,remittance",
    "data.office365.Parameters[4].Name": "StopProcessingRules",
    "data.office365.Parameters[4].Value": "True",
  },
};

const becLegitimateForwardEvent: TelemetryEvent = {
  id: "evt-bec-ac1-001",
  ts: "2026-03-02T10:14:00.000Z",
  source: "o365",
  vendor: "Microsoft 365 Unified Audit Log",
  event_type: "policy_modification",
  severity: "medium",
  mitre_technique: "T1114.003",
  mitre_tactic: "Collection",
  user_email: "t.reyes@meridianstructural.com",
  src_ip: "198.51.100.22",
  geo: { country: "United States", city: "Denver" },
  it_verify_result: "confirmed",
  it_verify_message:
    "Helpdesk ticket HD-30410: t.reyes requested a forwarding rule to a.walsh (Accounts Payable Team Lead) covering April 2 through April 16 while on approved leave, per Meridian's standard AP coverage procedure.",
  description:
    "A New-InboxRule operation created a rule on t.reyes's mailbox forwarding mail to a.walsh@meridianstructural.com, an internal colleague.",
  raw: {
    "data.office365.Operation": "New-InboxRule",
    "data.office365.RecordType": "1",
    "data.office365.Workload": "Exchange",
    "data.office365.UserId": "t.reyes@meridianstructural.com",
    "data.office365.UserType": "0",
    "data.office365.ResultStatus": "Succeeded",
    "data.office365.ClientIP": "198.51.100.22",
    "data.office365.Id": "6b91d4f2-3a05-4c68-9e17-7d2a5f8b0c94",
    "data.office365.OrganizationId": "5c8a2f19-4d63-4b8e-9c07-1e83a5f26d94",
    "data.office365.CreationTime": "2026-03-02T10:14:00",
    "data.office365.Parameters[0].Name": "Name",
    "data.office365.Parameters[0].Value": "Leave Coverage - AWalsh",
    "data.office365.Parameters[1].Name": "ForwardTo",
    "data.office365.Parameters[1].Value": "a.walsh@meridianstructural.com",
    "data.office365.Parameters[2].Name": "SubjectOrBodyContainsWords",
    "data.office365.Parameters[2].Value": "",
    "data.office365.Parameters[3].Name": "StopProcessingRules",
    "data.office365.Parameters[3].Value": "False",
  },
};

const becInvestigationRoom = {
  id: "bec-investigation",
  title: "Business Email Compromise (BEC): End-to-End Investigation",
  description:
    "Walk a real Business Email Compromise case from account takeover to a fraudulent wire transfer and back to full analyst response — the single costliest reported category of cybercrime, and one that runs almost entirely without malware. Covers the four BEC vectors (account takeover, lookalike domains, thread hijacking, vendor email compromise), how to read Entra ID sign-in logs for token replay and impossible travel (isInteractive, incomingTokenType, conditionalAccessStatus, riskLevelDuringSignIn, deviceDetail), the inbox-rule concealment techniques attackers build specifically to hide wire-fraud threads, timeline reconstruction, and the full response — technical containment, financial recall, scoping, and reporting.",
  difficulty: "intermediate" as const,
  category: "Identity",
  estimatedMinutes: 65,
  xp: 400,
  icon: "💸",
  prerequisites: ["phishing-analysis", "remote-email-collection"],
  tasks: [
    // ── Reading 1: what BEC is, and why it isn't just phishing ─────────────
    {
      type: "reading" as const,
      id: "bec-r1",
      heading: "What Business Email Compromise Actually Is — And Why It Isn't Just Phishing",
      content:
        "Business Email Compromise (BEC) is a family of attacks in which someone convinces an organization to move money, data, or access somewhere it shouldn't go, by making a fraudulent request look exactly like a legitimate one that would normally be trusted and acted on. In the FBI's Internet Crime Complaint Center (IC3) annual reports, BEC has for years been the single costliest category of reported cybercrime — regularly measured in the billions of dollars in a single year, ahead of ransomware, ahead of any individual malware family. It doesn't get the same headlines as a hospital ransomware outage, because no systems go down and nothing gets encrypted. Money just quietly moves to the wrong account, and by the time anyone notices, it's often gone.\n\n" +
        "**The defining fact, and why it changes everything about how you investigate.** Most BEC attacks involve no malware at all. There's no payload to sandbox, no process tree to pull apart, no EDR detection to pivot from. The entire attack is social engineering plus identity and account abuse — a convincing message, sent from a trusted-looking source, asking a real human being to do something they're already authorized to do (approve a payment, change a bank account, wire funds) just this once, for the wrong reason. That means the evidence for a BEC investigation lives almost entirely in identity and mail-audit telemetry — Entra ID sign-in logs, the Office 365 Unified Audit Log, mailbox rule history — not in your endpoint detection stack. An analyst who reflexively starts a BEC investigation by pulling EDR alerts is looking in the wrong place first.\n\n" +
        "**Who gets targeted, and what's actually asked for.** BEC overwhelmingly targets people who can move money or who sit close to someone who can: accounts payable staff, financial controllers, executive assistants, HR staff who manage payroll. The ask is almost always one of a small set of things — change the bank details on an outstanding invoice, approve an urgent wire before a deadline, buy a batch of gift cards for an executive's 'confidential' request, redirect an employee's payroll deposit. None of these asks are unusual on their own; that's exactly the point.\n\n" +
        "**Patient, not indiscriminate.** Commodity phishing is a numbers game — millions of nearly-identical emails, most caught by spam filters or antivirus, profitable purely on volume. BEC is the opposite: a targeted attacker may sit quietly inside a compromised mailbox for days or weeks, reading real correspondence, learning how a specific person actually writes, waiting for the right moment in an active, high-value conversation before sending a single, carefully-timed fraudulent message. That patience is what makes the final message so hard to catch by eye — and exactly why this room spends as much time on identity logs and timelines as it does on the fraudulent email itself.\n\n" +
        "**What's ahead.** The next reading breaks down the four distinct ways a BEC attack actually gets its foothold — because the technical evidence you'd look for is completely different depending on which one you're facing.",
      checkpoint: {
        question: "Per Reading 1, why does EDR/antivirus telemetry play little role in most BEC investigations?",
        options: [
          "Because BEC attackers always disable EDR agents as their very first action, so no telemetry survives to review",
          "Because most BEC attacks involve no malware at all — the attack is social engineering plus identity/account abuse, so the evidence lives in identity and mail-audit logs instead",
          "Because BEC only ever targets Linux servers, which this platform's EDR rooms don't cover",
          "Because EDR tools are contractually prohibited from monitoring finance department endpoints at most organizations",
        ],
        answer: 1,
        explanation:
          "Reading 1 was explicit: BEC is overwhelmingly a malware-free attack — a convincing message plus identity/account abuse. That means Entra ID sign-in logs and the O365 Unified Audit Log, not EDR, are where this investigation actually happens.",
      },
    },
    // ── Reading 2: the four BEC vectors ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "bec-r2",
      heading: "The Four Ways BEC Actually Happens",
      content:
        "Every BEC case traces back to one of four distinct footholds. Knowing which one you're facing changes where you'll find evidence — and, in one case, tells you the evidence won't exist in your own tenant at all.\n\n" +
        "**1. Account takeover (ATO) — MITRE ATT&CK T1078 (Valid Accounts), reached via T1566.002 (Spearphishing Link).** The attacker obtains a real, working session or valid credentials for the target's own mailbox and operates it directly. The two dominant paths in current attacks are adversary-in-the-middle (AiTM) phishing kits — a reverse-proxy page that sits between the victim and the real login page, silently capturing the full authenticated session including the post-MFA token, which is exactly what this room's log-analysis tasks are built around — and infostealer malware, which harvests browser session cookies already saved on an already-infected machine and sells them on criminal marketplaces, letting a completely separate buyer import the session later. Either way, once the attacker holds the session, Entra ID has no way to distinguish them from the real user for as long as that token remains valid.\n\n" +
        "**2. Lookalike / cousin domain — MITRE ATT&CK T1656 (Impersonation).** No mailbox is ever compromised. The attacker registers a domain that's nearly identical to a real one — a single substituted character, an added hyphen, a different top-level domain — and sends a spoofed request that appears to come from a trusted sender, most often an executive. This is the cheapest and simplest BEC method: no phishing kit, no session theft, just a convincing domain and a well-timed message. It defeats casual visual inspection precisely because 'almost identical' reads as identical at a glance.\n\n" +
        "**3. Thread hijacking — MITRE ATT&CK T1534 (Internal Spearphishing).** Once an attacker holds a real, working mailbox (via ATO), the strongest move usually isn't sending a fresh email — it's replying inside an existing, already-trusted conversation. A reply that lands in a real thread inherits that thread's history, formatting, tone, and — critically — the recipient's existing trust in the conversation, which is a much higher bar for a cold email to clear. This room's investigation case is built around exactly this pattern.\n\n" +
        "**4. Vendor Email Compromise (VEC).** This is the vector most teams are least prepared for, because the compromised mailbox isn't inside their own tenant at all — it belongs to a third-party vendor or supplier. MITRE ATT&CK has no single technique dedicated to VEC specifically; the closest conceptual fit is T1199 (Trusted Relationship), which describes an attacker abusing a trusted third party's access, though that technique is usually applied to network access rather than email fraud. The attacker rides an already-trusted business relationship: a genuinely real invoice, sent from the vendor's genuinely real, compromised mail server, with genuinely valid SPF, DKIM, and DMARC records, because the message truly did originate from that vendor's own infrastructure. From the target organization's own logs, nothing looks wrong at all — there's no anomalous sign-in, no suspicious inbox rule, no spoofed domain, because none of your own systems were ever touched. This is exactly why verifying banking-detail changes through an independent, out-of-band channel is a non-negotiable control: no amount of log correlation on your own side can catch a compromise that happened entirely on someone else's.",
      checkpoint: {
        question: "Per Reading 2, why does a Vendor Email Compromise (VEC) email pass SPF, DKIM, and DMARC checks perfectly even though it's fraudulent?",
        options: [
          "Because VEC attackers always purchase a valid TLS certificate for a lookalike domain, which satisfies email authentication checks automatically",
          "Because the message genuinely was sent from the vendor's own real, compromised mail infrastructure — the target organization's own tenant was never touched, so there is nothing anomalous in the sender's own logs",
          "Because SPF, DKIM, and DMARC are cosmetic checks that all commercial mail providers disable by default for external senders",
          "Because VEC attacks are always sent internally, from within the target organization's own tenant, which automatically passes authentication",
        ],
        answer: 1,
        explanation:
          "VEC is specifically the case where the compromise happened on the vendor's side, not the target's. The email authenticates perfectly because it genuinely originated from the vendor's real, compromised systems — which is exactly why out-of-band verification, not log analysis, is the control that actually catches it.",
      },
    },
    // ── Question 1 (applied — distinguishing vectors) ───────────────────────
    {
      type: "question" as const,
      id: "bec-q1",
      question:
        "Your organization's own tenant shows zero indicators — no anomalous sign-in, no inbox rule creation, no forwarding, nothing unusual in your Unified Audit Log — yet your CFO receives a bank-detail-change instruction from the correct, genuine email address of a long-standing supplier, later confirmed fraudulent. Which BEC vector best explains this?",
      options: [
        "Account takeover (ATO) of an internal Meridian mailbox — the evidence simply wasn't logged correctly",
        "A lookalike domain impersonating the supplier, one character off from their real domain",
        "Thread hijacking within your own organization's mail system",
        "Vendor Email Compromise (VEC) — the supplier's own mailbox was compromised, so nothing in your tenant's telemetry was ever touched",
      ],
      answer: 3,
      explanation:
        "Reading 2 covered this exact case: when your own tenant genuinely shows no indicators at all, and the sending address is authentically correct, the compromise happened on the other side of the relationship. Dismissing this as an ATO logging gap or assuming a spoofed lookalike domain both miss the point — a lookalike domain would fail your own SPF/DKIM checks or at least show a different sending domain, which isn't what's described here.",
      xp: 20,
    },
    // ── Reading 3: reading Entra ID sign-in logs for ATO ────────────────────
    {
      type: "reading" as const,
      id: "bec-r3",
      heading: "Reading Entra ID Sign-In Logs for Account Takeover",
      content:
        "When ATO is the vector, the Entra ID sign-in log is where the first hard evidence usually shows up — but reading it correctly means understanding what several specific fields actually mean, not just skimming for a 'success' or 'failure' status.\n\n" +
        "**isInteractive tells you whether a human typed anything just now.** True means the sign-in involved a live user interaction — a password typed, a push approved. False means the token was presented and accepted without any fresh interaction at all, which is exactly what happens when a stolen session or refresh token is replayed through an API or a background client rather than a browser login form.\n\n" +
        "**incomingTokenType tells you what kind of credential was actually presented.** A value of none means ordinary fresh authentication. refreshToken means the sign-in was completed using a previously issued token rather than a fresh username/password-plus-MFA exchange — consistent with a stolen browser session being replayed, which is what AiTM phishing kits and infostealer cookie theft both produce. primaryRefreshToken (PRT) is a stronger and rarer signal still: it means the sign-in used a device-bound token tied to a specific Windows device's identity, which requires the attacker to hold device-level secrets, not just a browser cookie — a materially more invasive compromise than a stolen session alone.\n\n" +
        "**conditionalAccessStatus and riskLevelDuringSignIn are not verdicts — they're inputs an attacker can satisfy without knowing it.** A replayed session that already carries a valid MFA claim will frequently show conditionalAccessStatus: success and riskLevelDuringSignIn: none, because from the identity provider's perspective, a valid, MFA-satisfied token was presented — it has no way to know that token was stolen rather than freshly earned. Treating these fields as 'nothing to see here' is one of the most common ways real AiTM compromises get closed as false positives.\n\n" +
        "**deviceDetail tells you whether this is a device the organization has ever seen.** isCompliant and isManaged being false, and trustType being empty, together describe a sign-in from a device with no enrollment or management relationship to the organization at all — worth noting on its own, and far more significant when it doesn't match the account's known device history.\n\n" +
        "**correlationId and sessionId are what let you actually reconstruct the story.** correlationId ties together every audit record produced by one specific underlying action; sessionId, where present, ties together every event within one continuous authenticated session. Two sign-ins sharing an identifier, minutes apart, from two locations no real flight could connect, is impossible travel — literal geographic distance divided by elapsed time exceeding any plausible transportation speed. That math is a fact you can compute yourself; it doesn't require the platform's own risk engine to agree with you first.",
      checkpoint: {
        question: "Per Reading 3, what is the practical difference between incomingTokenType 'refreshToken' and 'primaryRefreshToken' (PRT)?",
        options: [
          "There is no real difference — both values mean exactly the same thing under a different label",
          "refreshToken means a fresh password-plus-MFA login just occurred; primaryRefreshToken means the sign-in failed",
          "refreshToken is consistent with a replayed stolen browser session; primaryRefreshToken means the attacker holds device-bound secrets tied to a specific Windows device — a materially more invasive compromise",
          "primaryRefreshToken only appears on failed sign-ins, so it can be safely ignored when reviewing successful authentications",
        ],
        answer: 2,
        explanation:
          "As Reading 3 covered, a refreshToken is consistent with ordinary stolen-session replay (AiTM, infostealer cookies). A primaryRefreshToken is device-bound and requires the attacker to hold device-level secrets, not just a browser cookie -- a stronger, rarer, and more serious signal.",
      },
    },
    // ── Log Analysis 1: the replayed sign-in ─────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "bec-la1",
      heading: "A Second Sign-In, Nine Minutes Later, From the Wrong Continent",
      context:
        "Meridian Structural Group's SIEM flagged an anomaly on p.nair@meridianstructural.com's account. Nine minutes before the record below, the Entra ID sign-in log shows an interactive sign-in on the same correlationId, MFA satisfied by a live Microsoft Authenticator approval, sourced from Meridian's only known corporate egress IP (198.51.100.22) in Denver, Colorado — where p.nair's team is based and where her laptop has generated every sign-in in the ten months since it was issued. No flight exists that covers Denver to Lagos, Nigeria in nine minutes. Review the record below.",
      event: becSigninReplayEvent,
      questions: [
        {
          question:
            "azure.signinlogs.properties.isInteractive is false, and authenticationDetails shows authenticationMethod 'Previously satisfied' with authenticationStepResultDetail 'MFA requirement satisfied by claim in the token.' What does this combination indicate?",
          options: [
            "A user typed their password and approved a fresh MFA push at this exact moment, which is what 'Previously satisfied' always means",
            "No fresh authentication occurred at all — a token that already carried a prior MFA claim was presented and accepted, consistent with a replayed stolen session rather than a live login",
            "The sign-in failed and no access was actually granted, regardless of the resultType field",
            "This combination only ever appears on service-account sign-ins and has no relevance to a human user's account",
          ],
          answer: 1,
          explanation:
            "Reading 3 covered exactly this pattern: isInteractive false plus 'Previously satisfied' means the session presented a token that already carried a valid MFA claim, with no fresh user interaction at all -- the signature of a replayed session, not a live login by the account owner.",
          xp: 30,
        },
        {
          question:
            "azure.signinlogs.properties.incomingTokenType reads 'refreshToken', the location is Lagos, Nigeria, and this record shares its correlationId with an interactive sign-in from Denver, Colorado nine minutes earlier — the only corporate egress on file for this account. What does this combination indicate?",
          options: [
            "Nothing unusual — refreshToken sign-ins are routine background renewals that happen automatically throughout a normal workday from the same location",
            "Impossible travel combined with token replay: no flight connects Denver to Lagos in nine minutes, and a refreshToken sign-in with no fresh authentication step is consistent with a stolen session being used from attacker infrastructure, not the account's actual owner",
            "The correlationId match is a coincidental value Entra ID reuses across unrelated sign-ins and carries no investigative meaning",
            "This confirms p.nair is travelling internationally for work and the Denver sign-in earlier that day was the anomaly instead",
          ],
          answer: 1,
          explanation:
            "As Reading 3 taught, matching correlationId across two geographically incompatible sign-ins is exactly how impossible travel is confirmed with certainty -- the math (distance versus elapsed time) doesn't depend on Entra ID's own risk score agreeing with you. A refreshToken sign-in with no live authentication step, from a location the account has never used, is the token-replay pattern this room is built around.",
          xp: 30,
        },
        {
          question:
            "azure.signinlogs.properties.conditionalAccessStatus reads 'success' and riskLevelDuringSignIn reads 'none' on this record. Based on Reading 3, should an analyst treat these 'clean' fields as evidence this sign-in is safe to close?",
          options: [
            "Yes — Conditional Access and the risk engine are Microsoft's own security controls, and if they show success and no risk, no further review is needed",
            "No — a replayed token that already carries a valid MFA claim satisfies Conditional Access and often produces no risk score, because the identity provider has no way to know the token was stolen rather than freshly earned; the impossible-travel and device-mismatch facts are what actually matter here",
            "Yes, but only because this is a non-interactive sign-in — interactive sign-ins with the same field values would need escalation",
            "No, but only because the source IP is in Nigeria — the same clean fields would be perfectly trustworthy from any other country",
          ],
          answer: 1,
          explanation:
            "Reading 3 was explicit about this exact trap: a stolen, already-MFA-satisfied token routinely produces green Conditional Access and risk fields, because the identity provider is validating a legitimately-issued token, not verifying who is actually holding it. The impossible-travel math and the unfamiliar, non-compliant device are what an analyst has to weigh instead of the risk score alone.",
          xp: 35,
        },
      ],
    },
    // ── Question 2 (applied — don't trust green fields alone) ───────────────
    {
      type: "question" as const,
      id: "bec-q2",
      question:
        "A colleague argues that because conditionalAccessStatus reads 'success' and riskLevelDuringSignIn reads 'none' on the sign-in from the log analysis exercise, it should be closed as routine. What is the strongest counter-argument, based on this room?",
      options: [
        "Those fields are frequently unreliable software bugs in Entra ID and should be ignored on every sign-in record, not just this one",
        "A replayed, already-MFA-satisfied token routinely produces exactly those 'clean' values, because the identity provider is validating a legitimate token, not verifying who currently holds it — the impossible travel and device mismatch are the facts that actually matter",
        "Conditional Access and risk scoring only apply to interactive sign-ins, so they are meaningless on this non-interactive record regardless of the underlying facts",
        "The colleague is right, and no further action should be taken on this specific sign-in",
      ],
      answer: 1,
      explanation:
        "This is the exact trap Reading 3 and the log analysis exercise built toward: token-replay sign-ins frequently show green Conditional Access and risk fields precisely because the token itself is valid and already carries a satisfied MFA claim -- the identity provider has no way to distinguish the legitimate owner presenting it from someone who stole it.",
      xp: 25,
    },
    // ── Reading 4: inbox rules built for wire fraud ─────────────────────────
    {
      type: "reading" as const,
      id: "bec-r4",
      heading: "How Attackers Hide the Evidence: Inbox Rules Built for Wire Fraud",
      content:
        "Once an attacker holds a live session, the next move in almost every real BEC case is the same one covered in the remote-email-collection room: a New-InboxRule (or Set-Mailbox -ForwardingSmtpAddress) operation that keeps working long after the session ends. What matters for wire fraud specifically is which concealment shape the rule takes, because the goal here isn't just exfiltrating a copy of mail — it's making sure the one reply that would blow up the fraud never reaches the person who'd recognize it.\n\n" +
        "**The ForwardTo/RedirectTo/DeleteMessage pattern you already know sends mail out.** That pattern, covered in depth in remote-email-collection, is built for reading correspondence remotely or exfiltrating it to an attacker-controlled address.\n\n" +
        "**A quieter pattern exists for exactly this scenario: suppression without forwarding.** A rule using MoveToFolder combined with MarkAsRead moves matching messages into an ordinary, rarely-checked folder — often a default Outlook folder like RSS Feeds, which most users have never opened once — and marks them as already read, so no unread-count badge ever draws attention to them. Paired with StopProcessingRules:true, no other rule (including one a security team might add later) ever gets a chance to evaluate that message either. Nothing leaves the mailbox and nothing is deleted; the message simply becomes invisible to the one person who'd know to be suspicious of it.\n\n" +
        "**Why this specific shape matters for wire fraud.** If the attacker is about to reply inside a real vendor thread with fraudulent bank details (the pattern this room's investigation case follows), the single biggest risk to the fraud isn't the target org noticing the fraudulent message — it's the real vendor eventually writing back to ask why payment hasn't arrived, or worse, warning that their bank details were never actually changed. A forwarding rule alone does nothing to stop that reply from landing in front of the mailbox owner. A MoveToFolder rule scoped to the vendor's real domain and financially relevant keywords does exactly that.\n\n" +
        "**Timing correlation is still the strongest evidence, regardless of which shape the rule takes.** A New-InboxRule record sharing a ClientIP with an unfamiliar sign-in minutes earlier — the same correlation this room's own log-analysis case demonstrates — is far more significant than either fact reviewed in isolation, exactly as Reading 3 established for the sign-in itself.",
      diagram:
        "flowchart LR\n" +
        "  A[AiTM phishing captures\\np.nair's session] --> B[Non-interactive replay\\nsign-in from Lagos]\n" +
        "  B -->|same IP, minutes later| C[New-InboxRule:\\nMoveToFolder + StopProcessingRules]\n" +
        "  C --> D[Attacker replies inside\\nreal Cascade Fabrication thread]\n" +
        "  D --> E[CFO approves fraudulent\\nbank-detail change]\n" +
        "  C -.suppresses.-> F[Real vendor's reply\\nnever seen]\n",
      diagramCaption: "How the inbox rule enables the fraud, not just conceals it",
      checkpoint: {
        question: "Per Reading 4, what does a MoveToFolder + MarkAsRead + StopProcessingRules combination achieve that a ForwardTo/DeleteMessage pattern does not, in a wire-fraud scenario specifically?",
        options: [
          "It sends a copy of the matching mail to an external address the ForwardTo pattern would have missed",
          "It suppresses the mailbox owner's ability to ever see specific incoming replies — such as the real vendor questioning a bank-detail change — without any mail ever leaving the mailbox or being deleted",
          "It permanently disables the mailbox owner's account, preventing them from logging in at all",
          "It has no functional difference from ForwardTo/DeleteMessage; both patterns behave identically",
        ],
        answer: 1,
        explanation:
          "Reading 4's core point: this pattern doesn't exfiltrate anything -- it hides specific incoming replies from the mailbox owner by burying them, unread-badge and all, in a folder nobody checks. For a wire-fraud scenario, that's exactly the reply (the real vendor asking about a missing or disputed payment) the attacker most needs suppressed.",
      },
    },
    // ── Log Analysis 2: the concealment inbox rule ──────────────────────────
    {
      type: "log_analysis" as const,
      id: "bec-la2",
      heading: "The Rule That Hides the Real Vendor's Reply",
      context:
        "Continuing the same investigation: nine minutes after the non-interactive sign-in from Lagos reviewed in the previous exercise, this New-InboxRule record appears on p.nair's mailbox. No ticket, change record, or leave-coverage request exists for this account around this date. Meridian's only active supplier matching the scoped keyword 'cascadefab.com' is Cascade Fabrication Ltd, a long-standing vendor with an open invoice in the accounts-payable queue at the time this rule was created. Review the record below.",
      event: becInboxRuleEvent,
      questions: [
        {
          question:
            "data.office365.Parameters shows MoveToFolder = 'RSS Feeds', MarkAsRead = 'True', and StopProcessingRules = 'True', scoped to SubjectOrBodyContainsWords including 'cascadefab.com' and 'wire'. What is the combined effect of these specific parameters?",
          options: [
            "The rule forwards a copy of matching mail to an external address while leaving the original untouched, exactly like the ForwardTo pattern covered in remote-email-collection",
            "Matching messages are moved into a folder almost nobody checks, marked as already read so no unread badge draws attention, and no later rule ever gets a chance to evaluate them — none of this sends mail anywhere or deletes it, it simply hides specific incoming replies from the mailbox owner",
            "The rule permanently deletes any message matching the scoped keywords the instant it arrives, with no trace left anywhere",
            "RSS Feeds is a technical Exchange system folder that automatically flags its contents for security review, making this configuration self-defeating for an attacker",
          ],
          answer: 1,
          explanation:
            "As Reading 4 covered, this is the suppression-without-forwarding pattern: nothing leaves the mailbox and nothing is deleted, but the mailbox owner will never see anything moved into RSS Feeds unless they specifically go looking -- and MarkAsRead removes even the unread-count signal that might otherwise catch their eye.",
          xp: 30,
        },
        {
          question:
            "data.office365.ClientIP on this rule (154.72.18.63) matches the source IP of the non-interactive sign-in reviewed nine minutes earlier in the previous exercise. What does this specific correlation establish?",
          options: [
            "Nothing meaningful -- ClientIP values are assigned randomly by Exchange Online and carry no relationship to the sign-in that preceded them",
            "That the same session which replayed the stolen token also created this rule, minutes later -- tying the sign-in anomaly and the concealment rule into one continuous, purposeful sequence of actions rather than two unrelated events",
            "That p.nair personally travelled to Lagos and created this rule herself using a hotel business center's shared IP address",
            "That this rule was created by Meridian's own IT department as part of a scheduled maintenance window",
          ],
          answer: 1,
          explanation:
            "This is the same timing-and-IP correlation Reading 4 called the strongest evidence available, regardless of which concealment shape the rule takes: one IP, one narrow time window, two distinct but connected actions -- exactly the pattern that turns an isolated sign-in anomaly and an isolated rule creation into one confirmed, continuous compromise.",
          xp: 30,
        },
        {
          question:
            "Unlike the ForwardTo/DeleteMessage pattern from remote-email-collection, this rule never sends any mail outside Meridian's tenant and never deletes anything. Based on Reading 4, why is it still dangerous enough to justify the same urgency?",
          options: [
            "It isn't actually dangerous -- since nothing leaves the tenant or gets deleted, this rule should be treated as a low-priority finding",
            "It specifically suppresses the real vendor's own replies from ever reaching the mailbox owner -- which, in a wire-fraud scenario, is precisely the message (a dispute or a 'we never changed our bank details' correction) that would otherwise stop the fraud before money moves",
            "It is dangerous only because MoveToFolder rules are always flagged automatically by Exchange Online's built-in anti-phishing engine, creating unnecessary alert volume",
            "It is dangerous because RSS Feeds folders are synced to every other mailbox in the organization by default, spreading the rule's effect tenant-wide",
          ],
          answer: 1,
          explanation:
            "Reading 4's central point: for a wire-fraud scenario specifically, the single most dangerous incoming message is the real vendor's own correcting reply. A rule that quietly buries exactly that reply, with no unread badge and no trace of forwarding to investigate, is arguably more purpose-built for this fraud than a ForwardTo rule would be -- even though nothing ever technically leaves the tenant.",
          xp: 35,
        },
      ],
    },
    // ── Matching: vectors and fields ─────────────────────────────────────────
    {
      type: "matching" as const,
      id: "bec-m1",
      heading: "Match the BEC Vector or Field to What It Actually Means",
      instructions: "Match each term to what it indicates in a real investigation.",
      pairs: [
        { id: "ato", left: "Account Takeover (ATO)", right: "Attacker obtains a real, working session or valid credentials for the target's own mailbox — via AiTM phishing or stolen infostealer session cookies — and operates the account directly" },
        { id: "lookalike", left: "Lookalike / cousin domain", right: "A newly registered domain nearly identical to a real one, used to spoof a trusted sender without ever compromising any real mailbox" },
        { id: "hijack", left: "Thread hijacking", right: "Replying inside a real, already-trusted email conversation from a genuinely compromised mailbox, inheriting that thread's credibility instead of sending a cold new email" },
        { id: "vec", left: "Vendor Email Compromise (VEC)", right: "The compromised mailbox belongs to a third-party vendor, not the target organization — the fraudulent email authenticates perfectly because it truly originated from the vendor's own compromised systems" },
        { id: "refresh", left: "incomingTokenType: refreshToken", right: "Sign-in authenticated using a previously issued token rather than a fresh password-plus-MFA challenge — consistent with a replayed, stolen browser session" },
        { id: "prt", left: "incomingTokenType: primaryRefreshToken", right: "Sign-in authenticated using a device-bound Primary Refresh Token — indicates the attacker holds device-level secrets, a stronger and rarer compromise signal than a stolen browser session" },
        { id: "greenfields", left: "conditionalAccessStatus: success + riskLevelDuringSignIn: none", right: "Both fields can look 'clean' on a genuinely malicious, replayed sign-in — neither reliably catches token replay, so they should never close an investigation by themselves" },
      ],
      explanation:
        "Notice that the four vectors point to completely different places to look for evidence — ATO and thread hijacking live in your own tenant's identity and mail-audit logs, a lookalike domain lives in the message headers of a single email, and VEC lives nowhere in your own telemetry at all. Confusing which vector you're facing wastes time looking for evidence that was never going to exist in that location.",
      xp: 30,
    },
    // ── Analyst Choice: legitimate internal forwarding rule ─────────────────
    {
      type: "analyst_choice" as const,
      id: "bec-ac1",
      heading: "Verdict: An Employee's Leave-Coverage Forwarding Rule",
      scenario:
        "After two tasks built around a malicious New-InboxRule operation, a routine alert fires on a third: t.reyes@meridianstructural.com's mailbox now has a New-InboxRule record forwarding mail to a.walsh@meridianstructural.com. Review the record and its surrounding facts before deciding how to handle it.",
      event: becLegitimateForwardEvent,
      correct_verdict: "false_positive",
      explanation:
        "The forwarding destination (a.walsh@meridianstructural.com) is an internal, same-tenant colleague, not an external or lookalike address. data.office365.ClientIP (198.51.100.22) matches Meridian's known corporate egress. The rule uses ForwardTo, which leaves a copy in t.reyes's own mailbox, rather than RedirectTo or the MoveToFolder/StopProcessingRules suppression pattern from this room's log analysis exercise, and StopProcessingRules is explicitly False. it_verify_result confirms Helpdesk ticket HD-30410 authorizing exactly this leave-coverage arrangement.",
      fp_trap:
        "After two tasks centered on a malicious New-InboxRule operation, seeing the same operation name a third time reads as an obvious escalation on reflex. But the destination is internal, the copy is preserved rather than hidden or redirected, the source IP matches the known corporate baseline, and a ticket independently confirms the business reason — none of the correlating facts this room has built up (unfamiliar sign-in, IP mismatch, suppression-shaped parameters, no ticket) are present here. Escalating every ForwardTo rule regardless of destination and context trains a SOC to drown in noise on the exact operation this room has spent several tasks teaching you to take seriously when it actually matters.",
      xp: 30,
    },
    // ── Reading 5: investigating wire fraud, racing the clock ──────────────
    {
      type: "reading" as const,
      id: "bec-r5",
      heading: "Investigating Wire Transfer Fraud: Building the Timeline and Racing the Clock",
      content:
        "Once ATO and a concealment rule are confirmed, a BEC investigation with a financial-fraud outcome becomes two parallel problems at once: understanding exactly what happened (the technical investigation) and trying to get the money back (a race against time that has nothing to do with logs).\n\n" +
        "**Build the timeline from what you already have.** Every piece this room has covered stitches together into one story: the AiTM capture (or infostealer sale) that stole the session, the replayed sign-in with its correlationId and unfamiliar geography, the concealment rule created minutes later from the same IP, the fraudulent reply sent inside a real, trusted thread, and finally the approval and the wire itself. Reconstructing this in order — with exact timestamps — is what turns a pile of separate log records into a single, defensible account of what happened and when.\n\n" +
        "**Out-of-band verification is the one control logs can't substitute for.** Any request to change banking details, no matter how legitimate it looks or how well it fits an active thread, should be confirmed by calling the requester or the vendor at a phone number pulled from a previously verified source — a signed contract, an existing internal directory, a number dialed before, never a number found in the suspect email itself. This single habit defeats every one of the four vectors from Reading 2 simultaneously, including VEC, where no technical control on your side would ever catch it.\n\n" +
        "**The 'golden hours' for financial recovery are short, and they start the moment funds leave, not the moment fraud is discovered.** Once a fraudulent wire or ACH transfer executes, most banks can only attempt a recall or reversal within a narrow window — often measured in hours to a few days, shrinking sharply the moment the receiving funds move on to a second account. A case caught within hours of the transfer has a real chance at recovery. A case discovered weeks later, after a vendor's own missed-payment complaint finally surfaces the fraud — which is exactly how this room's own case comes to light — usually does not, no matter how thorough the eventual investigation is.\n\n" +
        "**Reporting bodies matter, and not just for the record.** Filing promptly with the FBI's Internet Crime Complaint Center (IC3), or the equivalent national cyber-fraud reporting body outside the US, isn't only a paperwork step — receiving banks and law enforcement sometimes coordinate an intercept using exactly that report, and banks frequently ask for a report reference number before they'll escalate a recall request internally.",
      checkpoint: {
        question: "Per Reading 5, why does a case discovered weeks after the fraudulent wire executes usually have a much lower chance of financial recovery than one caught within hours?",
        options: [
          "Because banks are legally prohibited from attempting any recall after 24 hours have passed, with no exceptions",
          "Because the 'golden hours' for a bank recall or reversal start the moment funds leave and shrink sharply once the money moves on to a second account — the clock runs from the transfer, not from when the fraud is discovered",
          "Because IC3 complaints filed more than a week after a wire transfer are automatically rejected and never reach the receiving bank",
          "Because fraudulent wire transfers become permanently untraceable exactly seven days after execution, regardless of any other factor",
        ],
        answer: 1,
        explanation:
          "Reading 5 was explicit: the recovery window is tied to when the funds actually moved, not to when anyone noticed. The longer that gap, the more likely funds have already moved on past the point any recall request can reach them -- which is exactly what happens in this room's own case, discovered weeks later via the vendor's missed-payment complaint.",
      },
    },
    // ── Ordering: chronological kill-chain reconstruction ───────────────────
    {
      type: "ordering" as const,
      id: "bec-o1",
      heading: "Reconstruct the Timeline: What Actually Happened, In Order",
      instructions: "Arrange these events from this investigation in the order they actually occurred, earliest to latest.",
      items: [
        { id: "capture", text: "An AiTM phishing page mimicking a document-sharing notification captures p.nair's authenticated session, including a token that already carries a satisfied MFA claim" },
        { id: "replay", text: "A non-interactive sign-in replays the stolen session from Lagos, nine minutes after p.nair's own legitimate interactive sign-in from Denver" },
        { id: "rule", text: "A New-InboxRule operation moves any message mentioning Cascade Fabrication or wire-related keywords into a rarely-checked folder and marks it read" },
        { id: "hijack", text: "Using p.nair's own, genuinely compromised mailbox, a reply is sent inside the real, ongoing Cascade Fabrication invoice thread with 'updated' bank details" },
        { id: "approve", text: "David Okonkwo (CFO), seeing a reply inside a thread he already trusted, approves the payment and Accounts Payable executes the wire" },
        { id: "diverted", text: "Cascade Fabrication's real accounts team emails asking why payment hasn't arrived — a message the inbox rule quietly diverts and nobody sees for over a week" },
        { id: "confirmed", text: "A follow-up phone call to Cascade Fabrication, prompted after the missed-payment complaint finally surfaces through another channel, confirms their bank details were never actually changed" },
      ],
      correct_order: ["capture", "replay", "rule", "hijack", "approve", "diverted", "confirmed"],
      explanation:
        "This is the same story told by every field this room examined, laid end to end: session theft comes before the session can be replayed; the replay comes before the concealment rule that protects it; the concealment rule has to exist before the fraudulent reply is safe to send; the reply has to arrive before it can be approved; and the real vendor's genuine correction — the one fact that would have stopped everything — only surfaces after being quietly suppressed for over a week, which is exactly why this case wasn't caught inside Reading 5's 'golden hours.'",
      xp: 35,
    },
    // ── Question 3 (applied — scoping beyond one confirmed mailbox) ─────────
    {
      type: "question" as const,
      id: "bec-q3",
      question:
        "The SOC confirms p.nair's account was compromised, revokes her sessions, resets her credentials, and removes the concealment rule. Should this investigation now be considered closed?",
      options: [
        "Yes — once the confirmed mailbox is contained and the rule is removed, the incident is fully resolved",
        "No — the same source IP, correlationId pattern, or concealment-rule shape should be hunted across other mailboxes, since real BEC campaigns frequently touch several accounts (especially other finance-adjacent staff) before an attacker chooses which one to weaponize",
        "No, but only because Cascade Fabrication's own mailbox must also be reset by Meridian's IT team, since VEC is always involved alongside ATO",
        "Yes, provided David Okonkwo personally confirms he will scrutinize future wire requests more carefully going forward",
      ],
      answer: 1,
      explanation:
        "One confirmed compromised mailbox almost never tells the full story of how widely an attacker probed before settling on p.nair specifically. Scoping — hunting the same IP, session pattern, or rule shape against other finance-adjacent accounts — is standard practice precisely because real campaigns rarely stop at the first mailbox they access. Resetting a vendor's own mailbox isn't Meridian's action to take in this case, since this scenario was ATO and thread hijacking, not VEC.",
      xp: 25,
    },
    // ── Reading 6: the full analyst response ─────────────────────────────────
    {
      type: "reading" as const,
      id: "bec-r6",
      heading: "The Analyst's Full Response: Containment, Scoping, Notification, and the Summary",
      content:
        "A confirmed BEC case with a financial-fraud outcome demands a response broader than 'the account is contained now.' Four categories of work run largely in parallel, not strictly one after another.\n\n" +
        "**Technical containment.** Revoke every active session and refresh token for the compromised account immediately — a password reset alone does not invalidate a token already issued. Force a password reset and require re-registration of MFA methods through a verified, out-of-band channel. Remove the concealment rule (or the mailbox-level ForwardingSmtpAddress, if that mechanism was used instead) so nothing further leaves silently. If any new authentication method was registered during the compromise window — MITRE ATT&CK T1098.005 (Account Manipulation: Device Registration), the exact scenario the device-registration-persistence room covers in depth — it must be explicitly found and removed; a password reset alone will not touch it.\n\n" +
        "**Scoping.** Search for the same source IP, ASN, correlationId pattern, or concealment-rule shape across every mailbox in the organization, not just the confirmed one — with particular attention to other finance-adjacent accounts (accounts payable, payroll, executive assistants). Real BEC operators frequently probe several accounts before settling on the one that gives them the most useful position.\n\n" +
        "**Financial and external notification.** As Reading 5 covered, the bank's fraud/recall team and an IC3 (or equivalent) report belong on the clock the moment fraud is confirmed, not after the technical investigation wraps up. The real vendor — Cascade Fabrication, in this case — needs a verified, out-of-band notification too, since their own accounts team was corresponding with an attacker impersonating a trusted contact for over a week without knowing it. Depending on what data was exposed, legal/privacy, executive leadership, and possibly regulators or the organization's cyber insurance carrier may also need to be looped in.\n\n" +
        "**The written summary.** A strong incident summary needs an exact timeline with real timestamps (Reading 5's reconstruction exercise is exactly this skill), the specific indicators found (source IPs, correlationId/sessionId values, the exact rule parameters), the dollar exposure, which actions have already been taken versus which remain pending, and — critically — the root cause: how the session was actually stolen in the first place. Fixing that specific gap (AiTM-resistant authentication, infostealer detection, user training on the specific lure used) is what actually prevents a repeat, and a summary that stops at 'we reset the password' leaves that question unanswered.",
      checkpoint: {
        question: "Per Reading 6, why does scoping deliberately extend beyond the one mailbox already confirmed compromised?",
        options: [
          "Because Meridian's compliance policy requires resetting every employee's password on a fixed quarterly schedule regardless of any incident",
          "Because real BEC operators frequently probe several accounts — especially other finance-adjacent ones — before settling on the one they actually weaponize, so the confirmed mailbox may not be the only one touched",
          "Because scoping is only required when the compromised account belongs to a member of the executive team, which p.nair is not",
          "Because Entra ID automatically locks every account in the tenant the moment any single account is confirmed compromised, making scoping unnecessary in practice",
        ],
        answer: 1,
        explanation:
          "Reading 6's point directly: the confirmed mailbox is rarely the full extent of a real campaign's reconnaissance. Hunting the same IP, session, or rule pattern against other finance-adjacent accounts is standard practice specifically because attackers often probe multiple accounts before choosing the one to actually act through.",
      },
    },
    // ── Question 4 (applied — parallel financial and technical response) ────
    {
      type: "question" as const,
      id: "bec-q4",
      question:
        "Investigators confirm the fraudulent wire was sent roughly six hours ago. Technical containment (session revocation, password reset, rule removal) is underway. Based on Reading 5 and Reading 6, what should happen to the bank-recall notification while that technical work continues?",
      options: [
        "It should wait until the full technical investigation and incident report are complete, so the bank receives one consolidated, final account of what happened",
        "It should be initiated immediately, in parallel with technical containment — the bank's recall window is measured in hours from the moment funds moved, not from when the technical investigation finishes",
        "It isn't necessary at all once the compromised account itself has been contained, since containment prevents any further financial loss",
        "It should be delayed until the vendor (Cascade Fabrication) is formally notified first, since their confirmation is a prerequisite for any bank recall request",
      ],
      answer: 1,
      explanation:
        "Reading 5 was explicit that the recall window is tied to elapsed time since the transfer, not to the technical investigation's progress -- at six hours out, delaying the bank call to finish IR steps first can be the difference between a real chance at recovery and none. Reading 6 frames financial and technical response as running in parallel, not strictly sequentially, for exactly this reason.",
      xp: 25,
    },
    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "bec-f1",
      prompt:
        "Look at the Log Analysis finding on the New-InboxRule operation (the rule concealing Cascade Fabrication's replies). What is the exact value of the data.office365.ClientIP field in the raw log?",
      answer: "154.72.18.63",
      hint: "Look inside the raw block of the inbox-rule log analysis event for the field named data.office365.ClientIP.",
      xp: 20,
    },
  ],
};

export const roomsBatch34 = [becInvestigationRoom];
