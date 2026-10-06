/**
 * Learning Rooms — Batch 38
 *
 * Closes an F-09 external-audit gap: the platform's Google Workspace
 * scenarios (gws-phishing-attachment, gws-oauth-marketplace) require reading
 * gws.* audit fields, but the platform only ever taught Microsoft 365 /
 * Exchange Online / SharePoint in depth. This room teaches the Google
 * Workspace audit-log model on its own terms and explicitly contrasts it
 * against the Microsoft 365 suite this platform already teaches.
 *
 * Rooms in this batch:
 *  1. google-workspace-security
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Google Workspace Security
// ===========================================================================

const oauthConsentEvent: TelemetryEvent = {
  id: "evt-gwsf-la1-001",
  ts: "2026-06-08T14:02:17.000Z",
  source: "gws",
  vendor: "Google Workspace",
  event_type: "account_modify",
  severity: "high",
  mitre_technique: "T1528",
  mitre_tactic: "Credential Access",
  user_email: "k.stensrud@medcorehealth.org",
  user_title: "Clinical Operations Manager",
  src_ip: "35.190.22.61",
  geo: { country: "United States", city: "Chicago" },
  description:
    "A token audit 'authorize' event recorded k.stensrud@medcorehealth.org granting a third-party app named FormFlow Sync the scopes for full Calendar and full Drive access, with an offline refresh token issued.",
  raw: {
    "gws.event.type": "token",
    "gws.event.name": "authorize",
    "gws.actor.email": "k.stensrud@medcorehealth.org",
    "gws.token.client_id": "719402883561-q8m3k7n2p9r4t6u1v0w5x8y3z2a7b6c1.apps.googleusercontent.com",
    "gws.token.app_name": "FormFlow Sync",
    "gws.token.client_type": "WEB",
    "gws.token.scope": [
      "https://www.googleapis.com/auth/calendar",
      "https://www.googleapis.com/auth/drive",
      "openid",
      "https://www.googleapis.com/auth/userinfo.email",
    ],
    "gws.token.api_name": ["calendar", "drive"],
    "gws.token.access_type": "offline",
    "gws.app.allowlist_status": "NOT_CONFIGURED",
    "gws.app.marketplace_verified": "false",
    "gws.app.publisher": "unverified",
    "gws.app.redirect_uri": "https://formflow-sync.app/oauth2/callback",
    "source.ip": "35.190.22.61",
    "source.geo.country_name": "United States",
    "source.geo.city_name": "Chicago",
    "application.name": "FormFlow Sync",
    "application.id": "719402883561-q8m3k7n2p9r4t6u1v0w5x8y3z2a7b6c1.apps.googleusercontent.com",
    "application.type": "oauth2_web",
    "event.action": "authorize",
    "event.outcome": "success",
    "user.email": "k.stensrud@medcorehealth.org",
  },
};

const driveDownloadBurstEvent: TelemetryEvent = {
  id: "evt-gwsf-la2-001",
  ts: "2026-06-08T14:19:04.000Z",
  source: "gws",
  vendor: "Google Workspace",
  event_type: "cloud_storage_access",
  severity: "high",
  mitre_technique: "T1530",
  mitre_tactic: "Collection",
  user_email: "k.stensrud@medcorehealth.org",
  src_ip: "146.148.92.14",
  geo: { country: "Netherlands", city: "Amsterdam" },
  file: {
    name: "Patient_Intake_Q2.xlsx",
    path: "/Drive/Clinical/Q2/Patient_Intake_Q2.xlsx",
    extension: "xlsx",
    size: 5_812_224,
  },
  description:
    "The Drive audit recorded 340 download operations under k.stensrud's account within eleven minutes, attributed to the FormFlow Sync token, from a hosting-provider IP in the Netherlands.",
  raw: {
    "gws.event.type": "access",
    "gws.event.name": "download",
    "gws.actor.email": "k.stensrud@medcorehealth.org",
    "gws.token.client_id": "719402883561-q8m3k7n2p9r4t6u1v0w5x8y3z2a7b6c1.apps.googleusercontent.com",
    "gws.token.app_name": "FormFlow Sync",
    "gws.drive.doc_title": "Patient_Intake_Q2.xlsx",
    "gws.drive.doc_id": "1Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0",
    "gws.drive.doc_type": "spreadsheet",
    "gws.drive.owner": "k.stensrud@medcorehealth.org",
    "gws.drive.visibility": "private",
    "gws.access.download_count_window": "340",
    "gws.access.via_oauth_app": "FormFlow Sync",
    "file.name": "Patient_Intake_Q2.xlsx",
    "file.path": "/Drive/Clinical/Q2/Patient_Intake_Q2.xlsx",
    "file.size": "5812224",
    "source.ip": "146.148.92.14",
    "source.geo.country_name": "Netherlands",
    "source.geo.city_name": "Amsterdam",
    "application.name": "FormFlow Sync",
    "event.action": "download",
    "event.outcome": "success",
    "user.email": "k.stensrud@medcorehealth.org",
  },
};

const benignAllowlistedGrantEvent: TelemetryEvent = {
  id: "evt-gwsf-ac1-001",
  ts: "2026-06-06T09:40:00.000Z",
  source: "gws",
  vendor: "Google Workspace",
  event_type: "account_modify",
  severity: "informational",
  user_email: "p.duval@medcorehealth.org",
  user_title: "Executive Assistant",
  src_ip: "35.190.22.4",
  geo: { country: "United States", city: "Chicago" },
  expected_verdict: "fp",
  fp_explanation:
    "p.duval authorized Grammarly, an admin-allowlisted, marketplace-verified app, requesting only a narrow document-content scope for its writing-assistance feature -- a routine, sanctioned OAuth grant. It does receive an offline refresh token, but a refresh token limited to drive.file on a vetted app is a small, sanctioned footprint. The act of granting an app is identical in shape to the FormFlow Sync incident; the discriminators are scope breadth, allowlist status, and publisher verification, not the act of consenting itself.",
  description:
    "A token audit 'authorize' event recorded p.duval@medcorehealth.org granting the app Grammarly one Drive scope, with an offline refresh token issued.",
  raw: {
    "gws.event.type": "token",
    "gws.event.name": "authorize",
    "gws.actor.email": "p.duval@medcorehealth.org",
    "gws.token.client_id": "441029581763-h5j2k9l1m3n7o4p6q8r0s2t5u1v9w3x7.apps.googleusercontent.com",
    "gws.token.app_name": "Grammarly",
    "gws.token.client_type": "WEB",
    "gws.token.scope": ["https://www.googleapis.com/auth/drive.file"],
    "gws.token.api_name": "drive",
    "gws.token.access_type": "offline",
    "gws.app.allowlist_status": "TRUSTED",
    "gws.app.marketplace_verified": "true",
    "gws.app.publisher": "Grammarly Inc.",
    "source.ip": "35.190.22.4",
    "source.geo.country_name": "United States",
    "source.geo.city_name": "Chicago",
    "application.name": "Grammarly",
    "application.type": "oauth2_web",
    "event.action": "authorize",
    "event.outcome": "success",
    "user.email": "p.duval@medcorehealth.org",
  },
};

const googleWorkspaceSecurityRoom = {
  id: "google-workspace-security",
  title: "Google Workspace Security",
  description:
    "The Google Workspace counterpart to this platform's Microsoft 365, Exchange Online, and SharePoint rooms: the gws.event.type/event.name audit model, Gmail's SPF/DKIM/DMARC fields, the OAuth token audit (scopes, offline vs online access, allowlist and marketplace-verification status), the Drive sharing and download audit, the admin console audit log, and Alert Center. Includes a direct contrast against Microsoft 365 so an analyst who only knows Exchange Online and SharePoint doesn't misread a Google Workspace tenant.",
  difficulty: "intermediate" as const,
  category: "Cloud Security",
  estimatedMinutes: 60,
  xp: 385,
  icon: "📨",
  prerequisites: ["email-security", "microsoft-365-security"],
  tasks: [
    // ── Reading 1: intro ─────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "gwsf-r1",
      heading: "Google Workspace in the SOC: Gmail, Drive, and the Admin Console",
      content:
        "This platform already teaches Microsoft 365 in depth — Exchange Online for mail, SharePoint and Teams for files and collaboration, Entra ID for identity. Google Workspace is Google's own answer to the same overall bundle of needs, and it is the productivity suite of choice for a large share of organisations that are not built primarily on Microsoft's stack: startups, education, healthcare systems, and many mid-market companies worldwide.\n\n" +
        "**The mental model.** Google Workspace bundles Gmail (mail), Drive (file storage and sharing), Calendar, Meet (video conferencing), and a handful of other apps under one subscription, all governed centrally through the Admin console — a single place where an administrator manages users, groups, security policy, and third-party app access for the whole organisation (called, in Google's own terminology, the domain or the workspace). Every one of those apps writes its own dedicated audit trail, and this room's central job is teaching an analyst to read those trails on their own terms.\n\n" +
        "**Why an analyst who knows Microsoft 365 still needs this room.** The concepts genuinely rhyme — mail security, file-sharing risk, OAuth consent abuse, and admin-console governance are universal SOC concerns regardless of vendor. But the field names, the event structure, and a handful of real behavioural differences do not carry over automatically. An analyst who assumes Google Workspace logs look like Exchange Online's Unified Audit Log, just with different field names sprinkled on top, will misread real evidence — this room exists specifically to prevent that.\n\n" +
        "**What this room does and does not cover.** Email-security fundamentals — what phishing looks like, what SPF/DKIM/DMARC exist to prove, how to read a suspicious message — are already taught in this platform's Email Security room, and those concepts transfer directly. What's new here is Google's own audit-log vocabulary for expressing them, the specific structure of Google's OAuth consent audit (a genuinely different and more consequential attack surface than most analysts expect), and where Google Workspace's own concepts map onto — and diverge from — the Microsoft 365 ecosystem this platform already teaches in depth.",
      checkpoint: {
        question: "An analyst who knows Microsoft 365 well is handed a Google Workspace tenant. Which part of their knowledge carries over directly?",
        options: [
          "The field names, since Workspace reuses the Unified Audit Log schema",
          "The judgement about what makes mail, sharing, OAuth or admin activity risky",
          "The event structure, since every Workspace app writes into one shared log",
          "Very little, because cloud-suite security concepts are vendor-specific",
        ],
        answer: 1,
        explanation:
          "The concepts rhyme; the schemas don't. Mail security, sharing risk, OAuth abuse and admin governance are the same SOC concerns on either suite, so that judgement transfers. The field names do not — Workspace has its own vocabulary — and neither does the structure: each Workspace app writes its own audit trail rather than one shared log. Saying very little transfers throws away exactly the judgement that does carry over.",
      },
    },
    // ── Reading 2: audit log model ─────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "gwsf-r2",
      heading: "The GWS Audit Log Model: gws.event.type and gws.event.name",
      content:
        "Google Workspace's audit activity is organised around two fields working together, and understanding the pairing is the foundation for reading everything else in this room.\n\n" +
        "**gws.event.type: the log category.** This field names which audit log an event came from — login (sign-in activity), admin (console configuration changes), drive (file access and sharing), token (OAuth app authorization and API activity), mobile (device management), groups, and several more. Each category corresponds, conceptually, to a distinct audit feed Google exposes through its Admin SDK Reports API — an organisation ingesting Google Workspace logs into a SIEM is typically pulling several of these categories in parallel, not one single unified feed the way Okta's System Log works.\n\n" +
        "**gws.event.name: the specific action within that category.** Within the token category, authorize records a new OAuth consent grant, and activity records the app actually using an already-issued token to call an API. Within the drive category, download, view, and edit each record a different kind of file interaction, and permission changes get their own event names entirely. Within the admin category, specific actions like CHANGE_PASSWORD or a 2-Step-Verification enforcement change each get their own precise name.\n\n" +
        "**Why this two-field structure differs from a single Operation field.** An analyst used to Microsoft 365's Unified Audit Log may expect one flat Operation field per event, covering everything from a mailbox rule change to a file share. Google Workspace instead separates 'which log' from 'which action within that log' — meaning an analyst has to know which category (event.type) they're even looking at before event.name is fully meaningful, since the same event.name string can theoretically mean different things in different categories.\n\n" +
        "**actor and target, the same shape as elsewhere.** As in the other identity-flavoured logs this platform teaches, an actor field names who performed the action (gws.actor.email is the most commonly used field), and where relevant, additional fields name what or whom the action affected — a file, another user's account, an application. Reading actor against the affected object is exactly as important here as it was in Okta's System Log: an admin resetting someone else's password is a different finding from an account somehow modifying its own settings unexpectedly.",
    },
    // ── Reading 3: SPF/DKIM/DMARC the GWS way ─────────────────────────────────
    {
      type: "reading" as const,
      id: "gwsf-r3",
      heading: "Email Authentication in Gmail: SPF, DKIM and DMARC, in Google's Own Fields",
      content:
        "The underlying concepts of SPF, DKIM and DMARC are universal — this platform's Email Security room already covers what each one actually verifies. This reading is specifically about where Gmail records the result of each check, and the one behavioural trap that catches analysts on any platform, Gmail included.\n\n" +
        "**Where the results live.** A delivered message in the Google Workspace audit carries gws.spf_result, gws.dkim_result (with a companion gws.dkim_domain naming which domain the DKIM signature actually validated against), and gws.dmarc_result, alongside gws.dmarc_policy (the sending domain's own published DMARC enforcement level — none, quarantine, or reject). A message's ultimate placement — inbox, spam, or quarantined — is recorded in gws.classification.\n\n" +
        "**What a PASS on all three actually proves, and what it doesn't.** All three mechanisms together answer one specific question: did the domain that appears to have sent this message actually authorise it to be sent. They say nothing about the content of the message, and critically, nothing about whether the sending mailbox itself has been compromised. A message sent from a genuinely compromised mailbox at a real, trusted domain will pass SPF, DKIM and DMARC every single time, because it really was sent through that domain's own infrastructure by whoever currently controls the account — the authentication check is answering the question correctly; the question just isn't 'is this message safe.'\n\n" +
        "**Why this matters more, not less, in a Workspace-to-Workspace or Workspace-to-Exchange world.** Attackers increasingly favour hijacking a real vendor or partner mailbox and replying inside an existing, legitimate email thread, rather than spoofing a domain outright — exactly because spoofing is what SPF/DKIM/DMARC are built to catch, while a hijacked mailbox sails through untouched. An analyst reviewing a suspicious Gmail message should treat a clean SPF/DKIM/DMARC result as confirmation of sender infrastructure, and look instead at sender history (has this address ever sent this kind of attachment before), thread context (is this really a reply inside a conversation the recipient started), and the attachment or link itself for the actual verdict.\n\n" +
        "**gws.spam_score, as a secondary signal.** Google's own spam-scoring model contributes a numeric score, but a low score on a message from a currently-compromised legitimate sender is expected, not reassuring — the message genuinely resembles the sender's normal traffic, because it came from their real infrastructure.",
    },
    // ── Question 1 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gwsf-q1",
      question:
        "A Gmail message shows gws.spf_result PASS, gws.dkim_result PASS, and gws.dmarc_result PASS, and it arrived as a reply inside a real, ongoing invoice thread with a genuine long-term supplier. What is the most accurate interpretation?",
      options: [
        "The sending domain did authorise the message -- which a compromised mailbox at that same real domain would also produce, so these three fields alone cannot establish that it is safe",
        "The message is very likely legitimate since all three mechanisms passed, so the only remaining risk is a lookalike display name, to be checked before the thread is trusted",
        "The passes indicate a permissive DMARC policy such as p=none on the sender's domain, so the result is advisory only and the message should be treated as effectively unauthenticated",
        "The three fields are Google's own re-evaluation of the message rather than the standard SPF, DKIM and DMARC outcomes, so no general conclusion can be drawn about the sender",
      ],
      answer: 0,
      explanation:
        "Reading 3 covered this exactly: all three checks answer 'did this domain authorise the message,' and a genuinely compromised mailbox at a real domain answers that question correctly too. Concluding safety from authentication alone is the precise trap, even with a display-name check added. A DMARC pass says nothing about whether the sender's policy is permissive like p=none -- it is working as intended, against a threat it isn't designed to catch. And the fields are not a Google-only re-evaluation: the underlying mechanisms are the same industry-standard SPF/DKIM/DMARC everywhere; only the field names Google uses to record the result are specific to Google Workspace.",
      xp: 25,
    },
    // ── Reading 4: OAuth ────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "gwsf-r4",
      heading: "OAuth in Google Workspace: Scopes, Consent, and the Token Audit",
      content:
        "Third-party OAuth applications are one of the highest-impact, most under-appreciated attack surfaces in any cloud-identity environment, and Google Workspace's token audit is where an analyst reads exactly what was granted.\n\n" +
        "**The consent flow, briefly.** A user visiting a third-party app's website is redirected to a genuine Google consent screen, listing the specific permissions (scopes) the app is requesting, and clicks Allow. Nothing about this flow requires a password to be re-entered, and no malware needs to run on the user's device — the entire transaction happens between the user's browser and Google's own servers, which is exactly why this vector bypasses endpoint detection entirely and, just as importantly, bypasses MFA: there is no interactive login for a second factor to challenge, because delegation, not authentication, is what's happening.\n\n" +
        "**Reading the token audit event.** A gws.event.type token, gws.event.name authorize event names the acting user (gws.actor.email), the app (gws.token.app_name and the durable gws.token.client_id, which stays constant across every future use of the grant), and — most importantly — gws.token.scope, an array listing exactly what was requested. A scope like https://mail.google.com/ grants full read/write/delete access to the entire mailbox. A scope like https://www.googleapis.com/auth/drive grants the same breadth over the entire Drive. Compare that to a narrow scope like drive.file, which only grants access to files the app itself created or the user explicitly opened with it — a dramatically smaller blast radius for the exact same 'a user authorized an app' shape.\n\n" +
        "**gws.token.access_type: online vs offline, and why it matters enormously.** An online token is only valid while a live session exists and typically expires quickly. An offline token — issued when the app requests it and the user consents — is a refresh token: a durable credential the app's own servers can use to obtain fresh access whenever they want, indefinitely, without the user present at all. This is the persistence mechanism in an OAuth-abuse case: the grant itself, not any later action, is what keeps working. Be precise about what a password reset does here. Google documents that a refresh token stops working when the user changes their password AND the token contains Gmail scopes (such as https://mail.google.com/). A refresh token holding only other scopes — Drive, Calendar, Contacts — is not tied to the password and keeps working after a reset. So a reset may happen to cut off a Gmail grant, but it is never a reliable way to contain OAuth abuse: the specific grant must be explicitly revoked.\n\n" +
        "**Governance fields: allowlist_status, marketplace_verified, publisher.** Google Workspace admins can restrict which third-party apps are allowed to request access at all; gws.app.allowlist_status reflects whether a given app was explicitly approved (TRUSTED) or is simply unrestricted by default policy (NOT_CONFIGURED / NOT_ALLOWLISTED). gws.app.marketplace_verified and gws.app.publisher indicate whether Google has reviewed the app's listing and whether it names a real, identifiable company. None of these fields is about what the user did — they're about the app's own governance status, and they are the fastest way to separate a sanctioned integration from an opportunistic one requesting the exact same kind of grant.",
      diagram:
        "flowchart LR\n" +
        "  U[User clicks Allow on Google's own consent screen] --> T[Token audit: event.name authorize]\n" +
        "  T --> S{scope breadth}\n" +
        "  S -->|narrow, e.g. drive.file| N[Limited blast radius]\n" +
        "  S -->|broad, e.g. full Gmail + full Drive| B[Large blast radius]\n" +
        "  T --> AT{access_type}\n" +
        "  AT -->|online| O[Expires with the session]\n" +
        "  AT -->|offline| R[Refresh token -- works indefinitely, non-Gmail scopes survive a password reset]\n",
      diagramCaption: "Scope breadth and access_type together determine how dangerous a single Allow click really is",
      checkpoint: {
        question: "Why does resetting a compromised user's password NOT stop an OAuth app that was already granted an offline (refresh) token for Drive and Calendar?",
        options: [
          "The refresh token is its own credential; a reset kills only Gmail-scoped ones",
          "The reset does revoke it, but only after the current access token expires",
          "The reset ends her browser sessions, and the app keeps the session it already had",
          "Offline tokens are bound to the device that consented, which a reset ignores",
        ],
        answer: 0,
        explanation:
          "This is the crux of Reading 4: an offline refresh token is a bearer credential in its own right, independent of the password. The one documented exception is Gmail: a password change invalidates refresh tokens that contain Gmail scopes. A Drive/Calendar grant has no such link, so only revoking the specific grant -- not resetting the password -- removes the app's access. The reset does not revoke it “later” either: the app simply uses the refresh token to get a fresh access token. The app never shared the user's browser session, so ending sessions does not touch it. And a refresh token is held by the app's own servers, not bound to the user's device.",
      },
    },
    // ── Log Analysis 1: OAuth consent grant ──────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "gwsf-la1",
      heading: "One Click on a Consent Screen",
      context:
        "MedCore Health's Alert Center flagged a sensitive-scope OAuth grant. k.stensrud, a clinical operations manager, had clicked through a consent screen for an app called FormFlow Sync earlier that afternoon after receiving an email inviting her to connect it to her Google account for form automation.",
      event: oauthConsentEvent,
      questions: [
        {
          question:
            "gws.token.scope lists https://www.googleapis.com/auth/calendar and https://www.googleapis.com/auth/drive, and gws.token.access_type is 'offline'. What did this single event actually grant FormFlow Sync?",
          options: [
            "Lasting read/write access to all of Calendar and Drive, via a refresh token",
            "Access only to Drive files the user creates or opens with FormFlow Sync",
            "Full Calendar and Drive access that ends when k.stensrud's session ends",
            "Full Calendar and Drive access, but read-only until an admin approves it",
          ],
          answer: 0,
          explanation:
            "The two scopes are among the broadest Google issues (full Calendar, full Drive), and 'offline' means a refresh token was issued — a durable credential the app's servers can use without the user present. Because neither scope is a Gmail scope, a password change does not invalidate it either. “Only files the user opens with the app” describes the narrow drive.file scope, which is not what was granted. “Ends with her session” describes an online token, not offline. And the governance fields do not turn a grant into read-only pending approval — the scopes requested are the access the app got.",
          xp: 25,
        },
        {
          question:
            "gws.app.allowlist_status is 'NOT_CONFIGURED' and gws.app.marketplace_verified is 'false'. What do these two fields tell you, distinct from the scope itself?",
          options: [
            "Admins have not approved the app, and Google has not verified its publisher",
            "The app cannot call any Google API until an admin approves it in the console",
            "Admins reviewed the app and deliberately chose to leave it unrestricted",
            "Google has judged the app malicious and removed it from the Marketplace",
          ],
          answer: 0,
          explanation:
            "These are governance fields, separate from scope: allowlist_status shows the org's admins never explicitly approved the app, and marketplace_verified shows Google has not reviewed its publisher — a red flag independent of the permissions requested. Neither field blocks API calls; the Drive audit later in this room shows the app using its token. NOT_CONFIGURED means unrestricted by default policy, not a reviewed decision to allow it. And “not verified” means no review happened, not that Google found it malicious.",
          xp: 25,
        },
        {
          question:
            "Given everything in this event, what should the analyst check next?",
          options: [
            "Whether the token has been used against Drive or Calendar, and from where",
            "Whether her sign-in before the consent passed 2-Step Verification",
            "Whether Gmail flagged the invitation email that led her to the app as spam",
            "Whether her password appears in a known breach, before resetting it",
          ],
          answer: 0,
          explanation:
            "The consent grant is the foothold; the next question is whether and how the token has been used — exactly what the next task investigates. Her own sign-in is not the issue: consent is delegation, so a perfectly MFA-protected session can still grant a malicious app. Whether Gmail flagged the lure is worth knowing later, but it does not tell you what the app is doing now. And her password plays no part in the grant — a breach check and a reset do not touch a Drive/Calendar refresh token.",
          xp: 30,
        },
      ],
    },
    // ── Reading 5: Drive sharing / download audit ─────────────────────────────
    {
      type: "reading" as const,
      id: "gwsf-r5",
      heading: "Drive Sharing and the Drive Audit Log",
      content:
        "Google Drive is where most of an organisation's working files live in a Workspace environment, and its audit log is where both sharing risk and exfiltration activity show up.\n\n" +
        "**The core fields.** A drive-category event names the affected document through gws.drive.doc_title and a stable gws.drive.doc_id, the file's gws.drive.owner, and its gws.drive.visibility (private, or shared at some broader level — within the organisation, or, most permissively, anyone with the link). gws.event.name distinguishes the kind of interaction: view, edit, download, or a permission change specifically (adding a collaborator, or changing a file's visibility level).\n\n" +
        "**Sharing risk.** A file moving from private or organisation-only visibility to anyone-with-the-link is one of the highest-value events to alert on in any Drive environment — it means the access control protecting that file's content no longer depends on who the recipient is at all, only on whether they have the link, which can itself be forwarded, guessed, or leaked. This is conceptually identical to an external-sharing alert in SharePoint or OneDrive; only the field names differ.\n\n" +
        "**Download volume as a collection signal.** A single download event is unremarkable — every normal workday produces many. What matters is volume and pattern: gws.access.download_count_window (or an equivalent aggregation an ingesting SIEM computes from a burst of individual download events) showing hundreds of downloads in a short window, especially attributed to an OAuth app's token rather than an interactive user session, is the Drive equivalent of a mass-download insider-threat or exfiltration signal this platform already teaches for SharePoint and OneDrive.\n\n" +
        "**gws.access.via_oauth_app: the field that ties collection back to a grant.** When present, this field names the specific OAuth application whose token authenticated the access — the direct link between an earlier token authorize event and everything that app subsequently does. An analyst investigating a suspicious download burst should always check this field: activity attributed to an app token, from an app's own infrastructure IP rather than the user's normal device, is a fundamentally different finding than the same volume of downloads from the user's own browser session.",
    },
    // ── Log Analysis 2: Drive download burst ─────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "gwsf-la2",
      heading: "Three Hundred and Forty Downloads in Eleven Minutes",
      context:
        "Later that afternoon, the Drive audit log for k.stensrud@medcorehealth.org shows the event below.",
      event: driveDownloadBurstEvent,
      questions: [
        {
          question:
            "gws.access.via_oauth_app names FormFlow Sync, and source.ip is 146.148.92.14 (Amsterdam) -- not k.stensrud's own device or location. What does that combination establish?",
          options: [
            "The app's servers used the grant's token; her own browser was not involved",
            "She was travelling and downloaded the files herself from a hotel network",
            "Her session cookie was stolen and replayed from a server in Amsterdam",
            "Google's own servers prefetched the files so they would open faster",
          ],
          answer: 0,
          explanation:
            "via_oauth_app names FormFlow Sync and the same client_id as the consent grant, and the IP belongs to a hosting provider rather than her device: the app's backend is using its token. If she had downloaded the files herself while travelling, the events would not be attributed to an OAuth app. A stolen session cookie replays her browser session, which would also show no via_oauth_app attribution. And Google-side caching is not logged as hundreds of downloads by a third-party app.",
          xp: 25,
        },
        {
          question:
            "340 downloads in 11 minutes is far above k.stensrud's ordinary daily volume. Combined with the earlier OAuth grant, how should this be classified?",
          options: [
            "Collection using the access from the consent grant: the grant was the foothold",
            "Her own Drive syncing to a new laptop, which pulls many files in one go",
            "A sign her password was stolen too, since app tokens cannot download files",
            "A separate insider downloading under her account, unrelated to the grant",
          ],
          answer: 0,
          explanation:
            "The consent grant is the durable foothold and this burst is the collection carried out with it — two jobs tied together by the same client_id and via_oauth_app value. A sync to her own laptop would run as her, from her device, with no third-party app attribution. App tokens with the drive scope can download files — that is what the scope grants — so nothing here requires a stolen password. And the shared client_id rules out an unrelated insider.",
          xp: 25,
        },
        {
          question:
            "What is the correct combined remediation, given both findings together?",
          options: [
            "Revoke the grant, blocklist the client ID, then scope what the token touched",
            "Reset k.stensrud's password, sign her out of all sessions, then close the case",
            "Block 146.148.92.14 at the perimeter firewall, then watch for new downloads",
            "Scope every file the token touched first, then revoke once scoping is done",
          ],
          answer: 0,
          explanation:
            "Only revoking the grant ends the app's access, and blocklisting the client_id stops it being re-authorized; then scope what was taken. A password reset and sign-out do not touch an offline token that holds only Drive/Calendar scopes. The app's API calls go to Google's servers, not through your perimeter, so blocking the IP neither reaches the app nor revokes anything. Scoping first is the right work at the wrong time: exfiltration is live, and revoking does not erase the audit history you need for scoping.",
          xp: 30,
        },
      ],
    },
    // ── Reading 6: Admin audit log ──────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "gwsf-r6",
      heading: "The Admin Audit Log: Console Actions That Change the Whole Tenant",
      content:
        "Beyond mail and files, the Google Workspace Admin console audit log records changes an administrator makes to the organisation itself, and these events matter for two distinct reasons: they scope an incident, and they verify whether a remediation step actually worked.\n\n" +
        "**Common admin-category actions.** CHANGE_PASSWORD (an admin resetting a user's password), suspending or restoring a user account, changing 2-Step-Verification enforcement policy, and managing the organisation's third-party app allowlist are all recorded here, each carrying gws.actor.email (the admin who acted) and a target user or object field.\n\n" +
        "**Why this log matters for scoping.** If an account is suspected compromised, the admin log shows exactly what administrative changes have already been made around it — useful both for reconstructing a timeline and for confirming that a response action assumed to have happened actually did.\n\n" +
        "**The specific verification trap this room keeps returning to.** An admin event resetting a password, for example, can carry a field like gws.admin.oauth_tokens_revoked recording whether that specific action also revoked the account's OAuth grants — and, per Reading 4, a plain password reset does not revoke grants by default (only Gmail-scoped refresh tokens stop working after a password change; Drive, Calendar and other grants carry on). Reading the admin log's own record of what a containment action actually did, rather than assuming what it probably did, is the single most reliable way to confirm an OAuth-abuse case has actually been closed rather than just appearing to be.\n\n" +
        "**Third-party app allowlist management.** When an admin adds an app to the organisation's allowlist or removes one, that action is itself logged here — meaning the blocklisting step that follows an OAuth-abuse investigation (removing a malicious client_id from being authorizable again) leaves its own audit trail, useful for confirming a specific incident's remediation was actually completed and documented.",
    },
    // ── Question 2 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gwsf-q2",
      question:
        "An admin's CHANGE_PASSWORD event for a compromised account shows gws.admin.oauth_tokens_revoked as 'false'. An analyst is about to close the OAuth-abuse ticket because a password reset was performed. What should this specific field change about that decision?",
      options: [
        "Nothing -- a reset invalidates the user's session cookies and the refresh tokens issued under them, so the field is informational and the ticket can be closed",
        "It should stop the closure -- the field confirms the reset did NOT revoke the OAuth grant, so the malicious app's token stays valid and needs separate revocation",
        "It means the reset partly failed and must be retried by an admin, since token revocation is the last step of a successful password reset",
        "It matters for marketplace-verified apps -- for an unverified app like this one, the reset already blocks further API calls on its own",
      ],
      answer: 1,
      explanation:
        "Reading 6 built this scenario directly around Reading 4's core lesson: the admin log's own record of oauth_tokens_revoked being false is direct, first-party confirmation that the containment step assumed to work did not actually revoke the grant. Assuming a reset is always sufficient is the exact trap -- Google only invalidates refresh tokens that contain Gmail scopes on a password change, and FormFlow Sync's Drive/Calendar grant has none. The field describes token revocation, not whether the password reset itself succeeded. And a grant's survival has nothing to do with whether the app is marketplace-verified -- verification is a governance signal, not a revocation mechanism.",
      xp: 25,
    },
    // ── Reading 7: Alert Center ──────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "gwsf-r7",
      heading: "Alert Center: Google's Built-In Correlation Layer",
      content:
        "Google Workspace ships its own pre-built correlation and alerting layer, called Alert Center, and knowing what it is — and, just as importantly, what it isn't — saves an analyst real time.\n\n" +
        "**What it does.** Alert Center watches the same underlying audit streams this room has covered and raises a small number of specific, named alert types when a recognisable risky pattern occurs: a third-party app granted sensitive scopes, a suspicious sign-in, a leaked-password match against a known breach corpus, a spike in suspicious email activity, and several more. Each alert carries a gws.alert.center.type field naming which pattern fired, and a unique gws.alert.center.id for tracking.\n\n" +
        "**Why this is genuinely useful, not just noise.** Alert Center's whole value is pre-correlation: instead of an analyst needing to notice a broad-scope OAuth grant by scanning the raw token audit themselves, Alert Center surfaces it directly as a named, actionable item. This is directly comparable in role — though, as with everything in this room, not in specific mechanism or field names — to how Microsoft Defender's own alerts sit on top of the raw Azure AD sign-in and audit logs this platform already teaches: a pre-built detection layer over the same underlying telemetry.\n\n" +
        "**Why an analyst still pivots to the raw logs.** An Alert Center notification tells you what pattern fired and roughly why, but it does not replace reading the underlying token, drive, or admin audit events directly — those raw events carry the specific scope list, the specific client_id, the specific source IP, and the specific timeline needed to actually scope and remediate an incident. Alert Center is where an investigation typically starts; the audit logs are where it's actually worked.",
    },
    // ── Reading 8: GWS vs M365 contrast ───────────────────────────────────────
    {
      type: "reading" as const,
      id: "gwsf-r8",
      heading: "Google Workspace vs Microsoft 365: Where the Concepts Rhyme, and Where They Don't",
      content:
        "This reading exists specifically because this platform teaches Microsoft 365, Exchange Online, and SharePoint in depth, and the biggest real risk for an analyst moving between the two suites is assuming more carries over than actually does.\n\n" +
        "**Mail.** Gmail and Exchange Online do the same job — hosted, cloud-based email with anti-spam and anti-phishing controls, and both support SPF/DKIM/DMARC identically at the protocol level. Where they diverge is the audit field structure: Gmail records gws.spf_result / gws.dkim_result / gws.dmarc_result in its own Gmail log events (Email Log Search / the Gmail logs exported to BigQuery), not in the login audit, while Exchange Online records comparable information inside the Unified Audit Log's message-tracking and mail-flow fields under a single Operation-centric model.\n\n" +
        "**Files.** Drive and SharePoint/OneDrive are the direct equivalents for file storage and sharing, and both support the same core risk pattern this platform already teaches — a file's visibility being widened beyond what it should be, and abnormal download volume as an exfiltration signal. Drive uses gws.drive.visibility and gws.event.name (download/edit/view); SharePoint and OneDrive express the same ideas through their own SharingCapability and Operation fields.\n\n" +
        "**Administration.** Google's Admin console and Microsoft's combination of the Microsoft 365 admin center plus Entra ID split responsibility differently — Microsoft separates identity administration (Entra) from productivity-suite administration (the M365 admin center) into genuinely different consoles and, largely, different logs, while Google Workspace's Admin console is the single place both identity-adjacent settings (like 2-Step-Verification enforcement) and productivity-suite settings are managed and logged together.\n\n" +
        "**OAuth.** Both platforms support third-party app consent with the exact same underlying risk (broad scope plus unverified publisher plus offline/refresh access), but Google's scope strings (like https://www.googleapis.com/auth/drive) and Microsoft's Graph API permission names (like Mail.ReadWrite) are entirely different vocabularies naming conceptually similar levels of access — an analyst has to learn each platform's own scope/permission naming to judge breadth correctly, rather than pattern-matching one vendor's strings against the other's.\n\n" +
        "**Pre-built alerting.** Alert Center is Google's analogue to Microsoft Defender's own alerting layered over Entra ID and M365 telemetry — same role, same reason to still check the raw logs behind it, different specific alert catalogue and field names.\n\n" +
        "**The one habit this reading is trying to build.** Before running a single query against an unfamiliar tenant, confirm which productivity suite actually issues its logs. If it's Google Workspace, expect gws.event.type/gws.event.name and Google's own scope strings. If it's Microsoft 365, expect the Unified Audit Log's Operation field and Microsoft Graph permission names. Treating the two as interchangeable is the single most avoidable mistake this room can prevent.",
      checkpoint: {
        question: "An analyst who knows Microsoft Graph permissions sees a Workspace grant with the scope https://www.googleapis.com/auth/drive and needs to judge how broad it is. What is the right approach?",
        options: [
          "Map it to the closest-looking Graph permission name and judge it from that",
          "Judge it in Google's own scope vocabulary, e.g. drive versus drive.file",
          "Treat googleapis.com scopes as low risk until Alert Center raises an alert",
          "Skip the scope and judge only the publisher field, since scopes don't compare",
        ],
        answer: 1,
        explanation:
          "The risk pattern is universal but the scope vocabulary is vendor-specific, so breadth must be read in Google's own terms: drive is the whole Drive, drive.file only the app's own or opened files. Pattern-matching to a similar-looking Graph name is exactly the cross-vendor guess this reading warns against. Alert Center is a starting point, not a substitute for reading the scope. And the publisher field is a governance signal that sits alongside scope breadth — it does not replace it.",
      },
    },
    // ── Analyst Choice: benign narrow-scope grant ─────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "gwsf-ac1",
      heading: "Verdict: Another User Authorizes Another Third-Party App",
      scenario:
        "MedCore's SIEM has a rule that raises an alert for every OAuth authorize event in the Workspace token audit. The event below fired for a different user, two days before the FormFlow Sync grant. Review it before deciding how to handle it.",
      event: benignAllowlistedGrantEvent,
      correct_verdict: "false_positive",
      explanation:
        "The shape is identical to the FormFlow Sync incident -- a user consenting to a third-party OAuth app -- but every discriminator points the other way. gws.token.scope lists only drive.file, a narrow scope limited to files the app itself created or the user explicitly opened with it, nowhere near the breadth of full Calendar plus full Drive. gws.app.allowlist_status is TRUSTED (the org's admins have explicitly approved this app) and gws.app.marketplace_verified is true, naming a real, identifiable publisher. gws.token.access_type is 'offline', so the app does hold a refresh token -- the one signal it shares with FormFlow Sync. On its own that is not suspicious: sanctioned add-ons often need to work while the user is away. What decides it is what that refresh token can reach (only drive.file) and who holds it (an approved, verified publisher). None of the governance red flags from Reading 4 are present here.",
      fp_trap:
        "A token 'authorize' event is precisely the shape this room has taught you to scrutinize closely, since it's exactly how the FormFlow Sync compromise began. But real, legitimate productivity add-ons authorize this way constantly, requesting narrow, purpose-specific scopes and carrying real publisher verification. Escalating every OAuth consent event on shape alone -- or on the offline token alone -- without weighing scope breadth, allowlist status and publisher together, trains a team to drown in noise on the one pattern that most needs real scrutiny when it's genuinely malicious.",
      xp: 30,
    },
    // ── Matching: GWS term to M365 equivalent ─────────────────────────────────
    {
      type: "matching" as const,
      id: "gwsf-m1",
      heading: "Match the Google Workspace Concept to Its Microsoft 365 Equivalent",
      instructions: "Match each Google Workspace concept to the Microsoft 365 concept that plays the same role.",
      pairs: [
        { id: "gmail", left: "Gmail", right: "Exchange Online -- hosted mail with SPF/DKIM/DMARC support" },
        { id: "drive", left: "Google Drive", right: "SharePoint / OneDrive -- hosted file storage and sharing" },
        { id: "admin", left: "Admin console", right: "Microsoft 365 admin center + Entra ID -- tenant-wide configuration and identity administration" },
        { id: "alertcenter", left: "Alert Center", right: "Microsoft Defender's own alerting layer -- a pre-correlated view over the same underlying raw audit telemetry" },
        { id: "tokenaudit", left: "Token audit (gws.event.type token)", right: "Azure AD / Entra sign-in and audit logs recording OAuth app consent and Microsoft Graph API activity" },
      ],
      explanation:
        "Every pairing here plays the same SOC role across both suites -- but reaches for a different field name and, for OAuth specifically, an entirely different permission-string vocabulary to express it, which is exactly why Reading 8's habit of confirming which suite you're looking at matters.",
      xp: 35,
    },
    // ── Ordering: OAuth-abuse response ─────────────────────────────────────────
    {
      type: "ordering" as const,
      id: "gwsf-o1",
      heading: "Order the Response to a Confirmed Malicious OAuth Grant",
      instructions: "Arrange these steps in the order they should actually be carried out once a malicious third-party OAuth grant is confirmed.",
      items: [
        { id: "scope_activity", text: "Scope what the token was actually used for -- check the token activity log for Drive/Calendar API calls and any download bursts" },
        { id: "revoke", text: "Revoke the specific app's OAuth grant for the affected user (not just a password reset)" },
        { id: "blocklist", text: "Add the app's client_id to the organisation's app blocklist so it cannot be re-authorized by anyone" },
        { id: "verify", text: "Confirm in the admin audit log that both the revocation and the blocklist entry actually took effect, rather than assuming they did" },
        { id: "policy", text: "Review and tighten the organisation's third-party app access policy so unlisted apps require admin approval going forward" },
      ],
      correct_order: ["revoke", "blocklist", "verify", "scope_activity", "policy"],
      explanation:
        "The grant is confirmed malicious and exfiltration is active, so contain first: revoke the grant directly -- Reading 4 and Reading 6 both established that a password reset alone does not do this for a Drive/Calendar token. Blocklist the client_id so the same app cannot simply be re-authorized by the same or another user. Verify both actions in the admin log itself, rather than assuming they worked, exactly the way Question 2 in this room tested. Only then scope what the token was used for -- revoking does not erase the token and Drive audit history, so nothing is lost by scoping after containment, while every minute spent scoping first is another minute of live exfiltration. And only once the immediate incident is closed does it make sense to address the underlying policy gap that allowed an unlisted, unverified app to be authorized in the first place.",
      xp: 35,
    },
    // ── Flag ──────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "gwsf-f1",
      event: driveDownloadBurstEvent, // the collection event; the consent event is in 'One Click on a Consent Screen'
      prompt:
        "How long did the attacker take to go from foothold to collection? Using the timestamp of FormFlow Sync's consent grant ('One Click on a Consent Screen') and the timestamp of the Drive download event shown here, how many complete minutes passed between them? Drop any leftover seconds and enter a whole number.",
      answer: "16",
      hint: "Both events carry a UTC timestamp on the log card. Subtract the earlier one from the later one.",
      xp: 20,
    },
    // ── Question 3 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gwsf-q3",
      question:
        "A Drive file's gws.drive.visibility changes from 'private' to 'anyone with the link', and shortly afterward the same file shows up as viewed from an unfamiliar external IP address. Which statement best matches how this platform teaches the same pattern in SharePoint/OneDrive?",
      options: [
        "A Google-specific risk with no Microsoft 365 counterpart, since Drive links can be publicly indexed whereas SharePoint links require the recipient to sign in",
        "The same risk as sharing a SharePoint/OneDrive file with anyone-with-the-link: access depends on holding the link, not on who the recipient is",
        "Usually benign, since link sharing is a default collaboration setting, and worth review when the file carries a confidential classification label",
        "A change to discoverability in search, since who can actually open a file is decided by Docs-level permissions rather than by Drive visibility",
      ],
      answer: 1,
      explanation:
        "Reading 8's contrastive framing applies directly here: this is the same universal file-sharing risk this platform already teaches for SharePoint/OneDrive, expressed through Google's own gws.drive.visibility field rather than Microsoft's SharingCapability. It is not Google-specific -- SharePoint and OneDrive have anyone-with-the-link sharing too -- it is not something to treat as benign by default just because a classification label is absent, and visibility genuinely does govern who can open the file without further permission checks, so it is not a search-discoverability setting only.",
      xp: 25,
    },
    // ── Question 4: synthesis ──────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gwsf-q4",
      question:
        "Summarising this room: an OAuth grant with a broad, unverified scope is followed by a large download burst attributed to the same app token, and an admin's later password reset shows oauth_tokens_revoked = false. What is the single most accurate classification and required action?",
      options: [
        "OAuth application abuse with confirmed collection and incomplete remediation -- the grant must be explicitly revoked and blocklisted, since the reset alone left the token and its access intact",
        "A contained incident -- the password reset ended the compromised account's access, so only a review of what the app downloaded remains before the ticket is closed",
        "A false positive pending review -- OAuth consent is a normal user action in Workspace, and the download burst is consistent with the app's declared sync purpose",
        "An issue limited to the downloaded Drive files -- once they are identified the ticket can close, since the grant's Calendar scope was never used and needs no action"
      ],
      answer: 0,
      explanation:
        "This draws the room's threads together: the broad-scope, unverified grant (Reading 4) is the persistence mechanism; the download burst tied to the same client_id (Reading 5) is the collection; and the admin log's own oauth_tokens_revoked field (Reading 6) proves the password reset did not actually close the gap. Calling this a contained incident or a false positive both repeat mistakes this room specifically targeted. And limiting it to the downloaded files ignores that the token itself is still live: the grant spans full Drive and full Calendar together, and stays usable until it is explicitly revoked.",
      xp: 30,
    },
  ],
};

export const roomsBatch38 = [googleWorkspaceSecurityRoom];
