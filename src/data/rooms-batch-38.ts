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
    "A token audit 'authorize' event recorded k.stensrud@medcorehealth.org granting a third-party app named FormFlow Sync the scopes for full Gmail and full Drive access, with an offline refresh token issued.",
  raw: {
    "gws.event.type": "token",
    "gws.event.name": "authorize",
    "gws.actor.email": "k.stensrud@medcorehealth.org",
    "gws.token.client_id": "719402883561-q8m3k7n2p9r4t6u1v0w5x8y3z2a7b6c1.apps.googleusercontent.com",
    "gws.token.app_name": "FormFlow Sync",
    "gws.token.client_type": "WEB",
    "gws.token.scope": [
      "https://mail.google.com/",
      "https://www.googleapis.com/auth/drive",
      "openid",
      "https://www.googleapis.com/auth/userinfo.email",
    ],
    "gws.token.api_name": ["gmail", "drive"],
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
    "p.duval authorized Grammarly, an admin-allowlisted, marketplace-verified app, requesting only a narrow document-content scope for its writing-assistance feature -- a routine, sanctioned OAuth grant. The act of granting an app is identical in shape to the FormFlow Sync incident; the discriminators are scope breadth, allowlist status, and publisher verification, not the act of consenting itself.",
  description:
    "p.duval authorized Grammarly, an admin-allowlisted, marketplace-verified app, requesting a single narrow document-editing scope.",
  raw: {
    "gws.event.type": "token",
    "gws.event.name": "authorize",
    "gws.actor.email": "p.duval@medcorehealth.org",
    "gws.token.client_id": "441029581763-h5j2k9l1m3n7o4p6q8r0s2t5u1v9w3x7.apps.googleusercontent.com",
    "gws.token.app_name": "Grammarly",
    "gws.token.client_type": "WEB",
    "gws.token.scope": ["https://www.googleapis.com/auth/drive.file"],
    "gws.token.api_name": "drive",
    "gws.token.access_type": "online",
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
  category: "Cloud & SaaS Security",
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
        question: "What is this room's central claim about an analyst who already knows Microsoft 365 security well, encountering a Google Workspace tenant for the first time?",
        options: [
          "They need no adjustment at all, since Google Workspace logs are a reformatted copy of the Microsoft 365 Unified Audit Log",
          "The underlying SOC concepts (mail security, sharing risk, OAuth abuse, admin governance) transfer directly, but the actual field names and event structure do not, and assuming otherwise risks misreading real evidence",
          "Google Workspace does not produce any audit logs at all, so no adjustment is possible",
          "Microsoft 365 knowledge is actively counterproductive and should be set aside entirely before learning Google Workspace",
        ],
        answer: 1,
        explanation:
          "The concepts rhyme; the schemas don't. That's the whole premise of this room -- transferable judgment, non-transferable field names.",
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
        "The domain that sent this message really did authorise it -- which is exactly what a compromised mailbox at that same real domain would also produce, so these three fields cannot by themselves establish that the message is safe",
        "The message is proven safe, because all three authentication mechanisms passed",
        "The passing results mean the sender's domain must have a misconfigured, overly permissive DMARC policy",
        "SPF, DKIM and DMARC in Google Workspace check different things entirely than they do for any other mail provider, so no general conclusion is possible",
      ],
      answer: 0,
      explanation:
        "Reading 3 covered this exactly: all three checks answer 'did this domain authorise the message,' and a genuinely compromised mailbox at a real domain answers that question correctly too. Concluding safety from authentication alone (b) is the precise trap. A pass says nothing about misconfiguration (c) -- it's working as intended, against a threat it isn't designed to catch. And the underlying mechanisms are the same industry-standard SPF/DKIM/DMARC everywhere (d); only the field names Google uses to record the result are specific to Google Workspace.",
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
        "**gws.token.access_type: online vs offline, and why it matters enormously.** An online token is only valid while a live session exists and typically expires quickly. An offline token — issued when the app requests it and the user consents — is a refresh token: a durable credential the app's own servers can use to obtain fresh access whenever they want, indefinitely, without the user present at all. This is the persistence mechanism in an OAuth-abuse case: the grant itself, not any later action, is what survives a password reset, since resetting a password does not revoke an already-issued refresh token.\n\n" +
        "**Governance fields: allowlist_status, marketplace_verified, publisher.** Google Workspace admins can restrict which third-party apps are allowed to request access at all; gws.app.allowlist_status reflects whether a given app was explicitly approved (TRUSTED) or is simply unrestricted by default policy (NOT_CONFIGURED / NOT_ALLOWLISTED). gws.app.marketplace_verified and gws.app.publisher indicate whether Google has reviewed the app's listing and whether it names a real, identifiable company. None of these fields is about what the user did — they're about the app's own governance status, and they are the fastest way to separate a sanctioned integration from an opportunistic one requesting the exact same kind of grant.",
      diagram:
        "flowchart LR\n" +
        "  U[User clicks Allow on Google's own consent screen] --> T[Token audit: event.name authorize]\n" +
        "  T --> S{scope breadth}\n" +
        "  S -->|narrow, e.g. drive.file| N[Limited blast radius]\n" +
        "  S -->|broad, e.g. full Gmail + full Drive| B[Large blast radius]\n" +
        "  T --> AT{access_type}\n" +
        "  AT -->|online| O[Expires with the session]\n" +
        "  AT -->|offline| R[Refresh token -- survives password reset, works indefinitely]\n",
      diagramCaption: "Scope breadth and access_type together determine how dangerous a single Allow click really is",
      checkpoint: {
        question: "Why does resetting a compromised user's password NOT stop an OAuth app that was already granted an offline (refresh) token?",
        options: [
          "A refresh token is a separate, durable credential the app presents on its own -- it is not derived from, and does not depend on, the user's password, so a reset has no effect on it",
          "Password resets always automatically revoke every OAuth grant a user has ever made, so this scenario cannot actually occur",
          "Offline tokens expire automatically within a few minutes regardless of any admin action, making the password reset irrelevant either way",
          "Because Gmail and Drive are not covered by password-based authentication at all, even before any OAuth grant exists",
        ],
        answer: 0,
        explanation:
          "This is the crux of Reading 4: an offline refresh token is a bearer credential in its own right, independent of the password. Only revoking the specific grant -- not resetting the password -- actually removes the app's access.",
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
            "gws.token.scope lists https://mail.google.com/ and https://www.googleapis.com/auth/drive, and gws.token.access_type is 'offline'. What did this single event actually grant FormFlow Sync?",
          options: [
            "Durable, indefinite read/write access to the entire mailbox and the entire Drive, via a refresh token that keeps working even after a password reset",
            "One-time read access to a single file the user had open at the moment of consent",
            "Temporary access that automatically expires the moment the user's browser tab is closed",
            "No actual access at all -- only a preview of what the app would request if it were later approved by an admin",
          ],
          answer: 0,
          explanation:
            "Reading 4 covered exactly this combination: the two scopes listed are among the broadest Google issues (full Gmail, full Drive), and 'offline' access_type means a refresh token was issued -- a durable credential independent of the password and the browser session, not a one-time or session-scoped grant.",
          xp: 25,
        },
        {
          question:
            "gws.app.allowlist_status is 'NOT_CONFIGURED' and gws.app.marketplace_verified is 'false'. What do these two fields tell you, distinct from the scope itself?",
          options: [
            "The app has not been explicitly vetted or approved by the organisation's admins, and Google has not verified its publisher identity -- a governance red flag independent of what permissions it happened to request",
            "The app is technically incapable of making any API calls until an admin manually approves it",
            "These fields are purely cosmetic labels shown to the end user and have no bearing on the app's actual access",
            "NOT_CONFIGURED means the exact opposite of what it says -- that the app has already been fully vetted and approved",
          ],
          answer: 0,
          explanation:
            "Reading 4 named these as governance fields distinct from scope: allowlist_status reflects whether the org's admins have explicitly approved the app (they haven't here), and marketplace_verified reflects Google's own review of the publisher (absent here too). Neither field blocks API calls by itself (b) -- the token audit's next event shows exactly that. And NOT_CONFIGURED means unrestricted-by-default, not vetted (d).",
          xp: 25,
        },
        {
          question:
            "Given everything in this event, what should the analyst check next?",
          options: [
            "Whether the token has actually been used to call the Gmail or Drive APIs, and from where",
            "Whether k.stensrud's password was typed correctly during the consent flow",
            "Whether Gmail's spam filter flagged the message that invited her to connect the app",
            "Whether the app requested a scope for Google Calendar as well",
          ],
          answer: 0,
          explanation:
            "The consent grant is the foothold; the natural next question is whether and how it has been used -- exactly what the next task in this room investigates. No password was involved in the OAuth consent flow at all (b) -- that is the point of delegated access. The inviting message's spam disposition (c) is a secondary, less urgent question at this stage. And no Calendar scope appears in this event, so speculating about one (d) isn't supported by the evidence.",
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
        "Seventeen minutes after the FormFlow Sync consent grant, the Drive audit log for k.stensrud@medcorehealth.org shows the event below.",
      event: driveDownloadBurstEvent,
      questions: [
        {
          question:
            "gws.access.via_oauth_app names FormFlow Sync, and source.ip is 146.148.92.14 (Amsterdam) -- not k.stensrud's own device or location. What does that combination establish?",
          options: [
            "These downloads were performed by the app's own backend servers using the token from the earlier consent grant, not by k.stensrud interactively using her own browser or device",
            "k.stensrud must have travelled to Amsterdam and performed the downloads herself in person",
            "The event is definitely corrupted, since a Drive download must always originate from the file owner's registered device",
            "via_oauth_app is a cosmetic label with no bearing on where the request actually originated",
          ],
          answer: 0,
          explanation:
            "Reading 5 named this exact pattern: via_oauth_app plus a source IP that doesn't match the user's own device or normal location is the tell that an app's own backend, not the user, is driving the activity -- using the token issued in the earlier consent grant. Nothing here requires (or evidences) physical travel (b), the event is a coherent, expected shape for OAuth-token-driven access, not corruption (c), and the field is directly informative about origin, not cosmetic (d).",
          xp: 25,
        },
        {
          question:
            "340 downloads in 11 minutes is far above k.stensrud's ordinary daily volume. Combined with the earlier OAuth grant, how should this be classified?",
          options: [
            "Collection/impact carried out using the persistent access obtained in the consent grant -- the grant was the foothold, this download burst is what was done with it",
            "A routine, expected Drive backup process that every Workspace account performs automatically overnight",
            "An unrelated coincidence with no connection to the earlier OAuth event",
            "Proof that k.stensrud's password, not just her OAuth grant, has been compromised",
          ],
          answer: 0,
          explanation:
            "This mirrors the persistence-vs-impact split this platform's OAuth-abuse content emphasises: the consent grant (Reading 4/Log Analysis 1) is the durable foothold, and this download burst is the collection carried out using it -- two different jobs, tied together by the same client_id and via_oauth_app value. Google Workspace does not run an automatic bulk-download 'backup' process attributed to a third-party app token (b), the shared client_id/timing rules out coincidence (c), and nothing here evidences or requires a separate password compromise -- the OAuth token alone fully explains the activity (d).",
          xp: 25,
        },
        {
          question:
            "What is the correct combined remediation, given both findings together?",
          options: [
            "Revoke FormFlow Sync's OAuth grant for k.stensrud (and blocklist the client id tenant-wide), then scope exactly which files and mail were accessed using the token",
            "Reset k.stensrud's password and consider the incident closed, since a password reset revokes any associated OAuth tokens automatically",
            "Block the source IP 146.148.92.14 at the network perimeter and take no further action",
            "Ask k.stensrud to manually delete the downloaded files from her own Drive to undo the exposure",
          ],
          answer: 0,
          explanation:
            "As Reading 4 established, only revoking the grant actually ends the app's access -- a password reset does not touch an already-issued offline token (b is the specific trap this room has repeated for a reason). The API traffic goes to Google's own servers, not through the organisation's perimeter, so blocking one IP (c) neither reaches the app's infrastructure nor revokes anything. And deleting files from Drive (d) does nothing about data already downloaded to the app's own servers -- the exposure already happened.",
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
        "**The specific verification trap this room keeps returning to.** An admin event resetting a password, for example, can carry a field like gws.admin.oauth_tokens_revoked recording whether that specific action also revoked the account's OAuth grants — and, per Reading 4, a plain password reset typically does not do this by default. Reading the admin log's own record of what a containment action actually did, rather than assuming what it probably did, is the single most reliable way to confirm an OAuth-abuse case has actually been closed rather than just appearing to be.\n\n" +
        "**Third-party app allowlist management.** When an admin adds an app to the organisation's allowlist or removes one, that action is itself logged here — meaning the blocklisting step that follows an OAuth-abuse investigation (removing a malicious client_id from being authorizable again) leaves its own audit trail, useful for confirming a specific incident's remediation was actually completed and documented.",
    },
    // ── Question 2 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gwsf-q2",
      question:
        "An admin's CHANGE_PASSWORD event for a compromised account shows gws.admin.oauth_tokens_revoked as 'false'. An analyst is about to close the OAuth-abuse ticket because a password reset was performed. What should this specific field change about that decision?",
      options: [
        "Nothing -- a password reset is always sufficient regardless of what this field says",
        "It should stop the analyst from closing the ticket -- the field confirms directly that the reset did NOT revoke the OAuth grant, meaning the malicious app's token is still valid and separate revocation action is still required",
        "It means the password reset itself failed and must be retried before anything else can be checked",
        "It only applies to Drive-scoped tokens, so Gmail-scoped access is unaffected either way",
      ],
      answer: 1,
      explanation:
        "Reading 6 built this scenario directly around Reading 4's core lesson: the admin log's own record of oauth_tokens_revoked being false is direct, first-party confirmation that the containment step assumed to work did not actually revoke the grant. Assuming a reset is always sufficient (a) is the exact trap. The field describes token revocation, not password-reset success or failure (c). And nothing in Reading 4 or 6 scopes token revocation to Drive only, separate from Gmail (d) -- a single OAuth grant's scopes typically span whatever the app originally requested.",
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
        "**Mail.** Gmail and Exchange Online do the same job — hosted, cloud-based email with anti-spam and anti-phishing controls, and both support SPF/DKIM/DMARC identically at the protocol level. Where they diverge is the audit field structure: Gmail records gws.spf_result / gws.dkim_result / gws.dmarc_result under the gws.event.type login/gmail categories, while Exchange Online records comparable information inside the Unified Audit Log's message-tracking and mail-flow fields under a single Operation-centric model.\n\n" +
        "**Files.** Drive and SharePoint/OneDrive are the direct equivalents for file storage and sharing, and both support the same core risk pattern this platform already teaches — a file's visibility being widened beyond what it should be, and abnormal download volume as an exfiltration signal. Drive uses gws.drive.visibility and gws.event.name (download/edit/view); SharePoint and OneDrive express the same ideas through their own SharingCapability and Operation fields.\n\n" +
        "**Administration.** Google's Admin console and Microsoft's combination of the Microsoft 365 admin center plus Entra ID split responsibility differently — Microsoft separates identity administration (Entra) from productivity-suite administration (the M365 admin center) into genuinely different consoles and, largely, different logs, while Google Workspace's Admin console is the single place both identity-adjacent settings (like 2-Step-Verification enforcement) and productivity-suite settings are managed and logged together.\n\n" +
        "**OAuth.** Both platforms support third-party app consent with the exact same underlying risk (broad scope plus unverified publisher plus offline/refresh access), but Google's scope strings (like https://www.googleapis.com/auth/drive) and Microsoft's Graph API permission names (like Mail.ReadWrite) are entirely different vocabularies naming conceptually similar levels of access — an analyst has to learn each platform's own scope/permission naming to judge breadth correctly, rather than pattern-matching one vendor's strings against the other's.\n\n" +
        "**Pre-built alerting.** Alert Center is Google's analogue to Microsoft Defender's own alerting layered over Entra ID and M365 telemetry — same role, same reason to still check the raw logs behind it, different specific alert catalogue and field names.\n\n" +
        "**The one habit this reading is trying to build.** Before running a single query against an unfamiliar tenant, confirm which productivity suite actually issues its logs. If it's Google Workspace, expect gws.event.type/gws.event.name and Google's own scope strings. If it's Microsoft 365, expect the Unified Audit Log's Operation field and Microsoft Graph permission names. Treating the two as interchangeable is the single most avoidable mistake this room can prevent.",
      checkpoint: {
        question: "An analyst notices a Google Workspace OAuth grant listing the scope https://www.googleapis.com/auth/drive and assumes it is directly equivalent, string-for-string, to a Microsoft Graph permission they already recognise from Entra ID. What is the correct adjustment per this reading?",
        options: [
          "No adjustment needed -- Google and Microsoft standardised on identical permission-string vocabularies years ago",
          "Recognise that both platforms support conceptually similar OAuth risk (broad scope, unverified publisher, offline access), but the specific scope/permission strings are each platform's own vocabulary and must be learned and judged on their own terms, not pattern-matched across vendors",
          "Assume the Google scope must be a typo, since only Microsoft Graph permissions are valid OAuth scope strings",
          "Conclude that Google Workspace does not support OAuth consent at all, since its scope naming looks unfamiliar",
        ],
        answer: 1,
        explanation:
          "Reading 8 was explicit about OAuth specifically: the risk pattern is universal, but the scope/permission vocabulary is vendor-specific. Assuming string-level equivalence (a) or dismissing the unfamiliar format (c, d) both miss the actual lesson -- learn each platform's own naming and judge breadth on its own terms.",
      },
    },
    // ── Analyst Choice: benign narrow-scope grant ─────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "gwsf-ac1",
      heading: "Verdict: Another User Authorizes Another Third-Party App",
      scenario:
        "MedCore's Alert Center generates a routine notification every time any OAuth authorize event occurs above a low sensitivity threshold. The event below fired for a different user, two days before the FormFlow Sync grant. Review it before deciding how to handle it.",
      event: benignAllowlistedGrantEvent,
      correct_verdict: "false_positive",
      explanation:
        "The shape is identical to the FormFlow Sync incident -- a user consenting to a third-party OAuth app -- but every discriminator points the other way. gws.token.scope lists only drive.file, a narrow scope limited to files the app itself created or the user explicitly opened with it, nowhere near the breadth of full Gmail plus full Drive. gws.app.allowlist_status is TRUSTED (the org's admins have explicitly approved this app) and gws.app.marketplace_verified is true, naming a real, identifiable publisher. gws.token.access_type is 'online', not the persistent offline/refresh pattern that made FormFlow Sync's grant a durable foothold. None of the governance red flags from Reading 4 are present here.",
      fp_trap:
        "A token 'authorize' event is precisely the shape this room has taught you to scrutinize closely, since it's exactly how the FormFlow Sync compromise began. But real, legitimate productivity add-ons authorize this way constantly, requesting narrow, purpose-specific scopes and carrying real publisher verification. Escalating every OAuth consent event on shape alone, without reading scope breadth, allowlist status, and access_type, trains a team to drown in noise on the one pattern that most needs real scrutiny when it's genuinely malicious.",
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
        { id: "scope_activity", text: "Scope what the token was actually used for -- check the token activity log for Gmail/Drive API calls and any download bursts" },
        { id: "revoke", text: "Revoke the specific app's OAuth grant for the affected user (not just a password reset)" },
        { id: "blocklist", text: "Add the app's client_id to the organisation's app blocklist so it cannot be re-authorized by anyone" },
        { id: "verify", text: "Confirm in the admin audit log that the revocation actually took effect, rather than assuming it did" },
        { id: "policy", text: "Review and tighten the organisation's third-party app access policy so unlisted apps require admin approval going forward" },
      ],
      correct_order: ["scope_activity", "revoke", "blocklist", "verify", "policy"],
      explanation:
        "Scope first, so the incident record reflects what actually happened, not just what could have happened. Revoke the grant directly -- Reading 4 and Reading 6 both established that a password reset alone does not do this. Blocklist the client_id so the same app cannot simply be re-authorized by the same or another user. Verify the revocation in the admin log itself, rather than assuming the action worked, exactly the way Question 2 in this room tested. And only once the immediate incident is closed does it make sense to address the underlying policy gap that allowed an unlisted, unverified app to be authorized in the first place.",
      xp: 35,
    },
    // ── Flag ──────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "gwsf-f1",
      prompt:
        "Look at the OAuth consent finding for k.stensrud@medcorehealth.org. What is the exact value of the gws.token.access_type field in the raw log?",
      answer: "offline",
      hint: "Look inside the raw block of the log analysis event for the field named gws.token.access_type.",
      xp: 20,
    },
    // ── Question 3 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gwsf-q3",
      question:
        "A Drive file's gws.drive.visibility changes from 'private' to 'anyone with the link', and shortly afterward the same file shows up as viewed from an unfamiliar external IP address. Which statement best matches how this platform teaches the same pattern in SharePoint/OneDrive?",
      options: [
        "This is a distinct, Google-specific risk with no real counterpart in Microsoft 365",
        "The underlying risk is identical to widening a SharePoint/OneDrive file's SharingCapability to anyone-with-the-link -- access no longer depends on who the recipient is, only on whether they hold the link -- just expressed through Google's own visibility field rather than Microsoft's",
        "This can only ever indicate a benign administrative default and never needs review",
        "Drive visibility settings have no bearing on who can actually open a file -- only Docs-level permissions do",
      ],
      answer: 1,
      explanation:
        "Reading 8's contrastive framing applies directly here: this is the same universal file-sharing risk this platform already teaches for SharePoint/OneDrive, expressed through Google's own gws.drive.visibility field rather than Microsoft's SharingCapability. It is not Google-specific (a), not something to wave off as always benign (c), and visibility genuinely does govern who can open the file without further permission checks (d).",
      xp: 25,
    },
    // ── Question 4: synthesis ──────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gwsf-q4",
      question:
        "Summarising this room: an OAuth grant with a broad, unverified scope is followed by a large download burst attributed to the same app token, and an admin's later password reset shows oauth_tokens_revoked = false. What is the single most accurate classification and required action?",
      options: [
        "OAuth application abuse with confirmed collection and an incomplete remediation -- the grant must be explicitly revoked and blocklisted, since the password reset alone left the token, and therefore the access, fully intact",
        "A fully resolved incident, since a password reset was already performed",
        "A false positive, since OAuth consent is a normal, expected user action in any Workspace environment",
        "An issue limited to Drive only, with no implication for the account's Gmail access"
      ],
      answer: 0,
      explanation:
        "This draws the room's threads together: the broad-scope, unverified grant (Reading 4) is the persistence mechanism; the download burst tied to the same client_id (Reading 5) is the collection; and the admin log's own oauth_tokens_revoked field (Reading 6) proves the password reset did not actually close the gap. Calling this resolved (b) or a false positive (c) both repeat mistakes this room specifically targeted, and the original grant's scope spanned both Gmail and Drive together, not Drive alone (d).",
      xp: 30,
    },
  ],
};

export const roomsBatch38 = [googleWorkspaceSecurityRoom];
