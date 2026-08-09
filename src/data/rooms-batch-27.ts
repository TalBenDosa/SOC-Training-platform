/**
 * Learning Rooms — Batch 27
 *
 * Two rooms closing a documented MITRE ATT&CK coverage gap: students practise
 * these exact sub-techniques inside scenario packs (aitmTokenTheft.ts fires
 * T1114 mailbox access and a T1098.005 device-registration persistence step)
 * but no room ever taught the mechanics behind either one.
 *
 * Rooms in this batch:
 *  1. remote-email-collection          — T1114.002, O365 Unified Audit Log,
 *                                         MailItemsAccessed, malicious inbox
 *                                         rules, BEC response
 *  2. device-registration-persistence  — T1098.005, Entra ID audit logs,
 *                                         StrongAuthenticationMethod,
 *                                         MFA/device persistence after
 *                                         account compromise
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM 1 — Remote Email Collection & Malicious Inbox Rules (T1114.002)
// ===========================================================================

const remcMailAccessEvent: TelemetryEvent = {
  id: "evt-remc-la1-001",
  ts: "2026-05-14T02:47:33.000Z",
  source: "o365",
  vendor: "Microsoft 365 Unified Audit Log",
  event_type: "cloud_api_call",
  severity: "high",
  user_email: "r.iversen@northgate-logistics.com",
  src_ip: "154.16.93.211",
  geo: { country: "Romania", city: "Bucharest" },
  cloud: {
    provider: "Microsoft",
    service: "Exchange Online",
    api_call: "MailItemsAccessed",
    resource: "r.iversen@northgate-logistics.com",
  },
  description:
    "The Unified Audit Log recorded a MailItemsAccessed bind against r.iversen's Inbox from 154.16.93.211, client string Client=REST;Client=RESTSystem;;.",
  raw: {
    "data.office365.Operation": "MailItemsAccessed",
    "data.office365.RecordType": "50",
    "data.office365.Workload": "Exchange",
    "data.office365.UserId": "r.iversen@northgate-logistics.com",
    "data.office365.UserType": "0",
    "data.office365.ResultStatus": "Succeeded",
    "data.office365.ClientIPAddress": "154.16.93.211",
    "data.office365.ClientInfoString": "Client=REST;Client=RESTSystem;;",
    "data.office365.MailboxOwnerUPN": "r.iversen@northgate-logistics.com",
    "data.office365.MailboxGuid": "9d3f7a12-5b8e-4c61-a2d0-6e1f8c4b7a93",
    "data.office365.LogonType": "0",
    "data.office365.ExternalAccess": "false",
    "data.office365.MailAccessType": "Bind",
    "data.office365.SessionId": "f4a29c6e8b1d47f0a3c5e9b2d6f18a74",
    "data.office365.OrganizationId": "3c9e7a41-2b6d-4f18-9a05-7e4c1b8d3f62",
    "data.office365.Folders[0].Path": "\\Inbox",
    "data.office365.Folders[0].FolderItems[0].InternetMessageId":
      "<DM6PR07MB58340F2A9C1E@DM6PR07MB5834.namprd07.prod.outlook.com>",
    "event.action": "MailItemsAccessed",
    "event.outcome": "success",
  },
};

const remcDelegateEvent: TelemetryEvent = {
  id: "evt-remc-ac1-001",
  ts: "2026-05-08T14:22:10.000Z",
  source: "o365",
  vendor: "Microsoft 365 Unified Audit Log",
  event_type: "cloud_api_call",
  severity: "medium",
  user_email: "j.tan@northgate-logistics.com",
  src_ip: "98.14.22.5",
  geo: { country: "United States", city: "Chicago" },
  cloud: {
    provider: "Microsoft",
    service: "Exchange Online",
    api_call: "MailItemsAccessed",
    resource: "c.reyes@northgate-logistics.com",
  },
  it_verify_result: "confirmed",
  it_verify_message:
    "Helpdesk ticket HD-88213 confirms j.tan (Executive Assistant) was granted Editor delegate access to c.reyes's (CFO) calendar and mailbox folders on 2026-05-02, as part of standard EA onboarding. Delegate access is reviewed quarterly.",
  description:
    "The Unified Audit Log recorded a MailItemsAccessed sync against c.reyes's Inbox performed by j.tan, client string Client=Outlook;Microsoft Office/16.0.17328.",
  raw: {
    "data.office365.Operation": "MailItemsAccessed",
    "data.office365.RecordType": "50",
    "data.office365.Workload": "Exchange",
    "data.office365.UserId": "j.tan@northgate-logistics.com",
    "data.office365.UserType": "0",
    "data.office365.ResultStatus": "Succeeded",
    "data.office365.ClientIPAddress": "98.14.22.5",
    "data.office365.ClientInfoString": "Client=Outlook;Microsoft Office/16.0.17328",
    "data.office365.MailboxOwnerUPN": "c.reyes@northgate-logistics.com",
    "data.office365.MailboxGuid": "1a7c3e92-4f6b-4d81-8e02-9b5f6c1d7a34",
    "data.office365.LogonType": "2",
    "data.office365.ExternalAccess": "false",
    "data.office365.MailAccessType": "Sync",
    "data.office365.SessionId": "8b3e5f91d2a746c0b8e4f1a9d6c37e52",
    "data.office365.OrganizationId": "3c9e7a41-2b6d-4f18-9a05-7e4c1b8d3f62",
    "data.office365.Folders[0].Path": "\\Inbox",
    "event.action": "MailItemsAccessed",
    "event.outcome": "success",
  },
};

const remoteEmailCollectionRoom = {
  id: "remote-email-collection",
  title: "Remote Email Collection & Malicious Inbox Rules",
  description:
    "Learn what an attacker does once they already hold a working session on someone's mailbox — MITRE ATT&CK T1114.002. Covers how remote mail access shows up in the Office 365 Unified Audit Log (MailItemsAccessed, ClientInfoString, Bind vs Sync, SessionId), how attackers build inbox rules that silently forward and delete finance-relevant mail, how to tell a compromised account from a legitimate delegate or migration tool, and the correct order of response for a confirmed Business Email Compromise.",
  difficulty: "intermediate" as const,
  category: "Identity",
  estimatedMinutes: 55,
  xp: 320,
  icon: "📬",
  prerequisites: ["identity-basics", "auth-identity-monitoring"],
  tasks: [
    // ── Reading 1: what T1114.002 is and why attackers want it ────────────
    {
      type: "reading" as const,
      id: "remc-r1",
      heading: "Remote Email Collection: What an Attacker Wants After the Takeover",
      content:
        "Getting into an account — through phishing, a stolen session token, or a reused password — is only step one for an attacker who is after money or intelligence. What they do next, once they can read that mailbox from anywhere in the world, is exactly what MITRE ATT&CK calls T1114.002, Remote Email Collection: using the account's own remote access to a mail server (webmail, an API, a synced client) to search, read, and often export mail without ever touching the victim's actual computer.\n\n" +
        "**The analogy.** Imagine a thief who doesn't need to break into your house at all, because they've copied your postal key and can now open your mailbox from the street corner, at any hour, for as long as nobody notices the key is duplicated. They don't need to be near you. They just need standing access to the box — and a mailbox holds a lot more than most people think: password reset links, financial statements, contract negotiations, and the full back-and-forth of every vendor relationship you have.\n\n" +
        "**Why 'remote' matters as a distinction.** This sub-technique specifically covers collection that rides on the account's normal remote access channels — a browser hitting Outlook Web Access, an API call to Microsoft Graph, a synced mobile client — as opposed to T1114.001, Local Email Collection, which is an attacker rifling through mail files (.pst, .ost, Thunderbird profiles) already sitting on a machine they've compromised locally. The distinction matters operationally: T1114.001 shows up in endpoint/file telemetry, while T1114.002 shows up almost entirely in cloud audit logs — which is exactly the skill this room builds.\n\n" +
        "**What the attacker is actually looking for.** Four goals show up again and again in real incidents: (1) intelligence gathering — reading enough of someone's real conversational style and ongoing business to write a convincing follow-up email, which is what makes a Business Email Compromise (BEC) wire-fraud attempt believable; (2) direct financial fraud — finding an active invoice or wire-transfer thread and inserting themselves into it with changed banking details; (3) credential harvesting — old emails routinely contain other systems' password reset links, shared credentials, or VPN configuration files; (4) reconnaissance for further attacks — an executive's calendar and contact list is a map of who else to target next.\n\n" +
        "**Why this almost never happens without an inbox rule alongside it.** Reading mail live, in real time, requires the attacker to keep coming back — which is risky and slow. Most real intrusions pair the mailbox access with something that keeps working after the attacker logs off: a forwarding rule that quietly copies everything to an address they control. That's this room's second half. But first, you need to be able to read the access itself in the audit log, because a forwarding rule alone tells you mail is leaving — it doesn't tell you whether anyone was actually reading and acting on it before the rule existed.",
    },
    // ── Reading 2: how remote access shows up in the audit log ─────────────
    {
      type: "reading" as const,
      id: "remc-r2",
      heading: "Reading the Unified Audit Log: MailItemsAccessed, ClientInfoString and SessionId",
      content:
        "Every time a mail item is opened, searched, or synced in Microsoft 365 — by any client, human or automated — Exchange Online can record it as a MailItemsAccessed operation in the Office 365 Unified Audit Log. This one operation is the single most useful data source for answering 'did anyone actually read this mailbox, and how.'\n\n" +
        "**The fields that tell you HOW the mailbox was touched.** data.office365.ClientInfoString identifies what actually made the request: a real Outlook desktop client reports something like Client=Outlook;Microsoft Office/16.0, a browser session through Outlook Web Access reports Client=OWA, and — critically — an application or script calling the Exchange or Graph REST API directly reports Client=REST;Client=RESTSystem;; with no human-facing client name at all. Seeing that REST string doesn't automatically mean something is wrong (plenty of legitimate tools, including Microsoft's own compliance search, use it), but it does tell you a program made the request, not a person clicking through a mail client.\n\n" +
        "**The field that tells you HOW MUCH was touched, in what shape.** data.office365.MailAccessType is either Bind or Sync. Sync is what a normal mail client does on startup or on a schedule — pulling a whole folder's worth of items in one operation, the way Outlook or a phone's mail app behaves. Bind means one specific item was accessed by its own individual request. A handful of Bind records is completely unremarkable — a person opening a few emails one at a time looks exactly like this. Many dozens of Bind records against different messages, packed into a few minutes, is a different shape entirely: that's what a script looks like when it iterates through a mailbox message by message, which a human simply doesn't do.\n\n" +
        "**The field that ties everything together.** data.office365.SessionId is shared across every audit record generated within the same authenticated session — a sign-in event, every MailItemsAccessed record that follows, and any inbox rule that gets created, all carry the identical SessionId if they happened in the same session. This is what lets an analyst reconstruct the whole story instead of looking at one isolated record: pull every event on that SessionId, in order, and you can see exactly when the session started, from where, and everything it did afterward.\n\n" +
        "**LogonType tells you whose access this is.** A value of Owner means the account is accessing its own mailbox. Delegate means someone else, with a granted delegate relationship, is accessing it (an executive assistant reading their boss's inbox, for example) — and Admin covers administrative or service-account access. None of these three is inherently suspicious on its own; what matters is whether the LogonType matches a relationship you'd actually expect, which Reading 5 covers in depth.",
      diagram:
        "sequenceDiagram\n" +
        "  participant A as Sign-in event\n" +
        "  participant M as MailItemsAccessed\n" +
        "  participant R as New-InboxRule\n" +
        "  Note over A,R: All three share the same SessionId\n" +
        "  A->>M: Session authenticated, SessionId issued\n" +
        "  M->>M: Mailbox items Bound/Synced under that SessionId\n" +
        "  M->>R: Same SessionId creates a forwarding rule\n" +
        "  Note over R: Pulling every record on one SessionId\n" +
        "  Note over R: reconstructs the full sequence of actions\n",
      diagramCaption: "Reconstructing one session's actions via SessionId",
      checkpoint: {
        question: "What does a MailAccessType of 'Bind' indicate, as opposed to 'Sync'?",
        options: [
          "Bind means a whole folder's worth of items was pulled in one operation, like a mail client starting up",
          "Bind means one specific item was accessed by its own individual request -- many Bind records in a short window can indicate a script iterating message by message",
          "Bind and Sync are two names for the exact same operation",
          "Bind means the item was permanently deleted after being read",
        ],
        answer: 1,
        explanation:
          "Sync is a whole-folder pull, the way a mail client behaves on startup. Bind is a per-item access -- a handful is unremarkable, but many dozens packed into a few minutes is the shape of automated iteration, not a person reading email one message at a time.",
      },
    },
    // ── Question 1 (applied — MITRE technique ID) ───────────────────────────
    {
      type: "question" as const,
      id: "remc-q1",
      question:
        "An attacker has obtained a valid, already-authenticated session token for a victim's mailbox — no password needed — and uses it through the Exchange REST API to search the Inbox for wire-transfer instructions. Which MITRE ATT&CK sub-technique best describes this specific action?",
      options: [
        "T1114.001, Local Email Collection — reading mail files already stored on a compromised endpoint",
        "T1114.002, Remote Email Collection — using the account's own remote access channel (here, an API) to read mail without touching the victim's device",
        "T1071, Application Layer Protocol — a technique describing command-and-control traffic, not mailbox access",
        "T1556, Modify Authentication Process — a technique describing tampering with how authentication itself is validated",
      ],
      answer: 1,
      explanation:
        "This is exactly T1114.002: the attacker never touches the victim's own computer or local mail files (which would be T1114.001) — they ride the account's existing remote access surface, here an API call, to read mail from anywhere. T1071 describes command-and-control communication patterns, not mailbox collection, and T1556 describes attacks against the authentication mechanism itself (like registering a rogue MFA method), which is a different technique covered in this platform's device-registration-persistence room.",
      xp: 20,
    },
    // ── Reading 3: malicious inbox rules ────────────────────────────────────
    {
      type: "reading" as const,
      id: "remc-r3",
      heading: "Malicious Inbox Rules: How Attackers Make Access Outlast the Login",
      content:
        "Once an attacker has read enough of a mailbox to understand what's valuable, most real intrusions add a rule that keeps working long after the attacker's session ends — turning a one-time access into a standing collection pipeline. The Exchange PowerShell operation behind this, logged in the Unified Audit Log as New-InboxRule (or Set-InboxRule when an existing rule is modified), takes a set of parameters worth knowing individually.\n\n" +
        "**ForwardTo vs RedirectTo — a distinction that matters.** ForwardTo sends a copy of matching mail to another address while still delivering the original to the mailbox — the owner might eventually notice a duplicate-looking thread if they look closely. RedirectTo is quieter: it sends matching mail to the other address and never delivers it to the original mailbox at all, so there is no copy left behind to notice unless the owner is specifically looking for missing mail.\n\n" +
        "**DeleteMessage:true closes the loop.** Paired with ForwardTo, this parameter deletes the original message immediately after it's forwarded — turning what would have been a visible duplicate into nothing the owner ever sees. This single parameter is one of the strongest signals in this whole reading: a legitimate business-forwarding rule essentially never needs to delete the owner's own copy of their own mail.\n\n" +
        "**StopProcessingRules:true skips everything else.** Exchange evaluates inbox rules in order; a rule with this flag set stops any later rule — including ones a security team might have added specifically to flag suspicious forwarding — from ever running against a message that already matched.\n\n" +
        "**Keyword scoping targets the valuable mail specifically.** Rules are frequently scoped with conditions like SubjectContainsWords for terms like 'invoice,' 'wire,' 'ACH,' or 'payment' — so the rule only fires on financially relevant threads instead of flooding the attacker's inbox (and the audit log) with every piece of mail the account receives. A narrowly-scoped rule is not a safer rule; it is a more deliberately targeted one.\n\n" +
        "**A separate, mailbox-level mechanism exists too.** Set-Mailbox with the -ForwardingSmtpAddress parameter configures automatic forwarding at the mailbox level, entirely outside of any inbox rule — it applies to every message, has no rule-matching logic, and is checked and logged completely differently. Many security teams that only hunt New-InboxRule miss this second forwarding path entirely, so both belong on a hunt checklist, not just one.\n\n" +
        "**A realistic lookalike domain.** Attackers rarely forward to an address that announces itself. A forwarding target like ap-invoices@northgate-logisitics.com — one character off from the real northgate-logistics.com — is designed to pass a glance from anyone who isn't checking character by character, which is precisely why domain comparison has to be deliberate, not a skim.",
    },
    // ── Question 2 (applied — inbox rule parameter combination) ────────────
    {
      type: "question" as const,
      id: "remc-q2",
      question:
        "A New-InboxRule audit record shows: ForwardTo -> ap-invoices@northgate-logisitics.com (note the extra 'i'), DeleteMessage -> true, StopProcessingRules -> true, scoped to SubjectContainsWords: 'wire, invoice, ACH'. What makes this specific combination especially dangerous, beyond simply having an external forward?",
      options: [
        "DeleteMessage:true erases the mailbox owner's copy after forwarding, and StopProcessingRules:true prevents any other rule — including a security team's own detection rule — from ever evaluating the same message, so the owner never sees it and no downstream rule gets a chance to flag it",
        "ForwardTo rules pointed at any domain outside the tenant are automatically rejected by Exchange Online's default configuration, so this specific rule could never have actually taken effect",
        "The keyword scoping to 'wire, invoice, ACH' makes the rule easier for Exchange to detect and auto-quarantine, since narrowly-scoped rules are held to stricter review than broad ones",
        "StopProcessingRules is a display-only audit flag with no functional effect on which rules actually evaluate a given message",
      ],
      answer: 0,
      explanation:
        "Reading 3 covered exactly this combination: DeleteMessage removes the evidence from the owner's own mailbox, and StopProcessingRules skips every rule evaluated after this one — including a defensive rule a security team might have added. Exchange Online does not block external ForwardTo by default (many organizations explicitly allow it for business reasons, which is why this can slip through). Narrow keyword scoping doesn't reduce danger — it means the attacker deliberately targeted the financially relevant subset of mail rather than everything, which is more purposeful, not less.",
      xp: 25,
    },
    // ── Matching: operations/parameters to meaning ──────────────────────────
    {
      type: "matching" as const,
      id: "remc-m1",
      heading: "Match the Field or Operation to What It Actually Means",
      instructions: "Match each Exchange/Unified-Audit-Log term to what it records or controls.",
      pairs: [
        { id: "newinboxrule", left: "New-InboxRule", right: "Exchange operation logged whenever any inbox rule — forwarding, moving, or deleting mail — is created" },
        { id: "forwardto", left: "ForwardTo parameter", right: "Sends a copy of matching mail elsewhere while still delivering the original to the mailbox" },
        { id: "redirectto", left: "RedirectTo parameter", right: "Sends matching mail elsewhere and never delivers it to the original mailbox at all" },
        { id: "deletemsg", left: "DeleteMessage:true", right: "Removes the original message after the rule processes it, so no copy is left for the owner to notice" },
        { id: "fwdsmtp", left: "Set-Mailbox -ForwardingSmtpAddress", right: "A mailbox-level auto-forward applying to ALL mail, configured entirely outside of any inbox rule" },
        { id: "mailitemsaccessed", left: "MailItemsAccessed", right: "Unified Audit Log operation recording every time a mail item is opened or bound to, by any client" },
        { id: "sessionid", left: "SessionId", right: "Shared identifier letting an analyst pull every audit record — sign-in, mailbox access, rule creation — from the same authenticated session" },
      ],
      explanation:
        "Notice how many separate mechanisms exist for the same underlying goal — getting mail out of a mailbox without the owner noticing. A hunt that only checks New-InboxRule's ForwardTo parameter misses RedirectTo, misses the mailbox-level ForwardingSmtpAddress path entirely, and misses the read-access evidence that MailItemsAccessed and SessionId together provide.",
      xp: 30,
    },
    // ── Reading 4: correlating sign-in, access and rule creation ────────────
    {
      type: "reading" as const,
      id: "remc-r4",
      heading: "Correlating the Session, Not Just the Event",
      content:
        "A single MailItemsAccessed record, by itself, is almost never enough to act on. People read their own email constantly; that's the entire point of having a mailbox. The investigative value comes from correlating that record against everything else that happened in the same session and against what's normal for that specific account — not from treating any one log line as a verdict.\n\n" +
        "**Start from the SessionId, then widen.** Pull every Unified Audit Log record sharing the SessionId of the event you're reviewing. If a sign-in, a burst of MailItemsAccessed records, and a New-InboxRule creation all share one SessionId within a few minutes of each other, you're looking at one continuous, purposeful sequence of actions by whoever held that session — not three unrelated coincidences.\n\n" +
        "**Compare the sign-in's origin against the account's actual baseline.** Most organizations have a small, known set of legitimate egress points — a corporate VPN's static IP, a specific office's public address range. A sign-in on the same SessionId as the mailbox activity, sourced from a geography or network the account has never used before, is one of the most reliable single signals available, especially when it lines up with an odd hour for that user's normal working pattern.\n\n" +
        "**Read the shape of the access, not just its existence.** Reading 2 already covered Bind vs Sync — a burst of many Bind records against different messages in a short window looks like automated collection; a handful of Bind records spread naturally through a workday looks like a person. Apply that same shape-reading here, alongside the SessionId correlation, rather than treating any single MailItemsAccessed record as inherently meaningful.\n\n" +
        "**Recognize the legitimate patterns before you escalate.** Delegate and Admin LogonType values tied to a known relationship (an assistant, a compliance tool, a migration service account) are routine and should not trigger the same response as an Owner-type access from an unfamiliar location. Reading 5 builds this out fully, but the short version: context — ticket references, known device fingerprints, expected working hours — is what turns 'mailbox was accessed' into either 'nothing to see here' or 'this needs containment,' and skipping that context in either direction is a mistake.\n\n" +
        "**Why this reading exists before the log analysis exercise.** The task that follows gives you a single MailItemsAccessed record plus the surrounding session facts in the narrative — exactly the way a real investigation actually presents itself. You won't be handed a verdict field; you'll be handed the same pieces described here, and asked to reason through them the way this reading just walked through.",
      checkpoint: {
        question: "Per Reading 4, why is a single MailItemsAccessed record almost never enough to act on by itself?",
        options: [
          "Because MailItemsAccessed records are frequently corrupted during ingestion",
          "Because people read their own email constantly -- the investigative value comes from correlating the record against everything else in the same session and against what's normal for that account",
          "Because MailItemsAccessed only logs failed access attempts, never successful ones",
          "Because Microsoft deprecated this operation in favor of SessionId-only logging",
        ],
        answer: 1,
        explanation:
          "Reading a mailbox is the entire point of having one, so a single record is unremarkable on its own -- the finding comes from correlating it via SessionId against the sign-in origin, the access shape, and what's normal for that specific account.",
      },
    },
    // ── Log Analysis: the REST-driven bulk mailbox access ───────────────────
    {
      type: "log_analysis" as const,
      id: "remc-la1",
      heading: "One MailItemsAccessed Record, and the Session Around It",
      context:
        "Northgate Logistics' SIEM flagged an anomaly on r.iversen@northgate-logistics.com's mailbox. Pulling the full Unified Audit Log for this event's SessionId shows the exact same record repeated 24 times inside a four-minute window, each one against a different InternetMessageId in the Inbox and Sent Items folders. Nine minutes before the first of these records, the same SessionId appears on an Exchange Online sign-in event; the only corporate VPN egress Northgate has on file is a single static address in Chicago, Illinois, and no employee on the finance team is assigned to travel. Per the asset inventory, r.iversen's own laptop has never generated an interactive session outside business hours in the eleven months since it was issued. Review the single representative record below.",
      event: remcMailAccessEvent,
      questions: [
        {
          question:
            "data.office365.ClientInfoString reads 'Client=REST;Client=RESTSystem;;' rather than a recognizable Outlook or OWA client string. What does that tell you about how this mailbox item was accessed?",
          options: [
            "It confirms an Outlook desktop client cached the message locally, which is what this string always indicates",
            "It means the access came through a script or application calling the Exchange/Graph REST API directly, not a human clicking through a mail client",
            "It means the mailbox is a shared mailbox and multiple people are reading it simultaneously",
            "It's a formatting artifact with no operational meaning — every ClientInfoString value is functionally identical",
          ],
          answer: 1,
          explanation:
            "As Reading 2 covered, Client=REST;Client=RESTSystem;; specifically identifies programmatic API access, distinct from the Outlook or OWA strings a human-facing client reports. It says nothing about shared mailboxes on its own, and ClientInfoString values are meaningfully different from each other — that's the entire reason the field exists.",
          xp: 30,
        },
        {
          question:
            "data.office365.MailAccessType reads 'Bind' rather than 'Sync', and the same SessionId produced 24 near-identical Bind records within four minutes, each against a different message. What does that combination indicate?",
          options: [
            "Bind means Outlook is performing its normal full-folder sync on startup, so 24 records like this in four minutes is routine client behavior that needs no further look",
            "Bind means each record represents one individual item pulled by its own separate request — 24 separate Binds in four minutes is consistent with a script iterating through the mailbox message by message, not a person reading email",
            "Bind vs Sync is purely a display setting controlling folder view options and carries no information about whether a human or a script made the request",
            "Bind means the accessed item was permanently and irreversibly deleted from the mailbox the moment this record was generated",
          ],
          answer: 1,
          explanation:
            "Reading 2 drew exactly this distinction: Sync is the folder-level pull a normal mail client performs; Bind is a per-item access. Two dozen Bind records against different messages inside four minutes is the shape of automated iteration, not a person opening emails one at a time — a human reading 24 separate emails that quickly, each triggering its own distinct API bind, would be an unusual reading pace even before considering anything else in this session.",
          xp: 30,
        },
        {
          question:
            "The SessionId on this record also appears on a sign-in nine minutes earlier, sourced from outside the only known corporate VPN egress (a single static Chicago IP), on an account whose laptop has never shown after-hours activity in eleven months. Based on Reading 4, what should you do first?",
          options: [
            "Close the alert — a MailItemsAccessed record on its own is routine mailbox traffic, and the surrounding facts described in this scenario don't change that conclusion",
            "Treat this as likely session or account compromise: pull every audit record on this SessionId, check specifically for a New-InboxRule created around the same time, and begin containment (revoke the session) while you confirm the full scope",
            "Immediately delete r.iversen's mailbox entirely so that no further message can possibly be accessed by anyone",
            "Email r.iversen directly at their own address and wait for them to confirm or deny recognizing this specific sign-in before taking any other action",
          ],
          answer: 1,
          explanation:
            "This is exactly the correlation Reading 4 built toward: an unfamiliar sign-in origin, an access shape consistent with automation, and both sharing one SessionId together are far more significant than any one fact alone — the correct move is containment plus scoping, not dismissal. Deleting the mailbox destroys evidence and the owner's legitimate mail. Emailing the account directly risks tipping off whoever currently holds that session if the account itself is compromised — exactly the mistake called out in this room's response-ordering task.",
          xp: 35,
        },
      ],
    },
    // ── Ordering: BEC response sequence ─────────────────────────────────────
    {
      type: "ordering" as const,
      id: "remc-o1",
      heading: "Order the Response to a Confirmed Business Email Compromise",
      instructions: "Arrange these response steps in the order they should actually happen once mailbox compromise is confirmed.",
      items: [
        { id: "contain", text: "Revoke all active sessions and refresh tokens for the account immediately" },
        { id: "reset", text: "Reset the account password and force re-registration of MFA methods" },
        { id: "rule", text: "Locate and remove the malicious inbox rule (or mailbox-level ForwardingSmtpAddress) so no further mail leaves silently" },
        { id: "scope", text: "Pull the full mailbox audit trail on the compromised SessionId(s) to determine exactly what was read, forwarded, or deleted" },
        { id: "notify", text: "Notify affected counterparties (finance, vendors) if wire-fraud-relevant emails were exposed or a fraudulent payment instruction may have gone out" },
        { id: "document", text: "Document the full timeline and findings for the incident report" },
      ],
      correct_order: ["contain", "reset", "rule", "scope", "notify", "document"],
      explanation:
        "Revoking the live session comes first because — as covered in Identity Basics — a password reset alone does not invalidate a session token already issued; skip this step and the attacker's already-open session keeps working through everything that follows. Removing the inbox rule before containing the session is backwards too: an attacker with a still-live session can simply recreate a removed rule in seconds. Only after access is actually cut off does it make sense to scope the damage, notify anyone financially exposed, and write it all up.",
      xp: 30,
    },
    // ── Reading 5: legitimate remote mailbox access ─────────────────────────
    {
      type: "reading" as const,
      id: "remc-r5",
      heading: "Legitimate Remote Mailbox Access — Delegates, Migrations, and Mobile Sync",
      content:
        "Most MailItemsAccessed records an analyst reviews are completely legitimate, and the goal of this reading is to make sure you can recognize the routine cases quickly instead of escalating every single one — a SOC that treats every mailbox access as suspicious teaches itself to ignore the alert entirely by the time a real one arrives.\n\n" +
        "**Delegate and Admin access with a known relationship.** An executive assistant with LogonType Delegate reading their manager's mailbox, or an IT admin with LogonType Admin performing a documented task, is exactly what those relationships are for. The check that matters is whether the relationship itself is real and current — does a ticket or an access grant record actually show this person has (or recently received) that delegation, and does the access pattern match what that role would plausibly need?\n\n" +
        "**Mobile and multi-device sync.** A phone's mail app or a new laptop performing an initial Sync (not Bind) shortly after being set up is routine, especially from a known device fingerprint or a corporate-managed network. The Sync/Bind distinction from Reading 2 does real work here — a new client pulling a folder's worth of mail on first launch is expected; the same client repeatedly Binding to individual items in unusual bursts, weeks after setup, is not.\n\n" +
        "**Migration and compliance service accounts.** Mailbox migrations, backup tools, and eDiscovery/compliance searches all use service accounts — often named in a recognizable pattern (a 'svc-' prefix, for example) — that legitimately touch large volumes of mail, frequently outside business hours, as part of a scheduled or ticketed operation. High volume alone, from an account like this, is expected; the same volume from a human user's individual account is the anomaly.\n\n" +
        "**The questions that separate routine from suspicious.** Does the LogonType match a relationship you can actually verify? Does the ClientInfoString and IP match a device or service this account is known to use? Is there a change ticket, onboarding record, or scheduled job that explains the timing? Is the access shape (Sync vs repeated Bind, volume, hours) consistent with what that role or tool would normally do? None of these questions can be answered from a single field in isolation — which is exactly why the analyst_choice task that follows gives you the same kind of surrounding context this reading described, for you to weigh yourself.",
    },
    // ── Analyst Choice: legitimate EA delegate access ───────────────────────
    {
      type: "analyst_choice" as const,
      id: "remc-ac1",
      heading: "Verdict: An Assistant Accessing the CFO's Mailbox",
      scenario:
        "A MailItemsAccessed record shows j.tan (Executive Assistant) accessing c.reyes's (CFO) Inbox. Any non-owner access to a CFO's mailbox is exactly the kind of high-value target this room has been teaching you to watch for — review the record before deciding how to handle it.",
      event: remcDelegateEvent,
      correct_verdict: "false_positive",
      explanation:
        "data.office365.LogonType is '2' (Delegate), not '0' (Owner) — this is someone else accessing the mailbox through a granted relationship, not the account itself being used to read its own mail from an unexpected place. data.office365.MailAccessType is 'Sync', the normal behavior of a real Outlook desktop client pulling its assigned folder, not the repeated per-item Bind pattern this room's log analysis task associated with automated collection. The source IP matches Northgate's only known corporate egress, and it_verify_result confirms Helpdesk ticket HD-88213 authorizing exactly this delegate relationship as part of standard EA onboarding.",
      fp_trap:
        "Non-owner access to an executive's mailbox is precisely the pattern that gets escalated on reflex — it looks, at a glance, like exactly what this room has spent several readings teaching you to catch. But LogonType Delegate, MailAccessType Sync, a matching corporate IP, and a confirmed ticket are the specific fields that separate this from the compromised-account pattern in the log analysis task. Escalating every instance of a non-owner touching a VIP mailbox, without checking these fields, trains a team to drown in noise on exactly the accounts that most need real attention when something is actually wrong.",
      xp: 30,
    },
    // ── Question 3 (applied — proportionate response) ───────────────────────
    {
      type: "question" as const,
      id: "remc-q3",
      question:
        "An analyst sees a single MailItemsAccessed Bind record from a known corporate IP during business hours, with no accompanying New-InboxRule, no sign-in anomaly on the SessionId, and a LogonType consistent with the account's owner. What is the appropriate response?",
      options: [
        "Escalate immediately as a confirmed Business Email Compromise, matching the severity of the log analysis exercise",
        "Treat it as routine mailbox activity unless further correlated evidence appears — a single, unremarkable MailItemsAccessed record on its own does not warrant escalation",
        "Disable the account preventively regardless of the evidence, since mailbox access always carries some risk",
        "Permanently stop reviewing any future MailItemsAccessed events from this user, since this one turned out to be fine",
      ],
      answer: 1,
      explanation:
        "Reading 4 was explicit that a single MailItemsAccessed record is almost never enough to act on by itself — people read their own mail constantly, and this record has none of the correlating signals (rule creation, sign-in anomaly, unusual access shape) that made the log analysis case worth escalating. Disabling the account on no real evidence and permanently ignoring future events from this user are both overcorrections in opposite directions — proportionate response means neither escalating everything nor tuning out a source entirely.",
      xp: 20,
    },
    // ── Query Fill: hunt for external forwarding ─────────────────────────────
    {
      type: "query_fill" as const,
      id: "remc-qf1",
      heading: "Write It Yourself: Hunt for Externally-Forwarding Inbox Rules",
      language: "kql" as const,
      context:
        "Detection engineering wants a daily hunt across the OfficeActivity table for any inbox rule that forwards or redirects mail externally, instead of relying on a single canned alert to catch every case. Fill in the operation name and both forwarding parameters from Reading 3.",
      template:
        "OfficeActivity\n| where OfficeWorkload == \"Exchange\"\n| where Operation == \"{{operation}}\"\n| where Parameters has \"{{param1}}\" or Parameters has \"{{param2}}\"\n| project TimeGenerated, UserId, ClientIP, Parameters",
      blanks: [
        { id: "operation", answers: ["New-InboxRule"], placeholder: "Exchange operation name" },
        { id: "param1", answers: ["ForwardTo"], placeholder: "forwarding parameter that keeps a copy" },
        { id: "param2", answers: ["RedirectTo"], placeholder: "forwarding parameter that keeps no copy" },
      ],
      explanation:
        "New-InboxRule is the operation logged for any inbox rule creation. Checking for both ForwardTo and RedirectTo matters because they behave differently — ForwardTo leaves a copy in the mailbox, RedirectTo doesn't — and a hunt that only checks one of the two, as Reading 3 pointed out, misses the quieter of the two mechanisms entirely.",
      xp: 25,
    },
    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "remc-f1",
      prompt:
        "Look at the Log Analysis finding on r.iversen's mailbox. What is the exact value of the data.office365.SessionId field in the raw log?",
      answer: "f4a29c6e8b1d47f0a3c5e9b2d6f18a74",
      hint: "Look inside the raw block of the log analysis event for the field named data.office365.SessionId.",
      xp: 20,
    },
    // ── Question 4 (applied — tokens survive password reset) ────────────────
    {
      type: "question" as const,
      id: "remc-q4",
      question:
        "IR resets r.iversen's password and forces a global sign-out, but has not yet separately revoked the specific session/refresh token that was already used to read mail and could still be used to create an inbox rule. Based on Identity Basics and this room, what is the most accurate statement?",
      options: [
        "Resetting the password alone is sufficient — passwords and active sessions are the same thing in Microsoft 365",
        "A password reset does not automatically invalidate a session token that was issued before the reset; the token must be explicitly revoked, or a still-live session may keep working",
        "Sessions expire automatically the instant a password changes, in every identity system, with no exceptions",
        "None of this matters, because MailItemsAccessed only ever shows read access and can never lead to real financial harm",
      ],
      answer: 1,
      explanation:
        "This is the exact lesson carried over from Identity Basics: a token represents a login that already happened, and it is honored on its own until it expires or is explicitly revoked — a password change doesn't retroactively invalidate something issued before the change. 'Global sign-out' and an explicit session/token revocation are related but not automatically guaranteed to be the same completed action depending on the platform's exact remediation flow, which is exactly why this room's ordering task puts session revocation as its own first step rather than folding it silently into 'reset the password.'",
      xp: 25,
    },
  ],
};

// ===========================================================================
// ROOM 2 — Device Registration Abuse & MFA Persistence (T1098.005)
// ===========================================================================

const devregRogueRegistrationEvent: TelemetryEvent = {
  id: "evt-devreg-la1-001",
  ts: "2026-03-11T09:44:00.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "account_modify",
  severity: "critical",
  mitre_technique: "T1098.005",
  user_email: "m.delgado@nexacorp.com",
  src_ip: "91.132.139.204",
  geo: { country: "Germany", city: "Frankfurt" },
  description:
    "A second Microsoft Authenticator method was registered on m.delgado's account. Compare the actor performing the registration to the account it was registered on, and check whether the registering session carried a directory role.",
  raw: {
    "azure.auditlogs.category": "AuditLogs",
    "azure.auditlogs.operationName": "User registered security info",
    "azure.auditlogs.properties.activityDisplayName": "User registered security info",
    "azure.auditlogs.properties.activityDateTime": "2026-03-11T09:44:00.000Z",
    "azure.auditlogs.properties.category": "UserManagement",
    "azure.auditlogs.properties.loggedByService": "Authentication Methods",
    "azure.auditlogs.properties.operationType": "Update",
    "azure.auditlogs.properties.result": "success",
    "azure.auditlogs.properties.resultReason": "User registered security info: Microsoft Authenticator app",
    "azure.auditlogs.properties.correlationId": "8b05d7c4-1a69-4e38-9f27-c40e6b91a53d",
    "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": "m.delgado@nexacorp.com",
    "azure.auditlogs.properties.initiatedBy.user.id": "b8f42a09-6d31-4c7e-9a15-3e0c8b71d4f2",
    "azure.auditlogs.properties.initiatedBy.user.ipAddress": "91.132.139.204",
    "azure.auditlogs.properties.initiatedBy.user.roles": [],
    "azure.auditlogs.properties.targetResources[0].type": "User",
    "azure.auditlogs.properties.targetResources[0].userPrincipalName": "m.delgado@nexacorp.com",
    "azure.auditlogs.properties.targetResources[0].id": "b8f42a09-6d31-4c7e-9a15-3e0c8b71d4f2",
    "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
    "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue":
      "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
    "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue":
      "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true},{\"MethodType\":\"PhoneAppNotification\",\"Default\":false}]",
    "event.action": "user-registered-security-info",
    "event.outcome": "success",
    "source.ip": "91.132.139.204",
  },
};

const devregLegitimateRegistrationEvent: TelemetryEvent = {
  id: "evt-devreg-ac1-001",
  ts: "2026-02-18T11:05:00.000Z",
  source: "o365",
  vendor: "Microsoft Entra ID",
  event_type: "account_modify",
  severity: "medium",
  mitre_technique: "T1098.005",
  user_email: "p.oduya@nexacorp.com",
  src_ip: "82.80.14.6",
  geo: { country: "Israel", city: "Tel Aviv" },
  it_verify_result: "confirmed",
  it_verify_message:
    "Helpdesk ticket HD-51142: p.oduya reported her phone was replaced under the corporate device-upgrade program and called in to confirm the correct steps for re-registering Microsoft Authenticator on the new device.",
  description:
    "A second Microsoft Authenticator registration was added on p.oduya's account from the corporate network during business hours.",
  raw: {
    "azure.auditlogs.category": "AuditLogs",
    "azure.auditlogs.operationName": "User registered security info",
    "azure.auditlogs.properties.activityDisplayName": "User registered security info",
    "azure.auditlogs.properties.activityDateTime": "2026-02-18T11:05:00.000Z",
    "azure.auditlogs.properties.category": "UserManagement",
    "azure.auditlogs.properties.loggedByService": "Authentication Methods",
    "azure.auditlogs.properties.operationType": "Update",
    "azure.auditlogs.properties.result": "success",
    "azure.auditlogs.properties.resultReason": "User registered security info: Microsoft Authenticator app",
    "azure.auditlogs.properties.correlationId": "2f6a9d31-7c48-4b16-a3e5-1d9f7b2c8e40",
    "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": "p.oduya@nexacorp.com",
    "azure.auditlogs.properties.initiatedBy.user.id": "c4e91a7d-3f5b-4e02-9d16-8a2c7f4b9e01",
    "azure.auditlogs.properties.initiatedBy.user.ipAddress": "82.80.14.6",
    "azure.auditlogs.properties.initiatedBy.user.roles": [],
    "azure.auditlogs.properties.targetResources[0].type": "User",
    "azure.auditlogs.properties.targetResources[0].userPrincipalName": "p.oduya@nexacorp.com",
    "azure.auditlogs.properties.targetResources[0].id": "c4e91a7d-3f5b-4e02-9d16-8a2c7f4b9e01",
    "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
    "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue":
      "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
    "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue":
      "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":false},{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
    "event.action": "user-registered-security-info",
    "event.outcome": "success",
    "source.ip": "82.80.14.6",
  },
};

const deviceRegistrationPersistenceRoom = {
  id: "device-registration-persistence",
  title: "Device Registration Abuse & MFA Persistence",
  description:
    "Learn MITRE ATT&CK T1098.005 — how an attacker who already holds a working, MFA-satisfied session registers their own authentication method or device against the account, turning a one-time compromise into standing access that survives a password reset. Covers Entra ID audit log fields (User registered security info, StrongAuthenticationMethod, targetResources, initiatedBy), how to tell self-service abuse from routine device changes, and why removing the rogue method is its own required remediation step.",
  difficulty: "intermediate" as const,
  category: "Identity",
  estimatedMinutes: 55,
  xp: 320,
  icon: "📲",
  prerequisites: ["identity-basics", "auth-identity-monitoring"],
  tasks: [
    // ── Reading 1: what device/MFA registration persistence is ─────────────
    {
      type: "reading" as const,
      id: "devreg-r1",
      heading: "Account Manipulation: Why Registering a Device Beats Stealing Another Password",
      content:
        "MITRE ATT&CK groups a family of techniques under T1098, Account Manipulation — attacks where the goal isn't gaining initial access, but modifying an account so the attacker's access outlasts whatever got them in the first place. T1098.005, Device Registration, is the specific version of this aimed at identity providers like Microsoft Entra ID: once an attacker has any working, already-authenticated session on an account, they register a new authentication method (an Authenticator app entry, a phone number) or a whole device object against that account, so the identity provider will treat their own device or app as a legitimate factor going forward.\n\n" +
        "**The analogy.** Picture a burglar who gets into your house once, and instead of just taking a spare key, quietly programs their own key into your smart lock's system alongside your existing ones. You can change the front lock's primary code all you want — their programmed key still opens the door, because you changed the wrong thing. Removing their key specifically is the only fix; changing the lock's public code does nothing to a key that was separately added to the approved list.\n\n" +
        "**Why an attacker bothers.** Getting into an account once is often the easy part — a phishing click, a stolen session cookie from an adversary-in-the-middle proxy, a password reused from another breach. The hard part, from the attacker's perspective, is staying in once the obvious signs of compromise get investigated. The single most predictable first remediation step any SOC takes is resetting the compromised account's password. Registering their own authentication method is a direct, deliberate answer to that exact step — because as Reading 3 covers in detail, a password reset by itself does not touch a separately-registered authentication method at all.\n\n" +
        "**Where this fits relative to other persistence techniques.** T1098 has several siblings worth knowing apart: T1098.001 covers adding illegitimate credentials to a cloud account, T1098.002 covers abusing Exchange delegation to add a mailbox permission, T1098.003 covers adding an owner to an application, and T1098.004 covers adding an SSH key. T1098.005 is specifically about the identity provider's own authentication factors and device objects — which is exactly why it matters so much for anyone investigating an account takeover in a modern, MFA-protected environment: the MFA that was supposed to stop the attacker becomes, once they've registered their own factor, exactly what lets them come back.\n\n" +
        "**This connects directly to real scenario telemetry on this platform.** In the AiTM Token Theft scenario, event aitm_12_mfa_register fires this precise technique nineteen minutes after a stolen session is replayed — a second Microsoft Authenticator method appears on the victim's account, registered by a session that itself never had to solve a fresh MFA challenge, because the replayed session already carried a prior MFA claim. This room teaches you to read that exact class of event.",
      checkpoint: {
        question: "Per Reading 1, why does registering a new authentication method specifically defeat a password reset as remediation?",
        options: [
          "Because Entra ID enforces a mandatory 24-hour delay between a password reset request and the reset actually taking effect on the account",
          "Because the registered method is a separate object on the account that a password reset does not touch at all -- like a burglar's own key added to a smart lock, changing the front lock's code doesn't remove their key",
          "Because Entra ID blocks any password reset attempt on an account flagged as compromised until an administrator manually clears the flag",
          "Because every registered MFA method is automatically set to expire 90 days after a password change, under Entra ID's default authentication policy",
        ],
        answer: 1,
        explanation:
          "The analogy in Reading 1 is exact: registering a new authentication method is like a burglar programming their own key into the smart lock -- changing the lock's primary code (the password reset) does nothing to a key that was separately added to the approved list.",
      },
    },
    // ── Reading 2: how registration happens, the fields that prove it ──────
    {
      type: "reading" as const,
      id: "devreg-r2",
      heading: "Self-Service Registration and the Entra ID Audit Fields That Prove It",
      content:
        "Modern identity providers deliberately make it easy for users to manage their own authentication methods, because forcing every phone upgrade or lost device through a helpdesk ticket doesn't scale. In Entra ID, any user with a valid, already-signed-in session can open their My Security Info page and add a new method — an Authenticator app entry, a phone number, a FIDO2 key — with no administrator involved at all. This self-service model is exactly what makes T1098.005 possible: it doesn't require the attacker to trick or compromise an admin, only to already be holding a working session, however they got it.\n\n" +
        "**The operation name to know.** Entra ID's audit log records this as 'User registered security info', with category 'UserManagement' and loggedByService 'Authentication Methods'. The specific property that changed is captured under targetResources[].modifiedProperties[], with displayName 'StrongAuthenticationMethod' — and its oldValue and newValue hold the complete list of registered methods before and after, as a JSON array of objects like {\"MethodType\":\"PhoneAppNotification\",\"Default\":true}. Comparing the two arrays directly is how you see exactly what was added, rather than guessing from the operation name alone.\n\n" +
        "**Who did it — initiatedBy.** Every audit record carries an initiatedBy.user block identifying who actually performed the action, including their id, userPrincipalName, ipAddress, and roles. When initiatedBy.user.id matches the id under targetResources[] — the same identity is listed as both actor and target — that's self-service: whoever was signed in as the account registered a method for that same account. When initiatedBy.user.roles instead shows something like Authentication Administrator or Helpdesk Administrator, an admin performed or assisted the registration on someone else's behalf, typically as part of a documented support interaction.\n\n" +
        "**A second, separate operation worth distinguishing.** Entra ID also logs 'Register device' and 'Add registered owner to device' under category 'DeviceManagement' — these add an entire device object to the tenant, not an authentication method. A registered or joined device can independently satisfy Conditional Access policies that require a compliant or hybrid-joined device, which is a different persistence surface than an authentication method entirely. An attacker could pursue either path, or both, depending on which Conditional Access controls actually gate access at a given organization.\n\n" +
        "**correlationId ties one operation's records together.** When a single user action produces multiple related audit entries, they share a correlationId — useful for confirming that a registration happened as one coherent action rather than being pieced together from unrelated events days apart.",
    },
    // ── Question 1 (applied — reading the modifiedProperties change) ───────
    {
      type: "question" as const,
      id: "devreg-q1",
      question:
        "A targetResources[].modifiedProperties[0] entry shows oldValue as a single-element array (one PhoneAppNotification method, Default:true) and newValue as a two-element array (both PhoneAppNotification, one Default:true, one Default:false). What does this change represent?",
      options: [
        "The original registered method was renamed — a routine, no-impact operation with no change in how many methods are registered",
        "A second, additional Authenticator registration was added alongside the original — not a replacement — leaving two methods registered where there was previously one",
        "The original registration was deleted, since the array's structure changed between oldValue and newValue",
        "This field only tracks phone number changes and has no relationship to Authenticator app registrations",
      ],
      answer: 1,
      explanation:
        "Comparing array lengths is exactly how you read this field, as Reading 2 described: one entry became two, meaning a method was added, not renamed or removed — the original Default:true entry is still present in newValue alongside the new one. StrongAuthenticationMethod tracks the full set of registered strong-auth methods generally, including but not limited to phone numbers.",
      xp: 20,
    },
    // ── Question 1b (applied — device registration vs MFA registration) ────
    {
      type: "question" as const,
      id: "devreg-q1b",
      question:
        "Entra ID logs two different self-service operations: 'User registered security info' and 'Register device' / 'Add registered owner to device'. What is the actual difference between what each one adds to an account's persistence surface?",
      options: [
        "They are two display names generated by the same underlying audit event, and Entra ID logs them identically regardless of which one actually happened",
        "'User registered security info' adds or changes an authentication method used to satisfy MFA; 'Register device' adds an entire device object to the tenant, which can separately satisfy Conditional Access policies requiring a compliant or hybrid-joined device — an attacker could pursue either, or both",
        "'Register device' is restricted specifically to mobile phone enrollment, while 'User registered security info' is restricted specifically to desktop and laptop devices",
        "Both operations require a Global Administrator or Authentication Administrator to initiate them, so self-service registration is never possible for either one",
      ],
      answer: 1,
      explanation:
        "As Reading 2 laid out, these are genuinely different objects with different downstream effects: an authentication method feeds MFA satisfaction, while a device object feeds device-based Conditional Access checks. Neither is limited by device type the way option c claims, and Reading 2 was explicit that both operations are available self-service, with no administrator required by default.",
      xp: 20,
    },
    // ── Reading 3: why this specifically survives a password reset ─────────
    {
      type: "reading" as const,
      id: "devreg-r3",
      heading: "Why a Password Reset Alone Does Not Fix This",
      content:
        "Identity Basics already established that a stolen session token isn't invalidated just because a password changes. This reading covers a second, separate way an attacker's access can survive a password reset — one that's specific to T1098.005 and easy to miss if you only think in terms of sessions.\n\n" +
        "**The sharpest concrete mechanism: self-service password reset (SSPR).** SSPR lets a user reset their own forgotten password by verifying their identity through one of their currently registered authentication methods — a code sent to a registered phone, an approval through a registered Authenticator app. If an attacker's own Authenticator entry is still registered on the account when a security team resets the password, the attacker doesn't need to know the new password at all: they can trigger the 'forgot password' flow themselves and complete verification using their own still-active method, setting the password to something they choose. The password reset that was meant to lock them out becomes, from the attacker's side, just another login screen they already hold the key to.\n\n" +
        "**The second mechanism: a standing advantage against future compromise.** Even without abusing SSPR directly, an attacker who successfully re-obtains the account's password through some other means later — a repeat phishing attempt, a leaked credential from an unrelated breach — walks straight back into a fully-satisfied MFA challenge if their registered method was never removed. They don't need to defeat MFA a second time; they already have a working factor sitting there from the first compromise, quietly waiting.\n\n" +
        "**Why 'revoke the session' and 'reset the password' both miss this.** Neither of those two actions touches the StrongAuthenticationMethod list at all. Revoking a session ends what the attacker was doing at that moment. Resetting a password changes one specific credential. The registered method is a third, separate object on the account, and it has to be found and explicitly removed as its own step — which is exactly why this room's ordering task treats it as a distinct action, not something folded silently into 'reset the password.'\n\n" +
        "**The same logic applies to a rogue registered device.** If Conditional Access at an organization grants access based on device compliance or hybrid-join status, a device the attacker successfully registered can keep satisfying that check independently of the account's password entirely, for as long as the device registration itself remains valid and untouched.",
      diagram:
        "flowchart LR\n" +
        "  A[Attacker compromises account] --> B[Attacker registers own MFA method]\n" +
        "  B --> C{IR resets password}\n" +
        "  C --> D[StrongAuthenticationMethod list: UNCHANGED]\n" +
        "  D --> E[Attacker triggers SSPR using own method]\n" +
        "  E --> F[Attacker sets a new password themselves]\n" +
        "  C --> G[Explicit removal of rogue method]\n" +
        "  G --> H[Persistence path actually closed]\n",
      diagramCaption: "Why the rogue method must be removed as its own step",
      checkpoint: {
        question:
          "Beyond abusing SSPR directly, what is the second mechanism Reading 3 describes by which an unremoved rogue authentication method benefits an attacker?",
        options: [
          "It automatically escalates the compromised account into the Global Administrator role after a fixed 30-day dormancy period with no admin action required",
          "If the attacker later re-obtains the account's password through some other means, they walk straight into a fully-satisfied MFA challenge using the method they already registered -- they don't need to defeat MFA a second time",
          "It silently disables Conditional Access MFA enforcement tenant-wide for every other account, not just the one that was compromised",
          "It permanently locks the legitimate account owner out of their own account, requiring IT to delete and completely rebuild the identity from scratch",
        ],
        answer: 1,
        explanation:
          "Even without triggering SSPR, an attacker who re-obtains the password later (via phishing or a leaked credential) still has their registered method sitting there as a standing advantage -- they've already cleared the MFA hurdle from the first compromise.",
      },
    },
    // ── Matching: Entra fields to meaning ───────────────────────────────────
    {
      type: "matching" as const,
      id: "devreg-m1",
      heading: "Match the Entra ID Field or Concept to What It Tells You",
      instructions: "Match each audit log field or concept to what it actually indicates during an investigation.",
      pairs: [
        { id: "operation", left: "User registered security info", right: "Entra ID audit operation recorded whenever ANY authentication method is added to an account, by the user or by an admin" },
        { id: "strongauth", left: "modifiedProperties displayName: StrongAuthenticationMethod", right: "The specific property that changed; its oldValue/newValue arrays show exactly which methods existed before and after" },
        { id: "selfservice", left: "initiatedBy.user.id equals targetResources[0].id", right: "Indicates self-service registration — the account registered a method for itself, with no administrator involved" },
        { id: "adminassist", left: "initiatedBy.user.roles is non-empty (e.g. Authentication Administrator)", right: "Indicates an admin performed or assisted the registration, typically tied to a documented support interaction" },
        { id: "registerdevice", left: "Register device / Add registered owner to device", right: "A SEPARATE operation that joins or registers an entire device object to the tenant, distinct from adding an authentication method" },
        { id: "correlationid", left: "correlationId", right: "Ties every audit record generated by one underlying user action together, confirming they happened as a single coherent operation" },
        { id: "sspr", left: "Self-service password reset (SSPR)", right: "A password-reset flow completed using ANY currently registered authentication method — including one an attacker added" },
      ],
      explanation:
        "The two matches most students get wrong on a first pass are treating 'self-service' as automatically suspicious, and forgetting that SSPR uses whatever methods happen to be registered at the moment it's triggered — including ones nobody has reviewed recently. Both misconceptions are exactly what this room's remaining tasks are built to correct.",
      xp: 30,
    },
    // ── Reading 4: detecting suspicious vs routine timing ───────────────────
    {
      type: "reading" as const,
      id: "devreg-r4",
      heading: "Reading the Timing: What Separates Suspicious Registration From Routine",
      content:
        "Self-service registration is, numerically, the normal case — most 'User registered security info' records reflect someone getting a new phone or setting up a second device with no malicious intent whatsoever. The signal that actually separates a suspicious registration from a routine one is almost never the operation itself; it's what surrounds it in time.\n\n" +
        "**The strongest correlating signal: proximity to a risky sign-in.** Entra ID sign-in logs carry a riskLevelDuringSignIn field and record exactly how an MFA requirement was satisfied — including, in a session hijacking scenario, being satisfied 'by claim in the token' rather than by a genuinely fresh push approval, meaning the session presented to the identity provider already carried a prior MFA claim rather than the user actually approving anything at that moment. A registration occurring within minutes of a sign-in like that — especially one sourced from an IP or geography the account has never used — is a fundamentally different situation than a registration happening on an ordinary Tuesday afternoon from the account's usual location.\n\n" +
        "**The second signal: whether a ticket or admin role explains it.** A registration with initiatedBy.user.roles empty (self-service) and no corresponding helpdesk ticket, device-refresh record, or onboarding note is worth more scrutiny than one where a ticket reference or an Authentication Administrator's involvement already explains exactly why it happened.\n\n" +
        "**The third signal: does it match the account's own device history.** An account's device inventory — even a simple record of which phone or Authenticator entry was originally enrolled — tells you whether a 'new' registration corresponds to a device the organization actually knows about, or introduces something with no prior record at all.\n\n" +
        "**None of these signals work alone.** A self-service registration with no ticket, by itself, describes an enormous number of completely legitimate personal-phone upgrades. It's the combination — self-service, no ticket, immediately following a risky or unfamiliar sign-in, with no matching device history — that turns a routine audit record into something requiring immediate containment. The log analysis task that follows gives you exactly this combination to work through, the way an investigation would actually hand it to you: pieces to correlate, not a verdict already attached.",
    },
    // ── Log Analysis: the rogue registration tied to a stolen session ──────
    {
      type: "log_analysis" as const,
      id: "devreg-la1",
      heading: "A Second Authenticator, Nine Minutes After a Replayed Session",
      context:
        "This record was pulled while investigating m.delgado@nexacorp.com's account, after a separate alert on a reverse-proxy phishing kit affecting the same account. Nine minutes before this registration, the Entra sign-in log shows a sign-in on the same account with authenticationRequirement 'multiFactorAuthentication' and authenticationStepResultDetail 'MFA requirement satisfied by claim in the token' — meaning the session presented at that sign-in already carried a prior MFA claim rather than the user approving a fresh push at that moment. m.delgado's own device inventory record lists exactly one enrolled Authenticator registration, added on the day her laptop was provisioned, tied to her personal iPhone. Review the audit record below.",
      event: devregRogueRegistrationEvent,
      questions: [
        {
          question:
            "Compare azure.auditlogs.properties.initiatedBy.user.id to targetResources[0].id, and note initiatedBy.user.roles is an empty array. What does that combination tell you about how this registration happened?",
          options: [
            "It was admin-assisted: an empty roles array is Entra ID's way of specifically flagging that a Helpdesk Administrator performed this registration on m.delgado's behalf",
            "It was self-service: the same identity (b8f42a09...) appears as both the actor and the target, and the actor held no directory role — whoever was signed in as m.delgado registered this themselves, with no admin involved",
            "The matching ID fields are coincidental placeholder GUIDs that Entra ID reuses across unrelated audit records and carry no investigative meaning",
            "An empty initiatedBy.user.roles array is Entra ID's standard signal that a record can be auto-closed as a false positive without further review",
          ],
          answer: 1,
          explanation:
            "As Reading 2 covered, initiatedBy.user.id matching targetResources[0].id is exactly the self-service signature — the same account acted on itself — and an empty roles array means no administrator role was attached to that session, ruling out admin-assisted registration rather than confirming it.",
          xp: 30,
        },
        {
          question:
            "The modifiedProperties oldValue shows one StrongAuthenticationMethod entry; newValue shows two, both MethodType PhoneAppNotification. Combined with the context that m.delgado's device inventory lists only one Authenticator enrollment tied to her issued iPhone, what does this change represent?",
          options: [
            "Her existing Authenticator entry was simply renamed, which is a routine, no-impact operation with no change in how many methods are registered",
            "A second, additional Authenticator registration was added alongside the original — it does not correspond to any device on her known inventory, which is exactly the persistence pattern this room has been building toward",
            "The original registration was deleted and nothing new was added, based on the arrays shown",
            "This field only tracks phone number changes, not Authenticator app registrations, so the change is unrelated to MFA",
          ],
          answer: 1,
          explanation:
            "One entry became two, both the same MethodType — an addition, not a rename or deletion, exactly as Question 1 taught you to read this field. The device-inventory fact from the context is what turns 'a method was added' into 'a method with no known corresponding device was added': her one known Authenticator entry is still accounted for in the array, and a second one now sits alongside it.",
          xp: 35,
        },
        {
          question:
            "Nine minutes before this registration, the referenced sign-in shows MFA satisfied 'by claim in the token' rather than a fresh push approval, and this registration's source IP (91.132.139.204, Frankfurt) doesn't match m.delgado's known device history. Based on this room, why does simply resetting m.delgado's password NOT fully remediate this incident?",
          options: [
            "It does fully remediate it — once a password changes, every registered authentication method on the account is automatically revoked as part of the same operation",
            "The newly-added Authenticator method survives a password reset entirely untouched; whoever holds it retains a working second factor and could complete a future self-service password reset using their own method unless it is explicitly found and removed",
            "Password resets are irrelevant to this incident, because no password was ever involved in the original compromise",
            "It doesn't matter, because Frankfurt is a routine location for this organization's user base and the IP mismatch carries no significance",
          ],
          answer: 1,
          explanation:
            "This is Reading 3's core point applied directly: StrongAuthenticationMethod is untouched by a password change, so the added method — and whatever advantage it gives whoever registered it, including a future SSPR path — persists until someone explicitly removes it. Nothing in Entra ID's default behavior automatically revokes registered methods on a password reset, and the geography mismatch against her known device history is a real, relevant fact here, not a coincidence to dismiss.",
          xp: 35,
        },
      ],
    },
    // ── Ordering: remediation sequence for this specific persistence type ──
    {
      type: "ordering" as const,
      id: "devreg-o1",
      heading: "Order the Remediation for a Rogue Device/MFA Registration",
      instructions: "Arrange these steps in the order they should actually happen once a rogue registration is confirmed.",
      items: [
        { id: "revoke", text: "Revoke the account's active sessions and refresh tokens immediately" },
        { id: "remove_method", text: "Identify and remove the attacker-added authentication method (or deregister the rogue device) from the account" },
        { id: "reset", text: "Reset the password, forcing sign-out everywhere" },
        { id: "review_ca", text: "Review sign-in logs for the account to confirm no further access has occurred using the removed method" },
        { id: "reregister", text: "Have the legitimate user re-register their own authentication methods through a verified, out-of-band channel" },
        { id: "document", text: "Document the timeline, including exactly which method or device was added and when, for the incident report" },
      ],
      correct_order: ["revoke", "remove_method", "reset", "review_ca", "reregister", "document"],
      explanation:
        "Revoking the live session first stops whatever is happening right now. Removing the rogue method comes immediately after, and deliberately before — or at minimum alongside — the password reset: as Reading 3 covered, resetting the password without removing the rogue method leaves the exact SSPR abuse path open, which defeats the point of resetting anything. Only after both are done does it make sense to verify no further use occurred, have the real user re-register safely, and write up the findings.",
      xp: 30,
    },
    // ── Reading 5: legitimate device/MFA registration ───────────────────────
    {
      type: "reading" as const,
      id: "devreg-r5",
      heading: "Legitimate Registration — New Phones, Planned Refreshes, and Helpdesk Assistance",
      content:
        "Self-service registration itself is not a red flag — it's the normal, expected path for the overwhelming majority of legitimate device and method changes, and treating every instance as suspicious is exactly the overcorrection this room has been steering you away from.\n\n" +
        "**A new personal phone.** An employee's phone breaks, is upgraded, or is replaced under a corporate program, and they re-register Authenticator on the new device themselves. This is routine, especially when it happens from a known corporate IP or device, during business hours, with no risky sign-in anywhere near it in time.\n\n" +
        "**A planned device refresh through IT.** Organizations running scheduled hardware refresh programs generate a predictable wave of registrations tied to a rollout, often with an accompanying ticket or enrollment record (through Intune or a similar management tool) that explains the timing across many users at once, not just one.\n\n" +
        "**Helpdesk-assisted registration for a locked-out user.** When a user genuinely loses all access to their existing methods, an Authentication Administrator or Helpdesk Administrator may register a temporary or new method on their behalf. This shows up with initiatedBy.user.roles populated and is normally tied to a support ticket documenting the identity verification the helpdesk performed before acting.\n\n" +
        "**The habit to build.** Don't ask 'was this self-service?' as your first question — Reading 4 already established that self-service is the default, expected case. Ask instead whether the timing correlates with anything risky, whether a ticket or enrollment record explains it, and whether it matches what you already know about that account's devices. The analyst_choice task that follows gives you a registration that looks structurally identical to the one in the log analysis exercise — same operation, same self-service pattern — specifically so you have to actually check those correlating facts rather than pattern-match on the operation name alone.",
    },
    // ── Analyst Choice: legitimate second-device registration ──────────────
    {
      type: "analyst_choice" as const,
      id: "devreg-ac1",
      heading: "Verdict: A Second Authenticator Registration on a Replaced Phone",
      scenario:
        "p.oduya@nexacorp.com's account shows a 'User registered security info' record, self-service, adding a second PhoneAppNotification method. Structurally this looks like the log analysis case you just worked through — same operation name, same self-service actor/target match. Review the record and its surrounding facts before deciding.",
      event: devregLegitimateRegistrationEvent,
      correct_verdict: "false_positive",
      explanation:
        "The source IP (82.80.14.6) matches p.oduya's normal corporate egress in Tel Aviv, the event occurred at 11:05 local business hours, and it_verify_result confirms Helpdesk ticket HD-51142, where she proactively called in about the exact device-replacement process this registration reflects. Nothing in the surrounding context matches the risky-sign-in correlation Reading 4 described.",
      fp_trap:
        "initiatedBy.user.roles is empty here too, and the operation name, category, and self-service actor/target match are identical in shape to the log analysis case — which is deliberate, because a student who escalates based on the operation name alone will flag this exactly the same way. The difference is entirely in the surrounding facts Reading 4 taught you to check: no risky or unfamiliar sign-in nearby, an IP matching known baseline, and a confirmed ticket explaining the timing. Escalating every self-service registration, rather than correlating it the way this room has taught, either buries real incidents in noise or — just as dangerous — trains an analyst to stop trusting their own alerts.",
      xp: 30,
    },
    // ── Question 3 (applied — roles field alone is insufficient) ───────────
    {
      type: "question" as const,
      id: "devreg-q3",
      question:
        "In both the log analysis case and the analyst_choice case, initiatedBy.user.roles is an empty array. Why doesn't that field alone tell you whether a registration is malicious?",
      options: [
        "Because an empty roles array simply means self-service registration, which is the normal path for the vast majority of legitimate device and method changes — you have to correlate it with sign-in risk, IP baseline, and timing to judge intent",
        "Because Microsoft deprecated the initiatedBy.user.roles field in current Entra ID audit schemas, so it is never reliably populated regardless of who acted",
        "Because self-service registration is inherently malicious in every single case, which makes the field's emptiness fully redundant with the malicious verdict",
        "Because the roles field is scoped only to device-registration events like 'Register device' and is never populated for StrongAuthenticationMethod changes at all",
      ],
      answer: 0,
      explanation:
        "This is the direct lesson from comparing the two tasks: identical field values, opposite verdicts, because the field that actually distinguished them was never the roles array — it was the sign-in correlation and ticket context around each event. The roles field is a real, current, and populated field; it just answers a narrower question (admin-assisted or not) than 'is this malicious.'",
      xp: 20,
    },
    // ── Query Fill: hunt for self-service registration after risky sign-in ──
    {
      type: "query_fill" as const,
      id: "devreg-qf1",
      heading: "Write It Yourself: Correlate Self-Registration With a Risky Sign-In",
      language: "kql" as const,
      context:
        "Detection engineering wants a query joining Entra ID's AuditLogs and SigninLogs tables to surface any 'User registered security info' event where the same user had a sign-in flagged with any non-'none' risk level, rather than relying on a human to manually cross-reference the two logs.",
      template:
        "AuditLogs\n| where OperationName == \"{{operation}}\"\n| where isnotempty(InitiatedBy.user.userPrincipalName)\n| where InitiatedBy.user.userPrincipalName == TargetResources[0].userPrincipalName\n| join kind=inner (\n    SigninLogs\n    | where RiskLevelDuringSignIn != \"{{riskvalue}}\"\n) on $left.InitiatedBy.user.userPrincipalName == $right.UserPrincipalName\n| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn",
      blanks: [
        { id: "operation", answers: ["User registered security info"], placeholder: "Entra ID audit operation name" },
        { id: "riskvalue", answers: ["none"], placeholder: "risk level meaning nothing was flagged" },
      ],
      explanation:
        "'User registered security info' is the exact operation name from Reading 2, and filtering SigninLogs for RiskLevelDuringSignIn not equal to 'none' surfaces exactly the correlating signal Reading 4 described — a registration paired with a sign-in that Entra ID itself flagged as risky, rather than every self-service registration indiscriminately.",
      xp: 25,
    },
    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "devreg-f1",
      prompt:
        "Look at the Log Analysis finding on m.delgado's account. What is the exact value of the azure.auditlogs.properties.correlationId field in the raw log?",
      answer: "8b05d7c4-1a69-4e38-9f27-c40e6b91a53d",
      hint: "Look inside the raw block for the field named azure.auditlogs.properties.correlationId.",
      xp: 20,
    },
    // ── Question 4 (applied — why this technique matters more broadly) ─────
    {
      type: "question" as const,
      id: "devreg-q4",
      question:
        "This room's log analysis case was tagged mitre_technique T1098.005 (Account Manipulation: Device Registration). Which of these is the most accurate summary of why this sub-technique matters more than plain credential theft alone?",
      options: [
        "It doesn't matter more than plain credential theft at all — both are always fully remediated by the exact same single remediation step, a password reset",
        "It specifically survives the standard first remediation step (a password reset) because the added authentication method or device isn't touched by a password change at all, so it must be found and removed as its own explicit step",
        "It is a purely on-premises Active Directory concern, with the technique having no equivalent mechanism or relevance inside a cloud identity provider like Entra ID",
        "It is scoped narrowly to Windows Hello for Business enrollments specifically, with no bearing on any other authentication method type",
      ],
      answer: 1,
      explanation:
        "This ties the entire room together: Reading 3 and the log analysis case both demonstrated that a password reset leaves StrongAuthenticationMethod completely unchanged, which is precisely why this technique outlasts the remediation step that would otherwise close off plain credential theft. This room's entire investigation happened inside Entra ID, a cloud identity provider, and applies to any registered method — Authenticator app, phone, or otherwise — not one specific technology.",
      xp: 25,
    },
  ],
};

export const roomsBatch27 = [remoteEmailCollectionRoom, deviceRegistrationPersistenceRoom];
