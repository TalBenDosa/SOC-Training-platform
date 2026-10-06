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
import { KQL_PRIMER } from "@/data/kqlPrimer";

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
        "**LogonType tells you whose access this is.** A value of Owner means the account is accessing its own mailbox. Delegate means someone else, with a granted delegate relationship, is accessing it (an executive assistant reading their boss's inbox, for example) — and Admin covers administrative or service-account access. In the raw audit record these appear as numbers: 0 = Owner, 1 = Admin, 2 = Delegate. None of these three is inherently suspicious on its own; what matters is whether the LogonType matches a relationship you'd actually expect, which Reading 5 covers in depth.",
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
        question: "You are holding one suspicious MailItemsAccessed record and need to know whether the same session also created an inbox rule. Which field do you pivot on?",
        options: [
          "MailboxGuid, because it ties together every record written against this one mailbox",
          "SessionId, because the sign-in, mail access and rule creation in one session share it",
          "ClientIPAddress, because records from the same address must belong to one session",
          "InternetMessageId, because a rule created afterwards is logged against the same message",
        ],
        answer: 1,
        explanation:
          "SessionId is shared by every audit record generated in the same authenticated session, so pulling it returns the sign-in, the MailItemsAccessed records and any New-InboxRule in order. MailboxGuid identifies the mailbox, so it returns every session that ever touched it, the owner's included, rather than this one session. ClientIPAddress can be shared by many sessions behind the same network, and it cannot prove two records came from one session. InternetMessageId identifies one message; an inbox rule is a mailbox setting, not an action logged against a particular message.",
      },
    },
    // ── Question 1 (applied — MITRE technique ID) ───────────────────────────
    {
      type: "question" as const,
      id: "remc-q1",
      question:
        "An attacker has obtained a valid, already-authenticated session token for a victim's mailbox — no password needed — and uses it through the Exchange REST API to search the Inbox for wire-transfer instructions. Which MITRE ATT&CK sub-technique best describes this specific action?",
      options: [
        "T1114.001, Local Email Collection — reading mail stored in the victim's Outlook cache on a compromised endpoint",
        "T1114.002, Remote Email Collection — reading mail via the account's remote access, here an API, from anywhere",
        "T1114.003, Email Forwarding Rule — redirecting the victim's mail to an external address so the attacker receives it automatically",
        "T1213, Data from Information Repositories — mining a shared business repository such as SharePoint for sensitive documents",
      ],
      answer: 1,
      explanation:
        "This is exactly T1114.002: the attacker never touches the victim's own computer or local mail files (which would be T1114.001) — they ride the account's existing remote access surface, here an API call, to read mail from anywhere. T1114.003 is the forwarding-rule technique (a standing pipeline created by New-InboxRule, not an interactive search), and T1213 targets shared repositories such as SharePoint rather than a mailbox.",
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
        "**A separate, mailbox-level mechanism exists too.** Set-Mailbox with the -ForwardingSmtpAddress parameter configures automatic forwarding at the mailbox level, entirely outside of any inbox rule — it applies to every message, has no rule-matching logic, and is checked and logged completely differently. Many security teams that only hunt New-InboxRule miss this second forwarding path entirely, so both belong on a hunt checklist, not just one.\n\n**A rule existing is not the same as mail leaving.** Whether automatically forwarded mail actually reaches an external address is controlled separately from the rule, by the tenant's outbound spam policy (Automatic - System-controlled, On, or Off) and by remote-domain settings. Microsoft's current default blocks automatic external forwarding for most tenants — the forward bounces with NDR 5.7.520 — but organizations that explicitly turned it on for business reasons will deliver it. So a hunt has two questions: does a forwarding rule exist, and is external forwarding allowed for this mailbox? The second answer tells you whether data has already left.\n\n" +
        "**A realistic lookalike domain.** Attackers rarely forward to an address that announces itself. A forwarding target like ap-invoices@northgate-logisitics.com — one character off from the real northgate-logistics.com — is designed to pass a glance from anyone who isn't checking character by character, which is precisely why domain comparison has to be deliberate, not a skim.",
    },
    // ── Question 2 (applied — inbox rule parameter combination) ────────────
    {
      type: "question" as const,
      id: "remc-q2",
      question:
        "A New-InboxRule audit record shows: ForwardTo -> ap-invoices@northgate-logisitics.com (note the extra 'i'), DeleteMessage -> true, StopProcessingRules -> true, scoped to SubjectContainsWords: 'wire, invoice, ACH'. What makes this specific combination especially dangerous, beyond simply having an external forward?",
      options: [
        "DeleteMessage erases the owner's copy after forwarding, and StopProcessingRules stops later rules, a security team's rule included, from evaluating the message",
        "ForwardTo sends matching mail to the external address instead of the mailbox, so the owner receives no copy of the wire or invoice threads at all",
        "The keyword scope makes the rule fire on every incoming message, so the attacker receives the whole mailbox rather than just finance-related mail",
        "StopProcessingRules deletes the mailbox's other inbox rules when it is saved, so the owner's own sorting rules and the security team's rules are gone",
      ],
      answer: 0,
      explanation:
        "Reading 3 covered exactly this combination: DeleteMessage removes the evidence from the owner's own mailbox, and StopProcessingRules skips every rule evaluated after this one — including a defensive rule a security team might have added. “ForwardTo sends matching mail to the external address instead of the mailbox” describes RedirectTo; ForwardTo keeps the original, which is why DeleteMessage is needed here to hide it. “The keyword scope makes the rule fire on every incoming message” reverses SubjectContainsWords: it narrows the rule to finance threads, which is more targeted, not broader. “StopProcessingRules deletes the mailbox's other inbox rules” misreads the flag: the other rules still exist, they just never run against a message this rule already matched. Whether the forwarded mail actually leaves the tenant is decided separately by the outbound spam policy and remote-domain settings, so checking that tells you whether mail has already left.",
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
        question: "An alert hands you one MailItemsAccessed record for a finance user, sourced from an IP you do not recognise. Following Reading 4, what is your next step?",
        options: [
          "Escalate it as BEC now: mailbox access from an unfamiliar IP is strong enough on its own",
          "Pull every record on its SessionId and compare origin and access shape to her baseline",
          "Close it as noise: people read their own mail constantly, so one record means nothing",
          "Reset her password first, then review the session once her account is locked down",
        ],
        answer: 1,
        explanation:
          "Reading 4's method is to correlate before acting: pull the session by SessionId, then compare the sign-in origin, the hours and the Bind/Sync shape against what is normal for this account. “Escalate it as BEC now” acts on one field when the reading says no single record is a verdict. “Close it as noise” takes the true point that people read their own mail and skips the unfamiliar IP, which is exactly what the correlation is meant to test. “Reset her password first” is a containment step before you know there is anything to contain, and a reset alone does not end an already-issued session.",
      },
    },
    // ── Log Analysis: the REST-driven bulk mailbox access ───────────────────
    {
      type: "log_analysis" as const,
      id: "remc-la1",
      heading: "One MailItemsAccessed Record, and the Session Around It",
      context:
        "Northgate Logistics' SIEM flagged an anomaly on r.iversen@northgate-logistics.com's mailbox. Pulling the full Unified Audit Log for this event's SessionId shows the exact same record repeated 24 times inside a four-minute window, each one against a different InternetMessageId in the Inbox and Sent Items folders. Nine minutes before the first of these records, the same SessionId appears on an Exchange Online sign-in event; the only corporate VPN egress Northgate has on file is a single static address in Chicago, Illinois, and no employee on the finance team is assigned to travel. Per the asset inventory, r.iversen's own laptop has never generated an interactive session outside business hours in the eleven months since it was issued; the burst began at 02:47 UTC, which is 21:47 in Chicago. Review the single representative record below.",
      event: remcMailAccessEvent,
      questions: [
        {
          question:
            "data.office365.ClientInfoString reads 'Client=REST;Client=RESTSystem;;' rather than a recognizable Outlook or OWA client string. What does that tell you about how this mailbox item was accessed?",
          options: [
            "An Outlook desktop client cached the item locally during its normal startup sync",
            "A program called the Exchange or Graph REST API directly, not a person in a mail client",
            "A browser session through Outlook Web Access opened the item on the user's behalf",
            "Several people opened it at once, as this is the client string of a shared mailbox",
          ],
          answer: 1,
          explanation:
            "As Reading 2 covered, Client=REST;Client=RESTSystem;; identifies programmatic API access with no human-facing client name. An Outlook desktop client reports Client=Outlook;Microsoft Office/16.0, and its startup pull would be a Sync, not a Bind. A browser session through Outlook Web Access reports Client=OWA. The string describes the client that made the request; it says nothing about the mailbox being shared or how many people read it. A REST string is not proof of compromise on its own — legitimate tools use it — which is why the session context still matters.",
          xp: 30,
        },
        {
          question:
            "data.office365.MailAccessType reads 'Bind' rather than 'Sync', and the same SessionId produced 24 near-identical Bind records within four minutes, each against a different message. What does that combination indicate?",
          options: [
            "A client starting up: Outlook pulls a folder this way, so 24 records is expected",
            "One item per request, 24 times in four minutes: a script iterating through messages",
            "A person skimming the Inbox: opening 24 short emails in four minutes is normal",
            "Activity from 24 separate clients, since each Bind record is its own sign-in",
          ],
          answer: 1,
          explanation:
            "Reading 2 drew exactly this distinction: Sync is the folder-level pull a normal mail client performs; Bind is a per-item access. Two dozen Binds against different messages, across two folders, inside four minutes is the shape of automated iteration. “A client starting up” describes Sync, not Bind. “A person skimming the Inbox” ignores that the records span Inbox and Sent Items through a REST client with no mail client at all, and that a handful of Binds through a workday, not a dense burst, is the human shape. “24 separate clients” misreads the log: every record carries the same SessionId, so this is one session.",
          xp: 30,
        },
        {
          question:
            "The SessionId on this record also appears on a sign-in nine minutes earlier, sourced from outside the only known corporate VPN egress (a single static Chicago IP), on an account whose laptop has never shown after-hours activity in eleven months. Based on Reading 4, what should you do first?",
          options: [
            "Close it: Reading 4 says one MailItemsAccessed record is routine traffic and not enough to act on",
            "Treat it as likely compromise: pull the SessionId, look for a new inbox rule, and start containment",
            "Reset r.iversen's password and close the case, since the reset ends whoever is in the session",
            "Message r.iversen to ask if she recognises the sign-in, and hold all action until she replies",
          ],
          answer: 1,
          explanation:
            "This is the correlation Reading 4 built toward: an unfamiliar sign-in origin, an after-hours time, an automated access shape and one shared SessionId together outweigh any single field, so the move is containment plus scoping. “Close it” quotes Reading 4's warning about a single record, but this is no longer a single record: the session context is exactly what turns it into a finding. “Reset the password and close the case” leaves the already-issued session able to keep working and skips checking for a forwarding rule. “Message r.iversen and hold all action” loses time, and a message to a compromised mailbox can be read by whoever holds the session.",
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
        { id: "contain", text: "Block sign-in for the account so no new session or token refresh can succeed" },
        { id: "reset", text: "Reset the password and revoke all sessions and refresh tokens back-to-back, then force MFA re-registration" },
        { id: "rule", text: "Locate and remove the malicious inbox rule (or mailbox-level ForwardingSmtpAddress) so no further mail leaves silently" },
        { id: "scope", text: "Pull the full mailbox audit trail on the compromised SessionId(s) to determine exactly what was read, forwarded, or deleted" },
        { id: "notify", text: "Notify affected counterparties (finance, vendors) if wire-fraud-relevant emails were exposed or a fraudulent payment instruction may have gone out" },
        { id: "document", text: "Document the full timeline and findings for the incident report" },
      ],
      correct_order: ["contain", "reset", "rule", "scope", "notify", "document"],
      explanation:
        "Blocking sign-in comes first, as in Identity Basics: a reset alone leaves an already-issued token working, and revoking alone lets an attacker who knows the password sign straight back in, so with sign-in blocked the reset and the revocation are done back-to-back with no gap. Removing the inbox rule before access is cut is backwards too: an attacker with a still-live session can simply recreate a removed rule in seconds. Only after access is actually cut off does it make sense to scope the damage, notify anyone financially exposed, and write it all up.",
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
        "A MailItemsAccessed record shows j.tan (Executive Assistant) accessing c.reyes's (CFO) Inbox. Any non-owner access to a CFO's mailbox is exactly the kind of high-value target this room has been teaching you to watch for. For reference, Northgate's only corporate VPN egress is 98.14.22.5 in Chicago. Review the record, and the IT verification note under it, before deciding how to handle it.",
      event: remcDelegateEvent,
      correct_verdict: "false_positive",
      explanation:
        "data.office365.LogonType is '2' (Delegate), not '0' (Owner) — this is someone else accessing the mailbox through a granted relationship, not the account itself being used to read its own mail from an unexpected place. data.office365.MailAccessType is 'Sync', the normal behavior of a real Outlook desktop client pulling its assigned folder, not the repeated per-item Bind pattern this room's log analysis task associated with automated collection. The source IP, 98.14.22.5, is Northgate's corporate VPN egress, and the IT verification note confirms Helpdesk ticket HD-88213 authorizing exactly this delegate relationship as part of standard EA onboarding.",
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
        "Escalate as Business Email Compromise, since per-item Bind access is the pattern this room links to scripted mailbox collection",
        "Treat it as routine mailbox activity unless correlated evidence appears; this one record shows none of the compromise signals",
        "Disable the account as a precaution and open an incident, since mailbox access that no ticket explains should be contained first",
        "Close it and suppress future MailItemsAccessed records from this user's corporate IP, since this one has turned out to be benign",
      ],
      answer: 1,
      explanation:
        "Reading 4 was explicit that a single MailItemsAccessed record is almost never enough to act on by itself — people read their own mail constantly, and this record has none of the correlating signals (rule creation, sign-in anomaly, unusual access shape) that made the log analysis case worth escalating. “Per-item Bind access” is suspicious as a dense burst; one Bind is what a person opening one email looks like. Disabling the account because no ticket explains a user reading her own mail, and suppressing all future records from her IP, are overcorrections in opposite directions — proportionate response means neither escalating everything nor tuning out a source entirely.",
      xp: 20,
    },
    // ── Query Fill: hunt for external forwarding ─────────────────────────────
    {
      type: "query_fill" as const,
      id: "remc-qf1",
      heading: "Write It Yourself: Hunt for Externally-Forwarding Inbox Rules",
      language: "kql" as const,
      context: KQL_PRIMER +
        "Detection engineering wants a daily hunt across the OfficeActivity table for any inbox rule that forwards or redirects mail externally, instead of relying on a single canned alert to catch every case. Fill in the operation name and both forwarding parameters from Reading 3.",
      template:
        "OfficeActivity\n| where OfficeWorkload == \"Exchange\"\n| where Operation =~ \"{{operation}}\"\n| where Parameters has \"{{param1}}\" or Parameters has \"{{param2}}\"\n| project TimeGenerated, UserId, ClientIP, Parameters",
      blanks: [
        { id: "operation", answers: ["New-InboxRule", "NEW-INBOXRULE"], placeholder: "Exchange operation that creates an inbox rule" },
        { id: "param1", answers: ["ForwardTo", "FORWARDTO"], placeholder: "forwarding parameter that keeps a copy" },
        { id: "param2", answers: ["RedirectTo", "REDIRECTTO"], placeholder: "forwarding parameter that keeps no copy" },
      ],
      explanation:
        "New-InboxRule is the operation logged for any inbox rule creation; the template compares it with =~, and KQL's has is case-insensitive too, so any letter case is a correct query. Checking for both ForwardTo and RedirectTo matters because they behave differently — ForwardTo leaves a copy in the mailbox, RedirectTo doesn't — and a hunt that only checks one of the two, as Reading 3 pointed out, misses the quieter of the two mechanisms entirely.",
      xp: 25,
    },
    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "remc-f1",
      event: remcMailAccessEvent, // show the r.iversen mailbox log this flag reads
      prompt:
        "Containment for r.iversen's mailbox includes blocking, and pivoting on, the network origin of the session that bound the 24 messages. Using the record shown, enter that address exactly.",
      answer: "154.16.93.211",
      hint: "You want where the request came from, not which mailbox it touched or which session it belonged to.",
      xp: 20,
    },
    // ── Question 4 (applied — tokens survive password reset) ────────────────
    {
      type: "question" as const,
      id: "remc-q4",
      question:
        "IR resets r.iversen's password at 10:00 but leaves sign-in enabled and does not revoke her sessions. The attacker's mail-reading session was issued before the reset. Based on Identity Basics and this room, what is the most accurate statement?",
      options: [
        "The reset ends it: any session issued under the old password stops working at once",
        "The reset alone may not end it; until revoked, the session can work until it expires",
        "The session survives, but it is bound to the IP address it was first issued to",
        "The session keeps working provided the attacker also learns the new password",
      ],
      answer: 1,
      explanation:
        "This is the lesson carried over from Identity Basics: a token represents a login that already happened and is honoured until it expires or is explicitly revoked, so a password change does not reliably end a session issued before it. That is why the response blocks sign-in, then resets and revokes back-to-back. “The reset ends it” is the common misconception the ordering task is built around. A token is not tied to its original IP address, so “bound to the IP address it was first issued to” is wrong and would not stop reuse from elsewhere. “Provided the attacker also learns the new password” misunderstands the token: it was never checked against the password on each use, so the new password is irrelevant to it.",
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
        "**Where this fits relative to other persistence techniques.** T1098 has several siblings worth knowing apart: T1098.001 (Additional Cloud Credentials) covers adding illegitimate credentials to a cloud account, T1098.002 (Additional Email Delegate Permissions) covers abusing Exchange delegation to add a mailbox permission, T1098.003 (Additional Cloud Roles) covers granting an account an extra privileged directory role such as Global Administrator, and T1098.004 (SSH Authorized Keys) covers adding an attacker-controlled SSH key. T1098.005 is specifically about the identity provider's own authentication factors and device objects — which is exactly why it matters so much for anyone investigating an account takeover in a modern, MFA-protected environment: the MFA that was supposed to stop the attacker becomes, once they've registered their own factor, exactly what lets them come back.\n\n" +
        "**This connects directly to real scenario telemetry on this platform.** In the AiTM Token Theft scenario, event aitm_12_mfa_register fires this precise technique nineteen minutes after a stolen session is replayed — a second Microsoft Authenticator method appears on the victim's account, registered by a session that itself never had to solve a fresh MFA challenge, because the replayed session already carried a prior MFA claim. This room teaches you to read that exact class of event.",
      checkpoint: {
        question: "Using a phished session, an attacker adds a new Microsoft Authenticator entry to the victim's own Entra ID account. Which ATT&CK sub-technique from Reading 1 fits this action?",
        options: [
          "T1098.001, Additional Cloud Credentials",
          "T1098.005, Device Registration",
          "T1098.003, Additional Cloud Roles",
          "T1098.002, Additional Email Delegate Permissions",
        ],
        answer: 1,
        explanation:
          "Reading 1 defines T1098.005 as registering a new authentication method or device object with the identity provider so it is trusted as a factor — exactly an added Authenticator entry. T1098.001 is the near-miss: it covers adding illegitimate credentials to a cloud account, whereas the identity provider's own authentication factors and device objects are what T1098.005 is about. T1098.003 would need an extra privileged directory role, which nothing here grants. T1098.002 is about mailbox delegation in Exchange, not sign-in factors.",
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
        "A StrongAuthenticationMethod change shows oldValue [{\"MethodType\":\"PhoneAppNotification\",\"Default\":true},{\"MethodType\":\"OneWaySMS\",\"Default\":false}] and newValue [{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]. What does this change represent?",
      options: [
        "An SMS method was added and set as the default for future sign-in prompts",
        "The SMS method was removed, and the Authenticator entry is still the default",
        "The Authenticator entry was replaced by SMS, now the account's only method",
        "The default switched from Authenticator to SMS, with both still registered",
      ],
      answer: 1,
      explanation:
        "Reading 2's method is to compare the two arrays: oldValue held two methods and newValue holds one, so a method was removed, and the surviving entry is the PhoneAppNotification one with Default:true, unchanged. “An SMS method was added” reads the arrays the wrong way round — oldValue is the before state. “Replaced by SMS” and “the default switched to SMS” both misread newValue, which contains no OneWaySMS entry at all.",
      xp: 20,
    },
    // ── Question 1b (applied — device registration vs MFA registration) ────
    {
      type: "question" as const,
      id: "devreg-q1b",
      question:
        "Entra ID logs two different self-service operations: 'User registered security info' and 'Register device' / 'Add registered owner to device'. What is the actual difference between what each one adds to an account's persistence surface?",
      options: [
        "Security info logs a user's own MFA method changes; Register device logs the same change when an administrator makes it for them",
        "Security info adds a method that satisfies MFA; Register device adds a device object that can meet device-based Conditional Access",
        "Register device covers phones enrolled through the Authenticator app; security info covers laptops enrolled through Windows Autopilot",
        "Both need an Authentication Administrator to start them, so a non-admin actor on either record is itself a sign of compromise",
      ],
      answer: 1,
      explanation:
        "As Reading 2 laid out, these are different objects with different downstream effects: an authentication method feeds MFA, while a device object feeds device-based Conditional Access checks, and an attacker could pursue either or both. Who acted is shown by initiatedBy, not by which operation was logged, so “Register device logs the same change when an administrator makes it” confuses the operation with the actor. Neither operation is tied to a device type (Authenticator phones versus Autopilot laptops). And both are available self-service, so a non-admin actor is the normal case, not a compromise signal.",
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
          "IR reset a user's password and revoked her sessions, but left the attacker's own Authenticator entry registered. A week later her new password leaks in an unrelated breach. What stands between the attacker and a fully MFA-satisfied sign-in?",
        options: [
          "A fresh push that she must approve, since the reset cleared the earlier factor",
          "Nothing more: their own registered method can answer the MFA challenge itself",
          "A new session token, since their method only worked inside the revoked session",
          "An admin role, since self-added methods stop working after a password change",
        ],
        answer: 1,
        explanation:
          "This is Reading 3's second mechanism: with the password re-obtained, the attacker's still-registered method satisfies MFA, so they never have to defeat MFA a second time. “The reset cleared the earlier factor” is the exact misconception the room targets: a password change does not touch StrongAuthenticationMethod. “Only worked inside the revoked session” confuses a session token with a registered factor; the method is a standing object on the account. “Self-added methods stop working after a password change” is false for the same reason, and no admin role is involved in using a factor.",
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
            "Admin-assisted: a Helpdesk Administrator registered it for her, which is what the empty roles array records",
            "Self-service: one identity is both actor and target, and the acting session held no directory role at all",
            "Approved by her: initiatedBy names the user who approved the push, not the session that added the method",
            "Not determinable: actor and target IDs match on every audit record, so they cannot show who acted",
          ],
          answer: 1,
          explanation:
            "As Reading 2 covered, initiatedBy.user.id matching targetResources[0].id is the self-service signature — whoever was signed in as m.delgado acted on her own account — and an empty roles array means no administrator role was attached, which rules out admin assistance rather than confirming it. An admin-assisted registration would show the admin's identity as the actor and a populated roles array. initiatedBy identifies who performed the action, not who approved a push. And the IDs do not always match: an admin acting on someone else's account produces different actor and target IDs, which is exactly why comparing them is meaningful.",
          xp: 30,
        },
        {
          question:
            "Read the StrongAuthenticationMethod oldValue and newValue in the record, together with the context that m.delgado's device inventory lists one Authenticator enrollment on her iPhone. What does this change represent?",
          options: [
            "Her existing Authenticator entry was renamed; the number of registered methods is unchanged",
            "A second Authenticator was added beside the original, matching no device on her inventory",
            "Her original entry moved to a new phone, leaving one method registered just as before",
            "Her default changed: the new entry now receives the push prompts for her sign-ins",
          ],
          answer: 1,
          explanation:
            "oldValue holds one PhoneAppNotification entry and newValue holds two, and the original Default:true entry is still present, so a method was added alongside it. The inventory lists one Authenticator, so the second has no known device behind it. “Renamed” and “moved to a new phone” both assume the count stayed at one, but newValue has two entries. “Her default changed” misreads the flags: the original entry is still Default:true and the new one is Default:false.",
          xp: 35,
        },
        {
          question:
            "Nine minutes before this registration, the referenced sign-in shows MFA satisfied 'by claim in the token' rather than a fresh push approval, and the registering session's source does not match m.delgado's known device history. Based on this room, why does simply resetting m.delgado's password NOT fully remediate this incident?",
          options: [
            "It does: in Entra ID a password change also clears the account's registered MFA methods",
            "The added Authenticator survives the reset, so its holder keeps a factor and an SSPR route",
            "It would if sessions were revoked too, since the added method is tied to the live session",
            "It would if the source IP were blocked, since the added method is bound to the IP it came from",
          ],
          answer: 1,
          explanation:
            "This is Reading 3's core point applied directly: StrongAuthenticationMethod is untouched by a password change, so the added method — and the self-service password reset path it opens for whoever holds it — persists until someone explicitly removes it. Nothing in Entra ID's default behaviour clears registered methods on a password reset. Revoking sessions ends what the attacker is doing now but, as Reading 3 says, does not touch the method list either. And a registered factor is not bound to the IP it was added from, so blocking the registering IP leaves the method usable from anywhere else.",
          xp: 35,
        },
      ],
    },
    // ── Ordering: remediation sequence for this specific persistence type ──
    {
      type: "ordering" as const,
      id: "devreg-o1",
      heading: "Order the Remediation for a Rogue Device/MFA Registration",
      instructions: "Arrange these steps in the order they should actually happen once a rogue registration is confirmed. The attacker is believed to hold the current password as well as their own Authenticator entry, and your playbook issues a new password only once every rogue factor is gone.",
      items: [
        { id: "revoke", text: "Block sign-in for the account so no new session or token refresh can succeed while you work" },
        { id: "remove_method", text: "Identify and remove the attacker-added authentication method (or deregister the rogue device) from the account" },
        { id: "reset", text: "Reset the password and revoke all sessions and refresh tokens, back-to-back" },
        { id: "review_ca", text: "Review sign-in logs for the account to confirm no further access has occurred using the removed method" },
        { id: "reregister", text: "Re-enable sign-in and have the legitimate user re-register their own methods through a verified, out-of-band channel" },
        { id: "document", text: "Document the timeline, including exactly which method or device was added and when, for the incident report" },
      ],
      correct_order: ["revoke", "remove_method", "reset", "review_ca", "reregister", "document"],
      explanation:
        "Blocking sign-in comes first: the attacker holds both the password and a working factor, so revoking sessions on an enabled account would just let them sign in again. With sign-in blocked, the rogue method is removed before the password reset — the playbook's rule, and the reason behind it is Reading 3's SSPR path: a new password issued while the attacker's factor is still registered can be reset again by the attacker. The reset and session revocation then go back-to-back so no old token survives. Only after that does it make sense to verify no further use occurred, re-enable the account for the real user to re-register safely, and write up the findings.",
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
      heading: "Verdict: A Second Authenticator on p.oduya's Account",
      scenario:
        "p.oduya@nexacorp.com's account shows a 'User registered security info' record, self-service, adding a second PhoneAppNotification method. Structurally this looks like the log analysis case you just worked through — same operation name, same self-service actor/target match. For reference, 82.80.14.6 is NexaCorp's Tel Aviv office egress, which p.oduya uses daily, and her sign-in log shows no risky sign-in that day. Review the record and the IT verification note under it before deciding.",
      event: devregLegitimateRegistrationEvent,
      correct_verdict: "false_positive",
      explanation:
        "The source IP (82.80.14.6) matches p.oduya's normal corporate egress in Tel Aviv, the event occurred at 11:05 UTC, during Tel Aviv business hours, and the IT verification note confirms Helpdesk ticket HD-51142, where she proactively called in about the exact device-replacement process this registration reflects. Nothing in the surrounding context matches the risky-sign-in correlation Reading 4 described.",
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
        "It shows no admin role was used, and self-service is the normal path, so intent comes from sign-in risk, IP and timing",
        "An empty array means Entra could not resolve who acted, so the actor fields on these records cannot be trusted",
        "It does decide it: an empty array marks self-service, and self-service registration is itself the attack signal",
        "An empty array still fits a Helpdesk Administrator, as the field records Global Administrator actions, not helpdesk ones",
      ],
      answer: 0,
      explanation:
        "This is the direct lesson from comparing the two tasks: identical field values, opposite verdicts, because the field that actually distinguished them was never the roles array — it was the sign-in correlation and ticket context around each event. The roles field answers a narrower question (admin-assisted or not) than “is this malicious”. An empty array does not mean the actor is unknown: initiatedBy.user still names the actor and their id. Treating self-service as the attack signal is the overcorrection Reading 5 warns against, since most self-service registrations are legitimate. And Reading 2 shows roles such as Authentication Administrator or Helpdesk Administrator appearing in the field, so an empty array does rule out an admin-assisted registration.",
      xp: 20,
    },
    // ── Query Fill: hunt for self-service registration after risky sign-in ──
    {
      type: "query_fill" as const,
      id: "devreg-qf1",
      heading: "Write It Yourself: Correlate Self-Registration With a Risky Sign-In",
      language: "kql" as const,
      context: KQL_PRIMER +
        "Detection engineering wants a query joining Entra ID's AuditLogs and SigninLogs tables to surface any self-service MFA method registration made within 30 minutes of a sign-in by the same user that Entra itself rated as risky, rather than relying on a human to manually cross-reference the two logs. Fill in the audit operation that records a new authentication method, and the SigninLogs column that holds Entra's risk rating for the sign-in.",
      template:
        "AuditLogs\n| where OperationName =~ \"{{operation}}\"\n| extend UPN = tostring(InitiatedBy.user.userPrincipalName)\n| where isnotempty(UPN) and UPN == tostring(TargetResources[0].userPrincipalName)\n| join kind=inner (\n    SigninLogs\n    | where {{riskfield}} != \"none\"\n) on $left.UPN == $right.UserPrincipalName\n| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) <= 30\n| project TimeGenerated, UPN, IPAddress, SigninTime = TimeGenerated1",
      blanks: [
        { id: "operation", answers: ["User registered security info"], placeholder: "audit operation for a newly added authentication method" },
        { id: "riskfield", answers: ["RiskLevelDuringSignIn", "RiskLevelAggregated"], placeholder: "SigninLogs risk column" },
      ],
      explanation:
        "'User registered security info' is the operation name from Reading 2, and RiskLevelDuringSignIn is the sign-in risk field from Reading 4, so filtering it for anything other than 'none' surfaces exactly the correlating signal Reading 4 described — a registration paired with a sign-in Entra ID itself flagged as risky, rather than every self-service registration indiscriminately. RiskLevelAggregated, the overall risk Entra assigns the sign-in, uses the same values and is also accepted. The extend turns the nested UPN into a string column the join can use, and the 30-minute window keeps the match to registrations that closely follow the risky sign-in.",
      xp: 25,
    },
    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "devreg-f1",
      event: devregRogueRegistrationEvent, // show the m.delgado account log this flag reads
      prompt:
        "To find every other session the attacker ran against m.delgado, you will pivot in SigninLogs on the network address of the session that registered the rogue Authenticator. Using the record shown, enter that address exactly.",
      answer: "91.132.139.204",
      hint: "You want where the registering session came from, not the account it acted on or the ID that groups its audit records.",
      xp: 20,
    },
    // ── Question 4 (applied — why this technique matters more broadly) ─────
    {
      type: "question" as const,
      id: "devreg-q4",
      question:
        "A tenant's Conditional Access lets users in only from compliant or hybrid-joined devices. During a compromise, the attacker's session also completed 'Register device'. IR has since removed the rogue Authenticator, reset the password and revoked sessions. What persistence remains?",
      options: [
        "None: removing the rogue method also removes devices registered in that session",
        "The rogue device can keep meeting the device check until it is deregistered",
        "None: the password reset invalidates every device registered under the old one",
        "A directory role: device registration adds its owner to Cloud Device Administrator",
      ],
      answer: 1,
      explanation:
        "Reading 3 is explicit: a registered device can keep satisfying a device-based Conditional Access check independently of the password, for as long as the registration itself remains valid, which is why the remediation includes deregistering the rogue device. Reading 2 describes the device object and the authentication method as separate objects, so removing the method does not remove the device. A password change does not touch device registrations any more than it touches StrongAuthenticationMethod. Adding an extra directory role is a different sub-technique, T1098.003, and registering a device grants no directory role such as Cloud Device Administrator.",
      xp: 25,
    },
  ],
};

export const roomsBatch27 = [remoteEmailCollectionRoom, deviceRegistrationPersistenceRoom];
