/**
 * Room 61 "Operation Loose Thread" (investigation-methodology): St Aldric's
 * Hospice Group. A donor heard a stranger quote the exact sum in his will; the
 * sums live in the Legacy Register inside the donor CRM. Rafe Nakagawa's rule:
 * no log is opened before there is a question to ask it. One case notebook from
 * the lure to the written finding (dataset "loose-thread",
 * src/lib/missions/datasets/looseThread.ts):
 *
 *   m1  open the case: indicators from the lure          (iocs)
 *   m2a the hypothesis board, hops 1-3 + next sources     (kql, kql, fields, kql, fields)
 *   m2b the hypothesis board, hops 4-7                    (kql, kql, fields, kql, kql)
 *   m3  one timeline in UTC from six clocks               (fields)
 *   m4  boss: scope and the finding                       (fields, report)
 *
 * Each hop's question names the OBJECT (mail, click, process, connection,
 * record, bytes), never the table; the board steps ask "where do you look?"
 * for the next hop and take the fact the last hop produced.
 */
import type { MissionField, MissionTask } from "../types";

const MENTOR = "Rafe Nakagawa, Senior Investigator";
const DATASET = "loose-thread";

/** The catalogue a "where do you look?" field picks from. */
const SOURCES = ["EmailEvents", "UrlClickEvents", "DeviceProcessEvents", "DeviceNetworkEvents", "SigninLogs", "CommonSecurityLog", "CrmAudit_CL"];

/** Why each source cannot answer a question about something else. */
const CANNOT: Record<string, string> = {
  EmailEvents: "EmailEvents is the mail trace: who sent what to whom and where it landed. It records nothing a user or a laptop did afterwards.",
  UrlClickEvents: "UrlClickEvents records clicks on links that came by mail, and nothing that happened on the laptop or the network after the click.",
  DeviceProcessEvents: "DeviceProcessEvents records processes starting on a host. It holds no connections, no records read in an application and no bytes sent.",
  DeviceNetworkEvents: "DeviceNetworkEvents records connections and the process that opened them, never what was asked for or carried inside them.",
  SigninLogs: "SigninLogs records sign-ins to Entra ID. Nothing in this chain so far needed a new sign-in, and a sign-in log never shows what ran or what was read inside an application.",
  CommonSecurityLog: "CommonSecurityLog here is the web proxy: an address, a URL and bytes. It cannot say which process on the laptop made the request or which records were in it.",
  CrmAudit_CL: "CrmAudit_CL is the donor CRM's own audit: logins, searches, reads, exports. It knows nothing about mail, processes or connections.",
};

/** A "where do you look?" field: every wrong source gets its own "cannot answer, because" line. */
function whereField(id: string, label: string, right: string, why?: Record<string, string>): MissionField {
  return {
    id, label, format: "choice", options: SOURCES, accept: [right],
    coach: "That source cannot answer this question. Ask what the question is about (a mail, a click, a process, a connection, a record, bytes) and which source records exactly that.",
    traps: SOURCES.filter(s => s !== right).map(s => ({ value: s, say: why?.[s] ?? CANNOT[s] })),
  };
}

// ─── M1. Open the case ────────────────────────────────────────────────────────

const HEADERS = `Return-Path: <notice@probate-registry-uk.example>
Received: from relay01.staldrics.example (10.10.1.25) by SAH-EXCH01.staldrics.example
 (10.10.1.30) with Microsoft SMTP Server (version=TLS1_2) id 15.2.1544.11;
 Tue, 14 Apr 2026 09:41:19 +0100
Received: from mail.probate-registry-uk.example (mail.probate-registry-uk.example [198.51.100.77])
 by relay01.staldrics.example (Postfix) with ESMTPS id 4Vb2kq1xZz
 for <m.oduya@staldrics.example>; Tue, 14 Apr 2026 08:41:17 +0000 (UTC)
Authentication-Results: relay01.staldrics.example;
 spf=pass (sender IP is 198.51.100.77) smtp.mailfrom=probate-registry-uk.example;
 dkim=pass header.d=probate-registry-uk.example;
 dmarc=pass action=none header.from=probate-registry-uk.example
From: "Probate Registry Notices" <notice@probate-registry-uk.example>
To: "M. Oduya" <m.oduya@staldrics.example>
Subject: Estate of the late R. Penhaligon: legacy notice, case 8841
Date: Tue, 14 Apr 2026 08:41:09 +0000
Message-ID: <20260414084109.8841.4471@probate-registry-uk.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1_8841"

--b1_8841
Content-Type: text/plain; charset=utf-8

Dear Estates Officer,

A legacy in favour of St Aldric's Hospice Group has been recorded against the
estate of the late R. Penhaligon. Before the executors can release the gift,
the charity must confirm the pledged sum on the case file within 48 hours.

View the case file: hxxps://probate-registry-uk[.]example/case/8841/view

The notice is also attached for your records.

Probate Registry Notices

--b1_8841
Content-Type: text/html; name="Estate_Notice_8841.html"
Content-Disposition: attachment; filename="Estate_Notice_8841.html"
Content-Transfer-Encoding: base64
(48211 bytes, not shown)
--b1_8841--`;

const ATTACHMENT = `EmailAttachmentInfo, one row
Timestamp              2026-04-14T08:41:17Z
SenderFromAddress      notice@probate-registry-uk.example
RecipientEmailAddress  m.oduya@staldrics.example
FileName               Estate_Notice_8841.html
FileType               html
FileExtension          html
FileSize               48211
SHA256                 fb8b41abdba095f5eb99ca714a7c22a0e1e14737915d0d7f95884fe31544c474
ThreatTypes
DetectionMethods`;

export const LOOSE_THREAD_M1: MissionTask = {
  type: "mission",
  id: "inv-method-m1",
  heading: "Open the Case: Indicators from the Lure",
  mentor: MENTOR,
  story: "A donor rang the fundraising office this afternoon: a stranger had quoted him the exact sum pledged in his will. Those sums live in the Legacy Register, inside the donor CRM. The only lead so far is a mail the estates officer, m.oduya, forwarded to IT this morning as \"odd\". Rafe opens a case and slides the original message across. \"Before we open a single log, the notebook gets the attacker's side of this mail. Only the attacker's side.\"",
  objective: "Log every attacker indicator from the mail into the case notebook, and nothing that belongs to St Aldric's.",
  artifacts: [
    { id: "headers", title: "Original message, full headers and body (as forwarded to IT)", format: "mono", body: HEADERS },
    { id: "attachment", title: "Attachment details from the mail filter", format: "mono", body: ATTACHMENT },
  ],
  steps: [
    {
      kind: "iocs", id: "lure", xp: 40,
      prompt: "Collect the indicators that belong to the **sender**: who sent it, from where, what it points to and what it carried. Select text in the evidence and add it, or type it into the notebook with its type.",
      artifactIds: ["headers", "attachment"],
      expect: [
        { type: "domain", value: "probate-registry-uk.example", label: "the sender's domain" },
        { type: "email", value: "notice@probate-registry-uk.example", label: "the sender's address" },
        { type: "ip", value: "198.51.100.77", label: "the sending server's IP" },
        { type: "url", value: "https://probate-registry-uk.example/case/8841/view", label: "the link in the body" },
        { type: "filename", value: "Estate_Notice_8841.html", label: "the attachment's file name" },
        { type: "sha256", value: "fb8b41abdba095f5eb99ca714a7c22a0e1e14737915d0d7f95884fe31544c474", label: "the attachment's SHA256" },
      ],
      forbidden: [
        { value: "m.oduya@staldrics.example", say: "That is the recipient, St Aldric's own officer. It goes in the case as the affected user, never as an attacker indicator: a block on it would cut off your own staff." },
        { value: "10.10.1.25", say: "That is St Aldric's own mail relay, relay01. Every inbound message passes through it, so it is the receiving side of the hop, not the sender." },
        { value: "10.10.1.30", say: "That is St Aldric's own Exchange server, the last internal hop. The sender is where the chain of Received lines starts, not where it ends." },
        { value: "staldrics.example", say: "That is the hospice's own domain. The attacker's domain is the one in Return-Path, From and the first Received line." },
      ],
      hint: "Read the `Received` lines bottom-up: the lowest one is where the mail entered, and it names the sender's server and address.",
      where: "Six indicators: the domain and address in `Return-Path` and `From`; the IP in square brackets on the lowest `Received` line; the link in the body (defanged, which the notebook accepts); and from the attachment row, `FileName` and `SHA256`.",
      worked: "Attacker side:\n- domain `probate-registry-uk.example`\n- address `notice@probate-registry-uk.example`\n- sending IP `198.51.100.77` (lowest Received line)\n- URL `hxxps://probate-registry-uk[.]example/case/8841/view`\n- file `Estate_Notice_8841.html`\n- SHA256 `fb8b41ab...c474`\n\nVictim side, not indicators: `m.oduya@staldrics.example` (the recipient), `10.10.1.25` (relay01) and `10.10.1.30` (Exchange), both St Aldric's own servers.",
      debrief: "Notice `spf=pass`, `dkim=pass` and `dmarc=pass`. They prove only that the mail really came from probate-registry-uk.example, and the attacker registered that look-alike domain, so of course it passes. Authentication says who sent it, never whether the sender is honest.",
    },
  ],
};

// ─── M2a. The hypothesis board: the mail, the click, the laptop ───────────────

export const LOOSE_THREAD_M2A: MissionTask = {
  type: "mission",
  id: "inv-method-m2a",
  heading: "The Hypothesis Board: Mail, Click, Laptop",
  mentor: MENTOR,
  story: "Rafe writes three hypotheses on the board: a stolen mailbox, a compromised laptop, an insider export. \"Each one predicts different rows. We ask one question at a time, we pick the one source that can answer it, and the answer picks the next question. Start with the mail you just took apart.\" The workspace holds this morning's mail trace, link clicks, endpoint telemetry, the CRM audit and the web proxy.",
  objective: "Follow the mail to the laptop in three hops: who got it, who clicked, what ran. Pin each answering row.",
  dataset: DATASET,
  steps: [
    {
      kind: "kql", id: "hop1", xp: 20,
      prompt: "Hop 1. **Who else received this email, and what happened to each copy?** Return each recipient with the delivery verdict.",
      starter: "// Which table records every message the mail gateway handled, one row per recipient?\n",
      hint: "Pivot on what the attacker controls and your notebook already holds: the sender. The subject is the attacker's story, and someone else may tell the same story.",
      where: "Mail trace is `EmailEvents`, one row per recipient. Filter on `SenderFromDomain` or `SenderFromAddress`, then `project RecipientEmailAddress, DeliveryAction`.",
      answer: {
        reference: [
          "EmailEvents | where SenderFromDomain == \"probate-registry-uk.example\" | project RecipientEmailAddress, DeliveryAction",
          "EmailEvents | where SenderFromAddress =~ \"notice@probate-registry-uk.example\" | distinct RecipientEmailAddress, DeliveryAction",
        ],
        mode: "rows", keys: ["RecipientEmailAddress", "DeliveryAction"], distinct: true,
        traps: [
          { ifQuery: "Penhaligon", say: "The family's solicitor wrote about the same estate this morning, genuinely. A subject line is the story the attacker tells; pivot on the sender, which the attacker cannot share with an honest correspondent." },
          { ifRowsMoreThan: 8, say: "Far more rows than one message has recipients. Keep the messages from this sender only." },
          { ifRowsFewerThan: 2, say: "One row is the copy you already hold. The question is who ELSE got it, so keep every recipient of this sender." },
        ],
      },
      worked: "```\nEmailEvents\n| where SenderFromDomain == \"probate-registry-uk.example\"\n| project RecipientEmailAddress, DeliveryAction\n```\nThree recipients: m.oduya Delivered (Inbox), j.pellow and a.fairweather Junked. The solicitor's mail about the same estate is a different sender and stays out.",
      debrief: "One message, one row per recipient: three copies, one in an inbox, two in Junk. Junk is not safe, because a user can still open it, so the click log is the next hop for all three.",
    },
    {
      kind: "kql", id: "hop2", xp: 20,
      prompt: "Hop 2. **Who clicked the link in that mail, and did each click get through?** Return the account and the click verdict.",
      starter: "// A delivery is not a click. Which table records clicks on links that came by mail?\n",
      hint: "The link is in your notebook. Match the domain, so every path on it counts.",
      where: "`UrlClickEvents`: `Url`, `AccountUpn`, `ActionType` (ClickAllowed, ClickBlocked). Use `Url has \"<the lure's domain>\"`, then `project AccountUpn, ActionType`.",
      answer: {
        reference: [
          "UrlClickEvents | where Url has \"probate-registry-uk.example\" | project AccountUpn, ActionType",
          "UrlClickEvents | where Url startswith \"https://probate-registry-uk.example\" | distinct AccountUpn, ActionType",
        ],
        mode: "rows", keys: ["AccountUpn", "ActionType"], distinct: true,
        traps: [
          { ifQuery: "^\\s*EmailEvents", say: "EmailEvents says where a message landed, never what anyone did with it. Clicks have their own table." },
          { ifRowsMoreThan: 5, say: "More clicks than this link got. Keep the clicks on the lure's domain only." },
        ],
      },
      worked: "```\nUrlClickEvents\n| where Url has \"probate-registry-uk.example\"\n| project Timestamp, AccountUpn, ActionType\n```\nm.oduya ClickAllowed at 08:52:31 UTC; j.pellow ClickBlocked at 09:20:05, from the Junk copy, after the link's verdict changed.",
      debrief: "One click got through, from the inbox copy. The blocked one still goes in the case: that user tried, and a later variant might not be blocked. Pin the allowed click: its time starts the next hop.",
    },
    {
      kind: "fields", id: "board1", xp: 15,
      prompt: "Pin the allowed click and write down its time. Then choose the source for the next question: **what ran on the officer's laptop right after the click?**",
      fields: [
        whereField("src3", "Where do you look for what ran on the laptop?", "DeviceProcessEvents"),
        { id: "clickAt", label: "Time of the allowed click (UTC)", format: "utc", placeholder: "hh:mm", accept: ["2026-04-14 08:52", "08:52"], tolerance: 1, coach: "Read `Timestamp` on the ClickAllowed row from hop 2. The workspace stores UTC already, so no conversion is needed.", traps: [{ value: "09:20", say: "09:20 is the blocked click from the Junk copy. The hop follows the click that got through." }] },
      ],
      hint: "A program starting on a host is endpoint telemetry, not mail and not network.",
      where: "The matrix row \"What ran on the host after it arrived?\" points to EDR process telemetry: `DeviceProcessEvents`. The time is the `Timestamp` of the ClickAllowed row.",
      worked: "Source: `DeviceProcessEvents`. Click: 08:52 UTC (08:52:31).",
      debrief: "Each fact picks the next source: an account and a time point to what ran on that account's machine from that minute on.",
    },
    {
      kind: "kql", id: "hop3", xp: 20,
      prompt: "Hop 3. **What started on the officer's laptop in the two minutes after the click?** Return each new process with the process that launched it.",
      starter: "// Which device is the officer's? The account name is on every process row.\n",
      hint: "Two filters: the laptop (or the officer's account) and the two minutes from the click time on your pinned row.",
      where: "`DeviceProcessEvents | where AccountName == \"m.oduya\"` (or the laptop's `DeviceName`) and `Timestamp between (datetime(<click>) .. 2m)`, then `project FileName, InitiatingProcessFileName`.",
      answer: {
        reference: [
          "DeviceProcessEvents | where DeviceName == \"SAH-BRS-LT14\" and Timestamp between (datetime(2026-04-14T08:52:31Z) .. 2m) | project FileName, InitiatingProcessFileName",
          "DeviceProcessEvents | where AccountName =~ \"m.oduya\" and Timestamp between (datetime(2026-04-14T08:52:31Z) .. 2m) | project FileName, InitiatingProcessFileName",
        ],
        mode: "rows", keys: ["FileName", "InitiatingProcessFileName"], distinct: true,
        traps: [
          { ifRowsMoreThan: 8, say: "Too many rows: narrow to the officer's laptop and to the two minutes after the click." },
          { ifQuery: "^(?![\\s\\S]*(DeviceName|AccountName|InitiatingProcessAccountName))", say: "No laptop in your filter: another PC in Halifax ran a script in the same minute. Keep the officer's machine only." },
        ],
      },
      worked: "```\nDeviceProcessEvents\n| where AccountName =~ \"m.oduya\"\n| where Timestamp between (datetime(2026-04-14T08:52:31Z) .. 2m)\n| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, ProcessCommandLine\n```\nOn SAH-BRS-LT14: msedge.exe starts mshta.exe on `Estate_Notice_8841.hta` (08:53:04), mshta.exe starts `powershell.exe -nop -w hidden -enc ...` (08:53:10), and conhost.exe hosts its console.",
      debrief: "A browser starting mshta.exe on a downloaded .hta is the tell; mshta.exe starting PowerShell with `-nop -w hidden -enc` (no profile, no window, an encoded command) is the payload. The \"compromised laptop\" hypothesis just survived a test that could have killed it.",
    },
    {
      kind: "fields", id: "board2", xp: 15,
      prompt: "Pin the hidden process. Name it and its parent, then choose the source for the next question: **where did that process connect?**",
      fields: [
        whereField("src4", "Where do you look for that process's connections?", "DeviceNetworkEvents", {
          CommonSecurityLog: "The proxy sees the laptop's address making a request, but not which process on the laptop made it. Only the EDR ties a connection to the process that opened it.",
        }),
        { id: "hiddenProc", label: "The process that ran hidden", format: "text", placeholder: "file name", accept: ["powershell.exe", "powershell"], coach: "Read the command lines of the three new processes: which one asks for no window?", traps: [{ value: "conhost.exe", say: "conhost.exe is the console host Windows starts beside any console program: the window that `-w hidden` keeps out of sight, not the payload." }, { value: "mshta.exe", say: "mshta.exe ran the .hta in the open. Look one step down the tree, at the command line that asks for no window." }] },
        { id: "parent", label: "The process that launched it", format: "text", placeholder: "file name", accept: ["mshta.exe", "mshta"], coach: "`InitiatingProcessFileName` on the hidden process's row names its parent.", traps: [{ value: "msedge.exe", say: "The browser launched mshta.exe. One step down: what launched the hidden process?" }] },
      ],
      hint: "The command line with `-w hidden` is the one; its parent is in `InitiatingProcessFileName`.",
      where: "Matrix row \"Which hosts talked to this IP, process to connections\": EDR network telemetry, `DeviceNetworkEvents`, keeps `InitiatingProcessFileName` on every connection. The hidden process is powershell.exe's row; its parent sits in the same row.",
      worked: "Hidden: `powershell.exe` (`-nop -w hidden -enc`). Parent: `mshta.exe`. Next source: `DeviceNetworkEvents`, because it records the process behind each connection.",
      debrief: "Process to network connections is the pivot: the EDR is the only source that can say THIS process opened THAT connection.",
    },
  ],
};

// ─── M2b. The hypothesis board: the address, the register, the way out ────────

export const LOOSE_THREAD_M2B: MissionTask = {
  type: "mission",
  id: "inv-method-m2b",
  heading: "The Hypothesis Board: Address, Register, Way Out",
  mentor: MENTOR,
  story: "Rafe crosses out \"stolen mailbox\": nothing so far needed anyone to sign in to the mail. Two hypotheses are left, a compromised laptop and an insider export. \"Now the address that PowerShell called. If ten laptops call it, this is a campaign and we scope wide. If one does, it is this laptop. Then the register, then the way out.\"",
  objective: "Follow the hidden process to the data: its address, who else called it, the export and where the bytes went.",
  dataset: DATASET,
  steps: [
    {
      kind: "kql", id: "hop4", xp: 20,
      prompt: "Hop 4. **Where did the hidden PowerShell connect?** Return each remote address with its port.",
      starter: "// The connection table keeps the process (and its command line) behind every connection.\n",
      hint: "Keep the laptop and the process. The same file name also runs for ordinary reasons: the command line and the time tell them apart.",
      where: "`DeviceNetworkEvents`, filtered on the laptop's `DeviceName`, `InitiatingProcessFileName =~ \"powershell.exe\"` and a time after the PowerShell started (or `InitiatingProcessCommandLine has \"-enc\"`), then `distinct RemoteIP, RemotePort`.",
      answer: {
        reference: [
          "DeviceNetworkEvents | where DeviceName == \"SAH-BRS-LT14\" and InitiatingProcessFileName =~ \"powershell.exe\" and Timestamp > datetime(2026-04-14T08:53:00Z) | distinct RemoteIP, RemotePort",
          "DeviceNetworkEvents | where InitiatingProcessCommandLine has \"-enc\" | distinct RemoteIP, RemotePort",
        ],
        mode: "rows", keys: ["RemoteIP", "RemotePort"], distinct: true,
        traps: [
          { ifRowsMoreThan: 6, say: "Too many: keep the connections the PowerShell opened, not everything the laptop did." },
          { ifQuery: "^(?![\\s\\S]*(Timestamp|TimeGenerated|-enc|hidden|between|ago\\())", say: "One of these is the management server, called by an Intune script on the same laptop at 07:58, before the click. Keep the PowerShell that started after the click: its command line holds `-enc`." },
        ],
      },
      worked: "```\nDeviceNetworkEvents\n| where DeviceName == \"SAH-BRS-LT14\"\n| where InitiatingProcessCommandLine has \"-enc\"\n| summarize Calls = count(), First = min(Timestamp), Last = max(Timestamp) by RemoteIP, RemotePort\n```\nOne external address, 203.0.113.164 on 443, every three minutes from 08:53:12. The 10.10.2.15 call at 07:58 is the management server, a normal script with the same file name.",
      debrief: "Every three minutes to one address: a beacon. A process name is not a verdict; its command line and its timing are. The address goes in the notebook and becomes the next pivot.",
    },
    {
      kind: "kql", id: "hop5", xp: 20,
      prompt: "Hop 5. **Which St Aldric's devices talked to that address?** Return the device names.",
      starter: "// Pivot: IP address to hosts.\n",
      hint: "Start from the address, not from the laptop. An address pivot is an exact match.",
      where: "`DeviceNetworkEvents | where RemoteIP == \"<the address>\" | distinct DeviceName`. Avoid `has` or `startswith` on an address: they also catch its neighbours.",
      answer: {
        reference: [
          "DeviceNetworkEvents | where RemoteIP == \"203.0.113.164\" | distinct DeviceName",
          "DeviceNetworkEvents | where RemoteIP == \"203.0.113.164\" | summarize count() by DeviceName",
        ],
        mode: "values", keys: ["DeviceName"],
        traps: [
          { ifQuery: "(has|contains|startswith)\\s*\\(?\\s*\"203\\.0\\.113\\.16\"", say: "A partial match also catches 203.0.113.165, a font site a Perth PC loads. An address pivot is exact: use `==`." },
          { ifQuery: "SAH-BRS-LT14", say: "You filtered on the laptop you already have. The question is who ELSE called the address, so filter on the address only." },
        ],
      },
      worked: "```\nDeviceNetworkEvents\n| where RemoteIP == \"203.0.113.164\"\n| summarize Calls = count() by DeviceName\n```\nOne device: SAH-BRS-LT14.",
      debrief: "Only the laptop. That kills the \"many laptops\" version of the case and scopes the endpoint side to one host. And \"only one found\" is a statement about this table and this window: the finding must say so, not \"no other hosts\".",
    },
    {
      kind: "fields", id: "board3", xp: 15,
      prompt: "Pin the result and write down the count. Then choose the source for the next question: **was the Legacy Register exported, by whom, and how many records?**",
      fields: [
        whereField("src6", "Where do you look for an export of the register?", "CrmAudit_CL", {
          SigninLogs: "Sign-in logs show an account signing in to Entra ID, never which records it read or exported inside the CRM. Only the application's own audit can say that.",
          CommonSecurityLog: "The proxy shows bytes leaving, not which records were in them. That is the hop after this one.",
          DeviceProcessEvents: "The CRM is a web application: an export in the browser starts no new process on the laptop.",
          DeviceNetworkEvents: "That shows the laptop talking to the CRM server, not what it asked the CRM for.",
        }),
        { id: "devices", label: "How many St Aldric's devices called that address?", format: "int", accept: ["1"], coach: "Count the distinct DeviceName values your last query returned." },
      ],
      hint: "Who exported which records is something only the application itself records.",
      where: "Matrix: \"Was it exported, by whom?\" is the application's audit trail, here the custom table `CrmAudit_CL` (`Operation`, `EntityName`, `RecordCount`, `UserName`).",
      worked: "Source: `CrmAudit_CL`. Devices that called 203.0.113.164: 1.",
      debrief: "Infrastructure logs show that something happened on the wire; only the application knows WHAT was done inside it. For data questions, go to the system that holds the data.",
    },
    {
      kind: "kql", id: "hop6", xp: 20,
      prompt: "Hop 6. **Was the Legacy Register exported on the morning of the click? By whom, how many records, and from which client?**",
      starter: "// The CRM's audit names the operation, the entity and the record count.\n",
      hint: "Three filters: the operation that takes records out, the register as the entity, and the morning of the click.",
      where: "`CrmAudit_CL | where Operation == \"ExportRecords\" and EntityName == \"LegacyRegister\"` and a time after the click, then `project UserName, RecordCount, ClientHostName`.",
      answer: {
        reference: [
          "CrmAudit_CL | where Operation == \"ExportRecords\" and EntityName == \"LegacyRegister\" and TimeGenerated > datetime(2026-04-14T08:52:31Z) | project UserName, RecordCount, ClientHostName",
          "CrmAudit_CL | where TimeGenerated > ago(12h) and Operation == \"ExportRecords\" and EntityName == \"LegacyRegister\" | distinct UserName, RecordCount, ClientHostName",
        ],
        mode: "rows", keys: ["UserName", "RecordCount", "ClientHostName"], distinct: true,
        traps: [
          { ifQuery: "GiftAid", say: "Gift Aid claims are a different entity, exported by finance as part of the normal day. The donor heard a sum from the Legacy Register." },
          { ifRowsMoreThan: 1, say: "One of these exports is six days old, by the legacy officer, 12 records: ordinary work. Keep the morning of the click." },
        ],
      },
      worked: "```\nCrmAudit_CL\n| where Operation == \"ExportRecords\" and EntityName == \"LegacyRegister\"\n| where TimeGenerated > datetime(2026-04-14T08:52:31Z)\n| project TimeGenerated, UserName, RecordCount, ClientHostName, SessionId\n```\n2,140 records by m.oduya@staldrics.example from SAH-BRS-LT14 at 09:15:02 UTC, in a session that logged in at 09:12:40 (the officer's own session started at 08:05).",
      debrief: "A real login is not a real person. The export ran under the officer's account, from the beaconing laptop, 22 minutes after the PowerShell started. Only a fact from outside the logs (where was the officer at 09:15?) separates this from an insider, so it goes in the case as a question.",
    },
    {
      kind: "kql", id: "hop7", xp: 20,
      prompt: "Hop 7. **Did it leave? Which destination received more than 100 MB in total from that laptop after the export?** Return the destination host.",
      starter: "// Which source counts the bytes each machine sends out, per destination?\n",
      hint: "Keep the laptop, keep the time after the export, add up the bytes sent per destination, and keep the big ones.",
      where: "The web proxy in `CommonSecurityLog`: `SourceIP` is the laptop's address (its `LocalIP` in DeviceNetworkEvents), `SentBytes` is what went out. `summarize Sent = sum(SentBytes) by DestinationHostName | where Sent > 100000000`.",
      answer: {
        reference: [
          "CommonSecurityLog | where SourceIP == \"10.10.4.37\" and TimeGenerated > datetime(2026-04-14T09:15:02Z) | summarize Sent = sum(SentBytes) by DestinationHostName | where Sent > 100000000 | project DestinationHostName",
          "CommonSecurityLog | where SourceUserName =~ \"m.oduya@staldrics.example\" and TimeGenerated > datetime(2026-04-14T09:15:02Z) | summarize Sent = sum(SentBytes) by DestinationHostName | where Sent > 100000000",
        ],
        mode: "values", keys: ["DestinationHostName"],
        traps: [
          { ifQuery: "^(?![\\s\\S]*(TimeGenerated|ago\\(|between))", say: "No time filter: the laptop also sent 150 MB to the hospice's own OneDrive at 08:20, before any of this. The question starts at the export." },
          { ifQuery: "^(?![\\s\\S]*(10\\.10\\.4\\.37|oduya))", say: "No laptop in your filter: a Halifax laptop uploaded a video this morning. Keep the officer's laptop only." },
        ],
      },
      worked: "```\nCommonSecurityLog\n| where SourceIP == \"10.10.4.37\"\n| where TimeGenerated > datetime(2026-04-14T09:15:02Z)\n| summarize Sent = sum(SentBytes), First = min(TimeGenerated), Last = max(TimeGenerated) by DestinationHostName\n| where Sent > 100000000\n```\nfiledrop-share.example: 1,405,353,984 bytes (about 1.4 GB) in ten PUTs from 09:31:10 to 09:44:20 UTC.",
      debrief: "Volume against the host's own day is the exfiltration signal. The OneDrive upload at 08:20 was big too, but sanctioned and before the export; the C2 posts were small. Pin the total and the first and last upload: the timeline and the scope need them.",
    },
  ],
};

// ─── M3. One timeline in UTC ──────────────────────────────────────────────────

const CLOCKS = `[1] Mail gateway, message trace (UTC)
    2026-04-14 08:41:17   Delivered   "Estate of the late R. Penhaligon: legacy notice, case 8841"   to m.oduya@staldrics.example

[2] Safe Links click report, exported from the Bristol admin console (BST)
    14/04/2026 09:52:31   ClickAllowed   m.oduya@staldrics.example   hxxps://probate-registry-uk[.]example/case/8841/view

[3] Defender for Endpoint, SAH-BRS-LT14 device timeline (UTC)
    2026-04-14T08:53:10Z   ProcessCreated   powershell.exe -nop -w hidden -enc JABjAD0ATgBl...

[4] CRM web server access log, SAH-PER-CRM01 in Perth (AWST, server local time)
    2026-04-14 17:12:40   POST /account/login   200   user=m.oduya@staldrics.example   c-ip=10.10.4.37

[5] CRM audit, exported from the CRM's own report screen
    2026-04-14T17:15:02+08:00   ExportRecords   LegacyRegister   RecordCount=2140   m.oduya@staldrics.example

[6] Web proxy admin console, Halifax hospice view (ADT)
    2026-04-14 06:31:10   PUT   hxxps://filedrop-share[.]example/u/7Qk2rX/part1   SentBytes=141557760   10.10.4.37`;

const utcField = (id: string, label: string, hhmm: string, traps: [string, string][], coach: string): MissionField => ({
  id, label, format: "utc", placeholder: "hh:mm UTC", accept: [`2026-04-14 ${hhmm}`, hhmm], tolerance: 1, coach,
  traps: traps.map(([value, say]) => ({ value, say })),
});

export const LOOSE_THREAD_M3: MissionTask = {
  type: "mission",
  id: "inv-method-m3",
  heading: "One Timeline in UTC",
  mentor: MENTOR,
  story: "Rafe lines up the six lines the case rests on, each copied out of the console that printed it: Bristol in British Summer Time, the CRM server in Perth on Western Australian time, the proxy console set to Halifax, two sources already in UTC. \"Sort these as printed and the data leaves before the mail arrives. That story never happened. Put every line on one clock.\"",
  objective: "Convert six events from four clocks to UTC and measure how long the register sat before it left.",
  artifacts: [{ id: "clocks", title: "Six lines, as each source printed them", format: "mono", body: CLOCKS }],
  steps: [
    {
      kind: "fields", id: "utc", xp: 40,
      prompt: "Write each event's time in **UTC** (hh:mm, or a full date and time). In April, BST is UTC+1, AWST is UTC+8 and ADT is UTC-3. Then the gap.",
      artifactIds: ["clocks"],
      fields: [
        utcField("mail", "[1] Mail delivered", "08:41", [], "This source already prints UTC: copy it."),
        utcField("click", "[2] Link clicked", "08:52", [["09:52", "09:52 is the BST clock. BST is one hour AHEAD of UTC, so UTC is one hour earlier."], ["10:52", "You added the hour. BST is ahead of UTC: subtract it."]], "BST is UTC+1: UTC is one hour earlier than the printed time."),
        utcField("ps", "[3] Hidden PowerShell started", "08:53", [], "The trailing Z means this line is already UTC."),
        utcField("login", "[4] CRM login", "09:12", [["17:12", "17:12 is Perth's local clock. AWST is eight hours ahead of UTC."], ["01:12", "You added eight hours. Perth is ahead of UTC: subtract them."]], "AWST is UTC+8: take eight hours off the printed time."),
        utcField("export", "[5] Legacy Register export", "09:15", [["17:15", "The value carries its own offset, +08:00: the clock is eight hours ahead of UTC."]], "A value ending +08:00 is eight hours ahead of UTC: subtract the offset."),
        utcField("upload", "[6] First upload", "09:31", [["06:31", "06:31 is the Halifax view. ADT is three hours BEHIND UTC, so UTC is three hours later."], ["03:31", "You subtracted the three hours. Halifax is behind UTC: add them."]], "ADT is UTC-3: add three hours to the printed time."),
        { id: "gap", label: "Minutes from the export to the first upload", format: "int", placeholder: "minutes", accept: ["16"], tolerance: 0, coach: "Subtract the export's UTC time from the first upload's UTC time, both in UTC." },
      ],
      hint: "Write the offset next to every line before you convert anything. A plus offset means the clock runs ahead of UTC.",
      where: "Worked conversion for [2]: 09:52:31 BST minus 1 hour = 08:52:31 UTC. Do the same with -8 hours for [4] and [5], and +3 hours for [6]. Lines [1] and [3] are UTC already.",
      worked: "In UTC: [1] 08:41:17, [2] 08:52:31, [3] 08:53:10, [4] 09:12:40, [5] 09:15:02, [6] 09:31:10. Gap: 09:31:10 - 09:15:02 = 16 minutes (16 min 8 s).",
      debrief: "Sorted by the printed clocks the upload (06:31) comes first and the login (17:12) last. In UTC it reads straight: mail, click 11 minutes later, code running 39 seconds after that, a new CRM session, the export, and the register on its way out 16 minutes later.",
    },
  ],
};

// ─── M4. Boss: scope and the finding ──────────────────────────────────────────

/** "No other hosts" as a bare fact; accepted when the sentence says it was looked for and not found. */
const NO_OTHER = { pattern: "re:\\bno other (users?|hosts?|systems?|devices?|machines?|laptops?|accounts?)\\b(?![^.]*\\b(found|identified|seen|observed|in DeviceNetworkEvents)\\b)", say: "\"No other hosts\" as a bare fact claims more than any search can show. Say what you searched and what you found: \"no other device found calling the address in DeviceNetworkEvents\"." };

export const LOOSE_THREAD_M4: MissionTask = {
  type: "mission",
  id: "inv-method-m4",
  heading: "Tie It Off: Scope and the Finding",
  mentor: MENTOR,
  story: "The board is full and the timeline reads straight. Rafe caps the pen. \"Tie it off. Someone will read this in a year without us in the room: the scope first, exactly as far as the evidence goes, then the finding, slot by slot, every claim with the source that proves it.\"",
  objective: "State the case's scope and write a five-part finding that someone else can check.",
  steps: [
    {
      kind: "fields", id: "scope", xp: 25,
      prompt: "The scope, exactly as far as the evidence on your board goes.",
      fields: [
        { id: "users", label: "Accounts the attacker used (UPNs, comma separated)", format: "set", item: "email", placeholder: "name@staldrics.example", accept: ["m.oduya@staldrics.example"], coach: "Write each account as its UPN. Scope is who the attacker actually used: a Junk copy or a blocked click is exposure, and it belongs in the gaps, not here." },
        { id: "hosts", label: "Hosts where the attacker's code ran", format: "set", item: "host", placeholder: "device names", accept: ["SAH-BRS-LT14"], coach: "Code ran where the process rows show it. The CRM server was used through a real login and ran nothing of the attacker's: name it in the finding, not here." },
        { id: "data", label: "Data set taken", format: "text", placeholder: "name of the data", accept: ["Legacy Register", "re:legacy\\s*register", "LegacyRegister"], coach: "Name the CRM data the export took, as the audit calls it." },
        { id: "records", label: "Records exported", format: "int", accept: ["2140"], coach: "`RecordCount` on the export row in the CRM audit." },
        { id: "bytes", label: "Data sent out (bytes, or with a unit such as GB)", format: "number", placeholder: "e.g. 250 MB", accept: ["1405353984"], tolerance: 110000000, coach: "Add up `SentBytes` of the large uploads after the export. A unit is fine (MB, GB).", traps: [{ value: "157286400", say: "That is the OneDrive upload at 08:20, before the export and to the hospice's own tenant." }] },
        { id: "start", label: "Window start (UTC)", format: "utc", placeholder: "hh:mm UTC", accept: ["2026-04-14 08:52", "08:52"], tolerance: 2, coach: "The window starts at the first thing the attacker's lure made happen on a St Aldric's machine.", traps: [{ value: "08:41", say: "08:41 is when the mail arrived. Nothing happened on a St Aldric's machine until the click: that is where the window starts." }] },
        { id: "end", label: "Window end (UTC)", format: "utc", placeholder: "hh:mm UTC", accept: ["2026-04-14 09:44", "09:44"], tolerance: 2, coach: "The window ends at the last event that moved data out: the last upload on your board.", traps: [{ value: "09:15", say: "09:15 is the export. The data had not left yet: the window runs to the last upload." }, { value: "09:31", say: "09:31 is the FIRST upload. The window runs to the last one." }] },
      ],
      hint: "Scope is what the evidence shows, with the window it covers. Everything here is already pinned on your board.",
      where: "Users: the account on the click, the process rows and the export. Hosts: the device in the process rows. Records: `RecordCount` on the export. Bytes: hop 7's total. Window: the allowed click to the last PUT.",
      worked: "Users: m.oduya@staldrics.example. Hosts: SAH-BRS-LT14. Data: the Legacy Register, 2,140 records. Out: 1,405,353,984 bytes, about 1.4 GB. Window: 08:52 to 09:44 UTC on 14 April 2026.",
      debrief: "A scope is a claim with edges: one account, one host, one data set, one window. Anything outside those edges that you have not checked is a gap, and the finding says so.",
    },
    {
      kind: "report", id: "finding", xp: 35,
      prompt: "The finding, one slot at a time. Short sentences, every claim backed by the board.",
      slots: [
        {
          id: "what", label: "What happened", maxWords: 60, placeholder: "Verdict and one sentence on what happened",
          checks: [
            { label: "States the verdict (true positive)", anyOf: ["true positive"] },
            { label: "Says the data left St Aldric's", anyOf: ["exfiltrat", "uploaded", "stolen", "theft", "left the network", "sent out", "taken out"] },
            { label: "Names the data (the Legacy Register)", anyOf: ["legacy"] },
          ],
          forbidden: [
            { pattern: "re:(?<!not a )\\bfalse positive\\b", say: "Every hop confirmed the one before it. Nothing on the board supports a false positive." },
            { pattern: "re:\\b(insider|the officer|m\\.oduya)\\b[^.]{0,30}\\b(stole|sold|leaked|exfiltrated)\\b", say: "The export ran under the officer's login from a laptop running attacker code. Nothing shows the officer did it: keep that as a gap, not a verdict." },
            NO_OTHER,
          ],
        },
        {
          id: "how", label: "How (entry)", maxWords: 60, placeholder: "How the attacker got in",
          checks: [
            { label: "Names the entry (phishing)", anyOf: ["phish"] },
            { label: "Names the vehicle (the link, HTA or HTML attachment)", anyOf: ["html", "hta", "attachment", "link", "url"] },
            { label: "Names what ran (mshta or PowerShell)", anyOf: ["powershell", "mshta"] },
          ],
        },
        {
          id: "impact", label: "Impact", maxWords: 60, placeholder: "What was taken, how much, where to",
          checks: [
            { label: "States the records exported (2,140)", anyOf: ["2140"] },
            { label: "States the volume sent out (about 1.4 GB)", anyOf: ["re:1[.,]4\\s*gb|1[.,]4\\s*gigabyte|1[.,]?4\\d\\d[.,]?\\d{3}[.,]?\\d{3}|1[.,]?4\\d\\d\\s*mb"] },
            { label: "Says where it went", anyOf: ["filedrop"] },
          ],
          forbidden: [NO_OTHER],
        },
        {
          id: "evidence", label: "Evidence (cite the sources)", maxWords: 60, placeholder: "Which source proves which part",
          checks: [
            { label: "Cites the mail or click source", anyOf: ["EmailEvents", "UrlClickEvents", "mail trace", "message trace", "click log", "safe links"] },
            { label: "Cites the endpoint source", anyOf: ["DeviceProcessEvents", "DeviceNetworkEvents", "EDR", "Defender for Endpoint"] },
            { label: "Cites the CRM audit or the proxy", anyOf: ["CrmAudit", "CRM audit", "CommonSecurityLog", "proxy"] },
          ],
        },
        {
          id: "gaps", label: "Gaps not yet examined", maxWords: 60, placeholder: "What you have not looked at yet",
          checks: [
            { label: "Marks it as not yet examined", anyOf: ["not yet", "not examined", "unexamined", "still to", "have not", "haven't", "to check", "to review", "remains", "unknown", "open question", "not checked"] },
            { label: "Names something concrete to examine", anyOf: ["other crm", "other users", "other accounts", "mailbox", "inbox rule", "forwarding", "memory", "persistence", "credential", "password", "sign-in", "signin", "where the officer", "j.pellow", "blocked click", "junk", "other exports", "token", "session", "the officer"] },
          ],
          forbidden: [NO_OTHER],
        },
      ],
      solution: {
        slots: {
          what: "True positive: data theft. An outsider used the estates officer's laptop and login to export the Legacy Register from the donor CRM and upload it out of St Aldric's.",
          how: "Phishing: a look-alike probate notice with a link; the click downloaded an HTA that mshta.exe ran, which started hidden PowerShell on SAH-BRS-LT14 beaconing to 203.0.113.164.",
          impact: "2,140 Legacy Register records exported at 09:15 UTC; about 1.4 GB uploaded to filedrop-share.example between 09:31 and 09:44 UTC.",
          evidence: "EmailEvents and UrlClickEvents for the mail and the click; DeviceProcessEvents and DeviceNetworkEvents on SAH-BRS-LT14; CrmAudit_CL for the export; the CommonSecurityLog proxy records for the upload.",
          gaps: "Not yet examined: mailbox rules on m.oduya, other CRM users' exports, and the laptop's memory. No other device was found calling 203.0.113.164 in DeviceNetworkEvents.",
        },
      },
      hint: "One slot, one job. The checklist looks for the facts, not for length: 60 words is a ceiling.",
      where: "Your pinned board already holds every fact: the verdict, the lure, the processes, the 2,140 records, the bytes and the destination, and the table each came from. Gaps: anything this case touched that no hop examined.",
      worked: "What: True positive, data theft: an outsider used the officer's laptop and login to export the Legacy Register and upload it.\nHow: Phishing link, an HTA run by mshta.exe, hidden PowerShell on SAH-BRS-LT14 calling 203.0.113.164.\nImpact: 2,140 records exported; about 1.4 GB to filedrop-share.example, 09:31-09:44 UTC.\nEvidence: EmailEvents, UrlClickEvents, DeviceProcessEvents, DeviceNetworkEvents, CrmAudit_CL, CommonSecurityLog (proxy).\nGaps: Not yet examined: mailbox rules, other CRM users, the laptop's memory, where the officer was at 09:15. No other device found calling the address in DeviceNetworkEvents.",
      debrief: "A finding someone can check in a year: a verdict, the entry, the impact in numbers, the source behind each claim, and an honest list of what nobody looked at. \"Not found in X\" is evidence; \"no other\" on its own is a guess.",
    },
  ],
};

/** The room's missions, in room order. */
export const LOOSE_THREAD_MISSIONS = { m1: LOOSE_THREAD_M1, m2a: LOOSE_THREAD_M2A, m2b: LOOSE_THREAD_M2B, m3: LOOSE_THREAD_M3, m4: LOOSE_THREAD_M4 };
