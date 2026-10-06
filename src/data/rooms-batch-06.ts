/**
 * Learning Rooms — Batch 06
 * Exchange Online Security, SharePoint & Teams Monitoring,
 * Endpoint Security Fundamentals, Microsoft Defender XDR
 *
 * Audience: absolute beginners progressing toward cloud threat detection.
 * Style: TryHackMe-style rooms with readings, MCQs, log analysis, and flags.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import type { Room, ReadingTask, QuestionTask, LogAnalysisTask, FlagTask, AnalystChoiceTask } from "@/data/rooms";

// ---------------------------------------------------------------------------
// Room 1 — Exchange Online Security
// ---------------------------------------------------------------------------

const exchangeOnlineSecurity: Room = {
  id: "exchange-online-security",
  title: "Exchange Online Security",
  description:
    "Learn how Microsoft's cloud email platform works, how attackers exploit it, and how SOC analysts detect phishing, Business Email Compromise, and malicious inbox rules. No prior email-server experience required.",
  difficulty: "intermediate",
  category: "Cloud Security",
  estimatedMinutes: 45,
  xp: 220,
  icon: "📧",
  prerequisites: ["microsoft-365-security"],
  tasks: [

    // ── Reading 1: Exchange Online & Email Flow ───────────────────────────────
    {
      type: "reading",
      id: "exch-sec-r1",
      heading: "How Exchange Online Works — The Journey of Every Email",
      content: `**Exchange Online** is Microsoft's cloud-hosted email service. It is the email backbone for any organisation using Microsoft 365. Instead of running their own on-premises mail servers, companies pay Microsoft to host their email infrastructure in Azure datacentres. Today, hundreds of millions of mailboxes run on Exchange Online.

**Why does a SOC analyst care about email?**
Email is one of the most common initial-access vectors for attackers: industry breach reports such as the Verizon DBIR consistently rank phishing alongside stolen credentials and exploited vulnerabilities as a leading way in. Understanding how email flows through Microsoft's infrastructure — and where it can be inspected — is essential knowledge for any blue-team professional.

**The Journey of an Inbound Email**

Think of email delivery like a package moving through several inspection checkpoints at an airport:

1. **Sender's mail server** — The attacker or legitimate sender composes a message and their mail server transmits it outbound.
2. **MX Record lookup** — The sending server queries DNS for the recipient domain's **MX record** (Mail Exchanger). The MX record says "send mail for corp.com to mail.protection.outlook.com." This tells the internet that Microsoft is handling email for that domain.
3. **Exchange Online Protection (EOP)** — Every inbound message first hits EOP, Microsoft's built-in filtering layer. EOP performs connection filtering (blocking known-bad IP ranges), anti-spam analysis, anti-malware scanning, and email authentication checks (SPF, DKIM, DMARC).
4. **Microsoft Defender for Office 365 (MDO)** — If the organisation has licenced MDO (formerly Advanced Threat Protection), the message additionally passes through **Safe Attachments** (detonates attachments in a sandbox) and **Safe Links** (rewrites URLs and checks them at click-time).
5. **Mailbox delivery** — If the message passes all checks, it lands in the recipient's inbox. If it is flagged as spam or malicious, it goes to the **Quarantine** instead.

**Exchange Online Protection (EOP) — The Free First Line**

Every Exchange Online subscription includes EOP at no extra cost. EOP provides:
- **Connection filtering**: Blocks emails from IP addresses that appear on known-bad reputation lists.
- **Anti-spam**: Assigns a **Spam Confidence Level (SCL)** from -1 (bypass, explicitly whitelisted) to 9 (high-confidence spam). SCL 5 and above usually routes to the Junk folder.
- **Bulk mail filtering**: A separate **Bulk Complaint Level (BCL)** score (0–9) identifies mass-marketing mail.
- **Anti-malware**: Scans attachments for known malware signatures.
- **Zero-hour Auto Purge (ZAP)**: Even after delivery, if a message is later reclassified as malware or phishing, ZAP retroactively moves it out of the inbox.

**Microsoft Defender for Office 365 (MDO) — The Premium Layer**

MDO adds behaviour-based, sandboxed inspection on top of EOP:
- **Safe Attachments**: Opens every attachment inside a detonation environment (a virtual machine) and observes what happens. Malicious behaviour = block.
- **Safe Links**: Rewrites URLs inside emails and Teams messages to pass through Microsoft's real-time reputation check. If a URL turns malicious after delivery, Safe Links blocks it when the user clicks it.
- **Anti-phishing / Impersonation Protection**: Detects look-alike sender names and domains designed to impersonate executives or trusted brands.

**The Exchange Admin Center (EAC) — admin.exchange.microsoft.com**

The EAC is the web portal where administrators manage Exchange Online. A SOC analyst uses the **Message Trace** feature here to track the delivery status of any individual email — where it came from, what happened to it, whether it was blocked, quarantined, or delivered.

**Key takeaway for analysts**: Email filtering is not perfect. Attackers constantly evolve their techniques to bypass filters. Your job as a SOC analyst is to recognise the indicators that a message slipped through, or that something suspicious happened after delivery (like a user clicking a link or forwarding rules being created).`,
      checkpoint: {
        question: "Message Trace shows that a phishing email reached a user's inbox with SCL -1. What does that value tell you about how EOP handled it?",
        options: [
          "Spam filtering was skipped because the sender was explicitly allowed",
          "EOP scored it as high-confidence spam, but delivery overrode the score",
          "Safe Attachments detonated the attachment and found nothing malicious",
          "EOP could not score the message because the SPF lookup returned an error",
        ],
        answer: 0,
        explanation:
          "SCL -1 is the bypass value: the message was explicitly allowed, so spam filtering did not apply — find out who created that allow and why. “High-confidence spam” is the other end of the scale (SCL 9), and anything at 5 or above would normally have gone to Junk. Safe Attachments is an MDO sandbox verdict, not part of the SCL score. An SPF lookup error shows up in the Authentication-Results header; it does not produce SCL -1.",
      },
    } satisfies ReadingTask,

    // ── Reading 2: SPF, DKIM, DMARC ──────────────────────────────────────────
    {
      type: "reading",
      id: "exch-sec-r2",
      heading: "Email Authentication — SPF, DKIM, and DMARC Explained",
      content: `One of the biggest problems with email is that it was invented before anyone thought about security. By default, **anyone can send an email claiming to be from any address**. This is called **email spoofing**, and it is the foundation of almost every phishing and Business Email Compromise (BEC) attack.

Three protocols were invented to fix this: SPF, DKIM, and DMARC. Together they let a receiving mail server verify whether an email really came from where it claims to come from. Think of them as the email equivalent of a passport, a seal of authenticity, and a border policy.

---

**SPF — Sender Policy Framework**

SPF is a DNS record that answers the question: **"Which mail servers are authorised to send email on behalf of this domain?"**

The domain owner publishes an SPF record in DNS. It looks something like:
\`v=spf1 include:spf.protection.outlook.com -all\`

This means: "Only Microsoft's mail servers (protection.outlook.com) are allowed to send email from our domain. Reject everything else."

When a receiving server gets an email claiming to be from corp.com, it checks the SPF record and asks: "Did this email come from one of the approved servers?" If yes → **SPF pass**. If no → **SPF fail**.

**Limitation**: SPF only checks the hidden "envelope from" address (used during SMTP delivery), not the visible "From:" header that users see. Attackers can exploit this mismatch. Microsoft's email logs name the two addresses: the envelope sender is the **P1 sender** and the visible From: header is the **P2 sender**, so a field such as \`P2SenderDomain\` holds the domain the recipient actually sees.

---

**DKIM — DomainKeys Identified Mail**

DKIM adds a **cryptographic signature** to every outgoing email. Think of it like a wax seal on a letter — it proves the message has not been tampered with in transit and really originated from the claimed domain.

The sending organisation has a private key (kept secret on their mail servers) and publishes the corresponding public key in DNS. When the email arrives, the receiving server retrieves the public key from DNS and verifies the signature.

If the signature checks out → **DKIM pass**. If the email was modified in transit or the signature is missing → **DKIM fail** or **DKIM none**.

DKIM survives email forwarding better than SPF, because it is tied to the message content, not the sending server's IP address.

---

**DMARC — Domain-based Message Authentication, Reporting & Conformance**

DMARC is the **policy layer** that sits on top of SPF and DKIM. It answers two questions:
1. **What should receiving servers do when SPF or DKIM fail?**
2. **How should failures be reported back to the domain owner?**

A DMARC record in DNS looks like:
\`v=DMARC1; p=reject; rua=mailto:dmarc-reports@corp.com\`

The **p= (policy) field** is the most important:
- \`p=none\` — Monitor only; take no action on failures. Used when first deploying DMARC.
- \`p=quarantine\` — Send failing emails to spam/junk folder.
- \`p=reject\` — Block and discard failing emails entirely. This is the most protective setting.

**DMARC Alignment** is a critical concept: for DMARC to pass, either the SPF domain or the DKIM signing domain must **align** (match) with the visible "From:" header domain. This closes the SPF loophole mentioned above.

---

**Reading the Authentication-Results Header**

Every email received by Exchange Online gets an **Authentication-Results** header added to it. This is where SOC analysts look to quickly check the authentication status of a suspicious email.

Example:
\`Authentication-Results: spf=fail (sender IP is 185.234.5.6); dkim=none; dmarc=fail action=none header.from=corp.com\`

Breaking this down:
- **spf=fail** — The sending IP (185.234.5.6) is NOT in corp.com's SPF record. This IP is not authorised.
- **dkim=none** — No DKIM signature was present at all. Legitimate email from Microsoft 365 always has DKIM.
- **dmarc=fail** — Because both SPF and DKIM failed, DMARC also fails.
- **action=none** — The DMARC policy is \`p=none\`, so the email was delivered anyway (just monitored).

**Key insight for analysts**: An email with \`dmarc=fail action=none\` was delivered to the inbox despite failing authentication. This is a critical finding — especially if the "From:" domain appears to be a trusted organisation like your CEO's company.

**Microsoft's 2025 enforcement update**: In May 2025, Microsoft began rejecting bulk email from senders who lack proper DMARC, SPF, and DKIM alignment when sending to consumer Microsoft addresses (Outlook.com, Hotmail). Enterprise tenants can enforce stricter policies in their own anti-phishing policies.`,
      checkpoint: {
        question: "A legitimate, signed newsletter is auto-forwarded from an employee's personal mailbox to their work inbox. Which check is most likely to still pass at the work inbox, and why?",
        options: [
          "SPF, because forwarding leaves the envelope-from domain unchanged",
          "SPF, because the forwarding server inherits the sender's approval",
          "DKIM, because its signature is tied to the content, not the server IP",
          "DMARC, because its policy is evaluated before SPF and DKIM run",
        ],
        answer: 2,
        explanation:
          "DKIM signs the message content, so an unmodified forward still verifies even though a different server delivered it. An unchanged envelope-from does not save SPF: SPF checks the connecting server's IP, and the forwarder's IP is not in the original sender's SPF record. Forwarding servers do not “inherit” approval; only the IPs listed in the record are authorised. DMARC is not evaluated first; it is the policy layer that uses the SPF and DKIM results.",
      },
    } satisfies ReadingTask,

    // ── Reading 3: BEC Detection & Monitoring ─────────────────────────────────
    {
      type: "reading",
      id: "exch-sec-r3",
      heading: "Detecting BEC Attacks and Monitoring Exchange Online",
      content: `**Business Email Compromise (BEC)** is one of the most financially damaging cyber threats facing organisations today. The FBI's Internet Crime Complaint Center (IC3) reports billions of dollars in BEC losses every year. Unlike ransomware, BEC doesn't need malware — it relies on deception.

**How BEC Works**

In a typical BEC scenario:
1. An attacker identifies a target organisation (e.g. Acme Corp) and researches its executives (LinkedIn, company website).
2. The attacker spoofs or typosquats the CEO's email address. Typosquatting means registering a domain that looks similar: \`acm3corp.com\` instead of \`acmecorp.com\`, or \`acmecorρ.com\` (using a Greek letter that looks like 'p').
3. The attacker emails the CFO or Finance team, impersonating the CEO: "I need an urgent wire transfer of $450,000 to this account. I'm in a meeting and cannot talk — just do it now."
4. The sense of urgency, combined with authority, causes the victim to act without verifying.

**Key BEC Detection Signals**

As a SOC analyst, watch for these in your email security tools:

- **DMARC/SPF/DKIM failures on executive-looking domains**: A message appearing to be from the CEO but with \`dmarc=fail\` is a major red flag.
- **Lookalike sender domains**: Compare the P2 sender domain (displayed to the user) against your internal domain list. Is \`c0rp.com\` (with a zero) trying to look like \`corp.com\`?
- **Urgency keywords in subjects**: "URGENT", "Wire Transfer", "Payment Required", "Confidential" are classic BEC subject line patterns.
- **Mismatch between display name and email address**: The From display says "John Smith (CEO)" but the actual email address is \`ceo@randomdomain.ru\`.
- **Reply-To header manipulation**: The visible From address looks legitimate but the Reply-To points to an attacker-controlled address.

**Malicious Inbox Rules — The Silent Forwarder**

A sophisticated attacker who successfully compromises a mailbox often creates **inbox rules** to maintain persistence and steal information silently. A common rule:
- Forward all incoming emails to an external address (attacker's mailbox)
- Delete the forwarded emails from Sent Items and Inbox so the victim doesn't notice
- Move security alerts or IT emails to Deleted Items automatically

These rules appear in the **Unified Audit Log** under different operation names depending on how they were made: \`New-InboxRule\` (rule created in Outlook on the web or with PowerShell), \`Set-InboxRule\` (existing rule changed the same way) and \`UpdateInboxRules\` (rule created or changed from the Outlook desktop client). Search for all three: the operation name tells you which client was used, but the rule's content (external forwarding, deletion, moving security mail) is what makes it suspicious.

Forwarding does not even need a rule: an attacker with admin rights, or a user in the mailbox settings, can set mailbox-level forwarding to an external address. That change is logged as the \`Set-Mailbox\` operation with the \`ForwardingSmtpAddress\` parameter.

**Monitoring Exchange Online — Key Tools**

| Tool | Where | What SOC Analysts Use It For |
|---|---|---|
| **Message Trace** | admin.exchange.microsoft.com → Mail flow → Message trace | Track individual emails: was it delivered, quarantined, or blocked? What was the spam confidence level? |
| **Quarantine Review** | security.microsoft.com → Email & collaboration → Quarantine | Review and release quarantined messages; look for false positives or attacker-released malware |
| **Unified Audit Log** | Microsoft Purview portal (purview.microsoft.com → Audit) or via Search-UnifiedAuditLog | Find MailItemsAccessed, SendAs, AddDelegate, New-InboxRule, UpdateInboxRules, Set-Mailbox events |
| **Threat Explorer** | security.microsoft.com → Email & collaboration → Explorer | Hunt for phishing campaigns, see email delivery status, trace URLs clicked by users |
| **Alert Policies** | security.microsoft.com → Alerts | Pre-built alerts for forwarding rules, unusual send volumes, impersonation detection |

**Key Audit Log Operations to Know**

- \`MailItemsAccessed\` — Someone accessed specific emails (critical for OAuth token compromise investigations)
- \`SendAs\` — Someone sent email as another user
- \`AddDelegate\` — A delegate (another user) was given access to a mailbox
- \`New-InboxRule\` / \`Set-InboxRule\` — An inbox rule was created / changed from Outlook on the web or PowerShell (check the forwarding and delete parameters)
- \`UpdateInboxRules\` — An inbox rule was created or modified from the Outlook desktop client (check the external address in the rule details)
- \`Set-Mailbox\` — Mailbox settings changed; with \`ForwardingSmtpAddress\` it means mailbox-level forwarding, no inbox rule needed

**Practical Analyst Workflow for Suspicious Email**

1. Open **Message Trace** and find the email by sender, recipient, or subject.
2. Check the **Authentication-Results**: did SPF, DKIM, DMARC pass?
3. Check the **SCL score**: was it filtered but delivered anyway?
4. Check the **P2SenderDomain** field: does it match the display name domain?
5. Search the **Unified Audit Log** for \`New-InboxRule\`, \`Set-InboxRule\`, \`UpdateInboxRules\` and \`Set-Mailbox\` for that user in the past 30 days.
6. If the user clicked a link, check **Safe Links** reports in Threat Explorer.
7. If mailbox compromise is suspected, check \`MailItemsAccessed\` for unusual activity.`,
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "exch-sec-q1",
      question: "An email arrives at your company with the following header:\n\n`Authentication-Results: spf=pass; dkim=pass; dmarc=fail action=quarantine`\n\nWhat does this indicate?",
      options: [
        "SPF and DKIM both passed, so DMARC must have passed too — a false alarm",
        "SPF and DKIM passed for a domain that does not match the visible From: domain",
        "The DMARC record could not be fetched, so the message was quarantined",
        "The message body was altered after signing, which DMARC detects separately"
      ],
      answer: 1,
      explanation: "DMARC needs **alignment**: the SPF domain or the DKIM signing domain must match the visible From: domain. An attacker can pass SPF and DKIM for a domain they own while showing a different domain in From:, so DMARC fails. “DMARC must have passed too” is the misconception this header disproves: two passes are not enough without alignment. The record was clearly fetched: action=quarantine is the From domain's published p=quarantine policy, which the receiver could only apply after reading it. A body changed after signing would break DKIM itself, and here dkim=pass. action=quarantine means the From domain's policy sent the message to junk.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "exch-sec-q2",
      question: "A finance employee reports receiving an urgent email from the CEO asking for a $200,000 wire transfer. The email passed SPF and DKIM. However, you notice the sender domain in the email is `c0rp.com` (with a zero) not `corp.com`. What attack technique is this?",
      options: [
        "Exact-domain spoofing — a forged corp.com From: address that SPF did not catch",
        "Lookalike domain — the attacker registered c0rp.com and authenticated it",
        "Account takeover — the CEO's real mailbox was compromised and used to send it",
        "Display-name spoofing — the display name says CEO; the domain is unrelated"
      ],
      answer: 1,
      explanation: "This is a **lookalike (typosquatted) domain**. The attacker registered `c0rp.com` and published SPF and DKIM for it, so authentication passes: the checks prove the mail really came from c0rp.com. DMARC is evaluated for the From domain, c0rp.com, which the attacker controls, so corp.com's own DMARC policy plays no part. Only lookalike/impersonation protection (MDO anti-phishing) or a careful look at the P2 sender domain catches it. Exact-domain spoofing would show corp.com in From:, and SPF would then fail. A taken-over CEO mailbox would send from the real corp.com address. Display-name spoofing pairs a CEO display name with an unrelated domain; here the domain itself imitates corp.com.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "exch-sec-q3",
      question: "A compromised user's incoming mail is being copied to an external Gmail address. You searched the Unified Audit Log for New-InboxRule, Set-InboxRule and UpdateInboxRules on that mailbox and found nothing. Which operation should you search for next to explain the forwarding?",
      options: [
        "MailItemsAccessed",
        "SendAs",
        "Set-Mailbox",
        "AddDelegate"
      ],
      answer: 2,
      explanation: "Forwarding without any inbox rule is **mailbox-level forwarding**, logged as **Set-Mailbox** with the ForwardingSmtpAddress parameter. That is why an empty search for the three rule operations does not close the question. MailItemsAccessed records items being read (important for scoping what the attacker saw) but it does not create a forwarding path. SendAs records mail sent as another user, which is outbound impersonation, not a copy of incoming mail. AddDelegate gives another user access to the mailbox inside the tenant; it does not push mail to an external address.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Log Analysis: BEC email with failed DMARC ─────────────────────────────
    {
      type: "log_analysis",
      id: "exch-sec-la1",
      heading: "Suspicious Email — Wire Transfer Request",
      context: "You are a SOC analyst at Corp Inc. The email security system has flagged an inbound message received by the Finance team. The message trace log below was pulled from the Exchange Admin Center. Analyse the event and answer the questions.",
      event: {
        id: "exch-la1-001",
        ts: "2025-11-14T09:23:41.000Z",
        source: "exchange",
        event_type: "email_received",
        severity: "high",
        description: "Inbound email to finance team — authentication failures detected",
        hostname: "mail.protection.outlook.com",
        user_email: "finance@corp.com",
        mitre_technique: "T1566.002",
        mitre_tactic: "Initial Access",
        vendor: "Microsoft 365 Unified Audit Log",
        raw: {
          "data.office365.Operation": "MessageReceived",
          "data.office365.InternetMessageId": "<7f3a9b21@mail.c0rp.com>",
          "data.office365.SenderAddress": "ceo@c0rp.com",
          "data.office365.RecipientAddress": "finance@corp.com",
          "data.office365.Subject": "URGENT: Wire Transfer Required — Confidential",
          "data.office365.AuthenticationResults": "spf=fail (sender IP is 185.234.91.7 not in c0rp.com SPF); dkim=none; dmarc=fail action=none",
          "data.office365.SCL": "1",
          "data.office365.BCL": "0",
          "data.office365.P2SenderDomain": "c0rp.com",
          "data.office365.DeliveryAction": "Delivered",
          "data.office365.DeliveryLocation": "Inbox",
          "data.office365.NetworkMessageId": "ae9f2c1d-4b77-4e3a-9123-fa8d2b3c9e01",
          "data.office365.ClientIP": "185.234.91.7"
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "The email was delivered to the Finance inbox despite failing SPF and DMARC. Based on the record, what is the most likely reason it was not stopped?",
          options: [
            "EOP was not filtering this tenant's mail, so no policy was evaluated",
            "c0rp.com's DMARC policy is p=none, so its DMARC failure triggered no action",
            "corp.com's DMARC policy is p=none, so lookalikes of corp.com go unenforced",
            "A tenant allow entry for the sender overrode the authentication failures"
          ],
          answer: 1,
          explanation: "DMARC is evaluated for the From domain, c0rp.com, and `dmarc=fail action=none` means that domain publishes `p=none`, so the failure carried no reject or quarantine instruction. Here p=none is the attacker's own choice for a domain they control. With SCL 1 the spam filter judged the content clean (below the Junk threshold of 5), so nothing else stopped it. EOP was clearly running: it produced the SCL, BCL and Authentication-Results values in this record. corp.com's DMARC policy plays no part, because the message never claims to come from corp.com. An allow entry would have bypassed filtering and shown SCL -1, not SCL 1.",
          xp: 40,
        },
        {
          question: "Which field in this record most directly shows that the message is pretending to come from your own company?",
          options: [
            "AuthenticationResults: corp.com's SPF record does not list the sending IP",
            "P2SenderDomain: c0rp.com uses a zero where your corp.com domain has an o",
            "InternetMessageId: the ID was generated by a server outside your tenant",
            "DeliveryLocation: Inbox shows that a spoofed corp.com message got through"
          ],
          answer: 1,
          explanation: "`P2SenderDomain` is the domain the recipient sees in From:, and `c0rp.com` swaps the letter o for a zero to pass as `corp.com`: a typosquatted lookalike built to fool a reader at a glance. The SPF result is for c0rp.com, not corp.com (the header says the IP is not in c0rp.com's SPF), so it says nothing about your own domain. Every external email has a Message-ID from a server outside your tenant, so that field is normal. DeliveryLocation only shows where the message landed; nothing in the record shows corp.com being spoofed.",
          xp: 40,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "exch-sec-f1",
      prompt: "Blocking the lookalike domain is not enough: the mail-flow team also wants to block the infrastructure that delivered this message. Using the log above, what is the IP address of the server that actually sent it to Exchange Online?",
      answer: "185.234.91.7",
      hint: "SPF judges the server that connected to EOP, not the From: address.",
      xp: 50,
    } satisfies FlagTask,

  ],
};

// ---------------------------------------------------------------------------
// Room 2 — SharePoint & Teams Security Monitoring
// ---------------------------------------------------------------------------

const sharepointTeamsMonitoring: Room = {
  id: "sharepoint-teams-monitoring",
  title: "SharePoint & Teams Security Monitoring",
  description:
    "Discover how attackers exploit Microsoft's collaboration tools to steal data, conduct phishing via Teams chat, and abuse external sharing. Learn to detect bulk exfiltration, insider threats, and guest-account abuse.",
  difficulty: "intermediate",
  category: "Cloud Security",
  estimatedMinutes: 40,
  xp: 220,
  icon: "💬",
  prerequisites: ["microsoft-365-security"],
  tasks: [

    // ── Reading 1: SharePoint & OneDrive Structure ────────────────────────────
    {
      type: "reading",
      id: "spt-teams-r1",
      heading: "SharePoint Online & OneDrive — How Data Lives in Microsoft 365",
      content: `**SharePoint Online** is Microsoft's cloud-based document management and collaboration platform. If you've ever seen a shared company folder in a browser that looks like a file explorer, chances are it was SharePoint. In a Microsoft 365 organisation, SharePoint is where teams store, share, and collaborate on documents. It integrates tightly with Teams (every Teams channel has a SharePoint library behind it), Outlook, and OneDrive.

**The SharePoint Architecture You Need to Know**

Understanding how SharePoint is organised helps you understand where data lives and how it can be leaked:

- **Tenant** — The entire organisation's Microsoft 365 environment. Everything lives under one tenant.
- **Site Collections / Sites** — Think of these as top-level department folders. Example: \`corp.sharepoint.com/sites/Finance\`, \`corp.sharepoint.com/sites/HR\`, \`corp.sharepoint.com/sites/Engineering\`.
- **Document Libraries** — Inside each site, there are document libraries. A library is like a folder that can have sub-folders, metadata, permissions, and version history.
- **OneDrive for Business** — Every individual employee gets their own personal SharePoint site for personal work files. This is OneDrive. URL pattern: \`corp-my.sharepoint.com/personal/john_smith_corp_com/\`.

**External Sharing — The Biggest Security Risk**

SharePoint makes it very easy to share files with people outside your organisation. This is useful for collaboration with clients and partners, but it is also a major data leakage risk. There are four levels of external sharing:

1. **Anyone links (Anonymous links)** — The most dangerous setting. A link is created that anyone with the link can access, with no authentication required. Use of the link is still logged (\`AnonymousLinkUsed\`, with the client IP and user agent), but it cannot be attributed to a named identity.
2. **Specific people links (external)** — A link sent to a specific external email address. The recipient must authenticate, and access is logged.
3. **Existing external guests** — Sharing with people already added as Azure AD guest accounts.
4. **Only people in your organisation** — Internal only; no external sharing.

**Key Audit Events in SharePoint**

Every action in SharePoint is logged in the Microsoft 365 Unified Audit Log (searchable in the Microsoft Purview portal, purview.microsoft.com → Audit). The operations a SOC analyst watches for:

| Operation | What it Means |
|---|---|
| \`FileAccessed\` | A file was opened/viewed |
| \`FileDownloaded\` | A file was downloaded to the user's device |
| \`FileUploaded\` | A file was uploaded to SharePoint |
| \`FileCopied\` | A file was copied within SharePoint |
| \`SharingInvitationCreated\` | A sharing invitation was sent to an external user |
| \`AnonymousLinkCreated\` | An "Anyone" link was created (high risk!) |
| \`AnonymousLinkUsed\` | An "Anyone" link was used to access a file |
| \`SensitiveFileRead\` | A file classified as sensitive (by DLP) was accessed |

**Bulk Downloads — The Classic Data Exfiltration Pattern**

A disgruntled or compromised user exfiltrating data from SharePoint will typically download hundreds or thousands of files in a short time window. Normal user behaviour might be 5–20 file downloads per day. Downloading 500+ files in a single session is highly anomalous.

Microsoft Purview (formerly Compliance Center) can generate alerts when bulk download activity is detected. When you see a \`FileDownloaded\` event storm from a single user, check:
- Is this user leaving the company soon? (Departing employees are a common insider threat vector)
- Are the files from sensitive sites (Finance, HR, Legal, Engineering)?
- What is the user's normal download baseline?
- Is the client IP internal or external?

**Tenant-Level External Sharing Controls**

Administrators can control external sharing at the SharePoint Admin Center (admin.microsoft.com → SharePoint → Policies → Sharing). SOC analysts should know whether their organisation allows "Anyone" links — if so, any created "Anyone" link is an exfiltration channel whose users cannot be identified once the URL is shared externally.`,
      checkpoint: {
        question: "The audit log shows a Finance spreadsheet being opened from an unfamiliar external IP address, but the access record carries no user identity at all. Which way of sharing the file produces that kind of record?",
        options: [
          "Specific people links (external)",
          "Anyone links (Anonymous links)",
          "Existing external guests",
          "Only people in your organisation",
        ],
        answer: 1,
        explanation:
          "Only an “Anyone” link lets someone open the file without signing in, so its use is logged (AnonymousLinkUsed, with IP and user agent) but cannot be tied to a person. A specific-people link makes the external recipient authenticate, so their identity is recorded. An existing guest signs in with a guest account (a #EXT# UPN). Internal-only sharing means a named employee account appears in the record.",
      },
    } satisfies ReadingTask,

    // ── Reading 2: Microsoft Teams Security ───────────────────────────────────
    {
      type: "reading",
      id: "spt-teams-r2",
      heading: "Microsoft Teams Security Risks and Monitoring",
      content: `Microsoft Teams has become one of the most widely used business communication platforms in the world. With hundreds of millions of daily active users, it is also an increasingly attractive target for attackers. SOC analysts need to understand how Teams works and how it can be abused.

**Teams Architecture Basics**

- **Teams** contain **Channels**. Each channel is a conversation thread plus a shared file library (backed by SharePoint).
- **Chats** are direct messages between individuals or small groups. These are separate from channels.
- **Files** shared in Teams are actually stored in the team's SharePoint library or in the sender's OneDrive.
- **External Access** allows Teams users to message people in other organisations' Teams tenants. This is a legitimate feature for business collaboration.
- **Guest Access** allows external people to be added as full members of a specific Team. They get an Azure AD guest account (B2B).

**Teams Attack Vectors**

**1. Phishing via Teams Chat**
Attackers have increasingly pivoted from email phishing to Teams phishing. The reasoning: employees are trained to be suspicious of phishing emails, but they often have lower guard in Teams chat. Techniques include:
- Sending malicious links in Teams messages to internal users (if an internal account is compromised)
- Using External Access to message employees from a fake external tenant (e.g. a tenant named "Microsoft Support")
- Adding external guests to a Team and using that access to harvest data or spread malware

The tool **TeamsPhisher** (seen in red-team exercises and, per Microsoft, in real campaigns by the group Storm-1674 to distribute DarkGate malware) automates sending phishing messages via Teams to large numbers of users by abusing the External Access feature.

**2. Guest Account Abuse**
When an external guest is added to a Team, they can access all files in that team's SharePoint library. A compromised or malicious guest account can exfiltrate documents. Guest accounts appear in audit logs with a UPN suffix like \`user_externalcompany.com#EXT#@corp.onmicrosoft.com\`.

**3. External Access Abuse**
External Access (federation between tenants) allows anyone from any tenant to initiate a Teams chat with your employees by default. Attackers set up or compromise Microsoft 365 tenants, rename them to look like "Microsoft Help Desk" or an identity-protection team, and message your employees claiming to be IT support; Midnight Blizzard used this approach in 2023.

**Key Teams Audit Events**

| Operation | Significance |
|---|---|
| \`MessageSent\` | A message was sent in a channel or chat |
| \`MessageDeleted\` | A message was deleted (suspicious if done in bulk) |
| \`TeamCreated\` | A new Team was created |
| \`MemberAdded\` | A member was added to a team, channel or group chat; adding an external guest is logged here too, with the added member's role recorded as Guest |
| \`AppInstalled\` | A Teams app was installed (could be malicious app) |

**Microsoft Defender for Cloud Apps (MDCA) Integration**

Microsoft Defender for Cloud Apps (formerly Cloud App Security) can monitor Teams activity and generate alerts. It integrates with the Microsoft 365 audit log and applies machine-learning-based anomaly detection. Relevant MDCA policies for Teams:
- **Mass download by a single user**: Triggers when a user downloads far more files than their peers.
- **Activity from infrequent country**: A Teams login from a country the user has never been in before.
- **Suspicious app consent**: A third-party Teams app was granted broad permissions.

**DLP in Teams**

Microsoft Purview DLP policies can inspect Teams messages and files shared in Teams for sensitive data types (credit card numbers, Social Security Numbers, custom regex patterns). When a policy matches, Teams will show a warning to the user or block the message entirely. SOC analysts see these as \`DlpRuleMatch\` events in the audit log, with the Teams workload.`,
      checkpoint: {
        question: "An employee gets a Teams chat from “IT Help Desk”, a sender in another organisation's tenant. That sender is not a member of any of your teams. Which Teams feature delivered the message?",
        options: [
          "External Access, which lets other tenants start chats with your users",
          "Guest Access, through a B2B guest account added to one of your teams",
          "A compromised internal account renamed to look like the help desk",
          "A Teams app installed in your tenant that posts messages as a bot",
        ],
        answer: 0,
        explanation:
          "External Access (federation between tenants) lets anyone in another tenant start a chat with your users, and by default it is open. That is the path abused by fake help-desk tenants and by tools like TeamsPhisher. Guest Access would require the sender to be added to one of your teams as a #EXT# guest, which the scenario rules out. A compromised internal account would sit in your own tenant, not another organisation's. A bot from an installed app is also part of your tenant and would show up as an AppInstalled event, not as an external sender.",
      },
    } satisfies ReadingTask,

    // ── Reading 3: DLP and Insider Threat ─────────────────────────────────────
    {
      type: "reading",
      id: "spt-teams-r3",
      heading: "DLP and Insider Threat Detection in Microsoft 365",
      content: `**Data Loss Prevention (DLP)** is a set of policies and technologies designed to detect and prevent the movement of sensitive information outside your organisation. In Microsoft 365, DLP is managed through **Microsoft Purview** (purview.microsoft.com → Data loss prevention).

**How Microsoft Purview DLP Works**

DLP policies define three things:
1. **What to protect** — Sensitive information types (e.g. credit card numbers, UK National Insurance numbers, patient health information, company-defined custom patterns like project codes).
2. **Where to protect it** — Which services to monitor: Exchange email, SharePoint, OneDrive, Teams chats, Endpoint devices, Power BI.
3. **What to do when a match occurs** — Options include: notify the user with a policy tip (warning), block the action (prevent sending/uploading), notify the admin, log the event for audit.

**Key DLP Audit Operations**

- \`DlpRuleMatch\` — A DLP policy rule was triggered. The audit log entry includes: the policy name, the rule that matched, the workload (Exchange/SharePoint/Teams), the user who triggered it, the sensitive information type(s) detected, and the confidence level and count.
- \`DlpRuleUndo\` — A user acknowledged a policy tip and provided a justification to override the block.
- \`DlpRuleActivated\` — A DLP rule was enabled or changed.

**Insider Threat — The Risk from Within**

Insider threats come from current or former employees (or contractors) who misuse their legitimate access to steal, damage, or expose data. They are especially dangerous because:
- They already have authorised access — no need to "break in"
- They know where sensitive data lives
- Their activity can look legitimate until you look closely

**Microsoft Purview Insider Risk Management**

Microsoft Purview offers a dedicated **Insider Risk Management** module (separate from DLP) that uses machine learning to score users based on risky behaviours:
- **Data theft by departing employees**: Triggered when HR feeds show a user's resignation date is approaching and that user starts downloading unusually large amounts of data.
- **Data leaks**: High volume of file uploads to personal cloud storage or email to personal accounts.
- **Security policy violations**: Attempting to access restricted sites or disabling security tools.

The module requires integration with HR systems and applies a risk score to users. High-scoring users appear in the Insider Risk dashboard.

**Behavioural Indicators of Insider Threat in SharePoint**

Even without Purview Insider Risk Management, SOC analysts can identify suspicious insider behaviour by looking for these patterns in the Unified Audit Log:

| Indicator | Description |
|---|---|
| **Bulk download** | User downloads hundreds of files in a short time window (e.g. 847 files in 4 minutes) |
| **Access to previously unvisited folders** | User suddenly accesses Finance or Legal folders they have never touched in 12 months |
| **Off-hours access** | Downloads at 2 AM on a Saturday are unusual for a normal employee |
| **Download from sensitive sites** | Focus on Finance, HR, Legal, Engineering IP repositories |
| **External sharing spike** | Sudden creation of many "Anyone" links or sharing invitations to personal email addresses |
| **OneDrive sync of entire libraries** | Syncing a whole SharePoint library to a personal laptop for offline access; the sync client logs \`FileSyncDownloadedFull\`, while a browser download logs \`FileDownloaded\` |

**Practical Investigation Workflow**

When you receive a DLP alert or a bulk-download alert:

1. Go to **purview.microsoft.com → Audit** and search for the user's \`FileDownloaded\` operations in the last 24–72 hours.
2. Count the volume and look at the file paths — were they from sensitive sites like /Finance/ or /HR/?
3. Check the **ClientIP** field — is this the user's normal corporate IP or an unusual external IP?
4. Cross-reference with **HR systems** — is this employee on a performance improvement plan, under investigation, or about to leave?
5. Check for **external sharing** by the same user: search for \`AnonymousLinkCreated\` or \`SharingInvitationCreated\` with external email addresses.
6. If warranted, **escalate to HR and Legal** — insider threat cases have legal and HR implications beyond technical response.`,
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "spt-teams-q1",
      question: "An attacker creates an anonymous 'Anyone' link for a sensitive financial spreadsheet in SharePoint and shares the URL externally. What is the primary security limitation of this sharing method from a SOC analyst's perspective?",
      options: [
        "Anyone links grant view-only access, so the file itself cannot be downloaded",
        "Anyone links expire after 24 hours by default, so the access evidence disappears",
        "Anyone links need no sign-in, so logged access cannot be tied to a named person",
        "Anyone links bypass the Unified Audit Log, so creation and use are not recorded"
      ],
      answer: 2,
      explanation: "An **Anyone** link needs no authentication, so anyone holding the URL can open the file. Creation (`AnonymousLinkCreated`) and use (`AnonymousLinkUsed`, with client IP and user agent) are logged, but the use records have no identity: you can see that and from where the file was opened, not by whom. View-only is a choice made when the link is created, not a property of all Anyone links, and edit/download links are common. Expiry is an admin setting, not a fixed 24-hour default, and an expired link does not delete the audit records already written. The log does record both events, so the problem is attribution, not missing records.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "spt-teams-q2",
      question: "FileDownloaded events on your Finance SharePoint site show the user `vendor_externalco.com#EXT#@corp.onmicrosoft.com`. What does this UPN tell you, and what should you check first?",
      options: [
        "A sync service principal; check which permissions the app registration holds",
        "A B2B guest from externalco.com; check which team or site granted it access",
        "A hybrid-synced on-prem account; check AD Connect for a broken UPN rewrite",
        "An External Access chat contact; check the Teams federation allow list"
      ],
      answer: 1,
      explanation: "`#EXT#` marks an **Entra ID (Azure AD) B2B guest**: an external user (vendor@externalco.com, with @ replaced by _) invited into your tenant. Guests reach files through the team or site they were added to, so the first question is which membership gave this vendor access to Finance data. A service principal has no UPN of this form. A hybrid-synced employee keeps a normal corp.com-style UPN. External Access contacts chat from their own tenant and get no account in yours, so they cannot appear as a user downloading your SharePoint files.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "spt-teams-q3",
      question: "HR suspects that a departing employee copied Finance files from SharePoint last week. No alert fired. Where do you look for that user's FileDownloaded operations?",
      options: [
        "Message Trace in the Exchange Admin Center",
        "The user's Entra ID sign-in logs for last week",
        "Audit search (Unified Audit Log) in Microsoft Purview",
        "The tenant sharing settings in the SharePoint Admin Center"
      ],
      answer: 2,
      explanation: "SharePoint file operations such as `FileDownloaded`, `FileSyncDownloadedFull` and `AnonymousLinkCreated` are recorded in the **Unified Audit Log**, which you search in the Microsoft Purview portal (purview.microsoft.com → Audit). They are there whether or not an alert fired. Message Trace tracks email delivery, not file activity. Sign-in logs show when and from where the user authenticated, not which files they took. The SharePoint Admin Center sharing page sets tenant policy (for example, whether Anyone links are allowed) and holds no record of user activity.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Log Analysis: Bulk SharePoint Download ────────────────────────────────
    {
      type: "log_analysis",
      id: "spt-teams-la1",
      heading: "Mass File Download Alert — SharePoint",
      context: "You are reviewing alerts in the Microsoft Purview compliance portal. A bulk-download alert has fired for a user in the Finance department. The alert aggregated 847 individual FileDownloaded operations into this summary event. The user's last day of employment is in 3 days according to HR records.",
      event: {
        id: "spt-la1-001",
        ts: "2025-11-21T22:47:15.000Z",
        source: "sharepoint",
        event_type: "sharepoint_download",
        severity: "high",
        description: "Mass file download alert — possible data exfiltration by departing employee",
        user_email: "departing.employee@corp.com",
        src_ip: "10.0.1.55",
        mitre_technique: "T1213.002",
        mitre_tactic: "Collection",
        vendor: "Microsoft 365 Unified Audit Log",
        raw: {
          "data.office365.Operation": "FileDownloaded",
          "data.office365.UserId": "departing.employee@corp.com",
          "data.office365.ClientIP": "10.0.1.55",
          "data.office365.ObjectId": "https://corp.sharepoint.com/sites/Finance/Shared Documents/Q4_Revenue_Report.xlsx",
          "data.office365.Workload": "SharePoint",
          "data.office365.SourceFileName": "Q4_Revenue_Report.xlsx",
          "data.office365.SourceRelativeUrl": "/sites/Finance/Shared Documents/",
          "rule.description": "Mass file download detected — 847 files in 4 minutes",
          "data.office365.SiteUrl": "https://corp.sharepoint.com/sites/Finance",
          "data.office365.EventData": "{\"ListItemUniqueId\":\"a7f9c2e1-...\",\"DestinationUrl\":\"\"}",
          "rule.level": "high"
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "Using the alert, the raw record and the HR context, how should you classify this event?",
          options: [
            "Benign: the OneDrive sync client re-downloading the library after a laptop refresh",
            "Likely insider data theft before departure; escalate to IR, HR and Legal now",
            "Expected: Finance staff pull large report sets during the month-end close",
            "Low priority: the client IP is internal, so the files are still inside the network"
          ],
          answer: 1,
          explanation: "The signals converge: 847 files in 4 minutes from the Finance site, late in the evening (22:47 UTC), by a user who leaves in 3 days. That is the classic pre-departure pattern, so escalate and preserve evidence. A sync-client re-download is the plausible benign story, but the sync client logs `FileSyncDownloadedFull`, and this record's Operation is `FileDownloaded`, a direct download. 21 November is not month-end, and month-end work would not explain this volume at this hour. An internal IP only shows where the download landed; from that laptop the files can still go out by USB, personal cloud or email.",
          xp: 40,
        },
        {
          question: "The alert only captures FileDownloaded operations inside SharePoint. Which MITRE ATT&CK tactic does this bulk-download activity fall under, and what would you still need to confirm to prove data actually left the organisation?",
          options: [
            "Exfiltration: a FileDownloaded record means the files have already left the company",
            "Collection: data is gathered onto a device; a later transfer out still needs proof",
            "Discovery: the user is enumerating the site's contents before choosing what to take",
            "Initial Access: the T1213.002 mapping marks how the user first reached the site"
          ],
          answer: 1,
          explanation: "Pulling files out of a repository such as SharePoint onto a device is **Collection** (T1213.002 is a Collection technique). The data is gathered, but nothing in this record shows it leaving the organisation. To prove exfiltration you need follow-on evidence such as a USB copy, an upload to personal cloud storage or a large outbound email. Calling it exfiltration already is the common misreading: the download went to a device on the internal network. Discovery would be browsing or listing content, but here the files themselves were downloaded. The user already had legitimate access, so there is no Initial Access, and T1213.002 is not an Initial Access technique.",
          xp: 40,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "spt-teams-f1",
      prompt: "To prove exfiltration you must find the endpoint that now holds the downloaded Finance files, then check its USB, personal-cloud and email activity. Using the bulk-download log above, what address do you pivot on to identify that endpoint?",
      answer: "10.0.1.55",
      hint: "The audit record notes where each download request came from.",
      xp: 50,
    } satisfies FlagTask,

  ],
};

// ---------------------------------------------------------------------------
// Room 3 — Endpoint Security Fundamentals
// ---------------------------------------------------------------------------

const endpointSecurityFundamentals: Room = {
  id: "endpoint-security-fundamentals",
  title: "Endpoint Security Fundamentals",
  description:
    "Learn what an endpoint is, how security technology evolved from simple antivirus to modern EDR and XDR, how to read an EDR alert, and how analysts use endpoint tools to investigate and contain threats.",
  difficulty: "beginner",
  category: "Endpoint Security",
  estimatedMinutes: 45,
  xp: 220,
  icon: "💻",
  prerequisites: ["windows-fundamentals"],
  tasks: [

    // ── Reading 1: AV Evolution ───────────────────────────────────────────────
    {
      type: "reading",
      id: "ep-sec-r1",
      heading: "From Antivirus to EDR — The Evolution of Endpoint Security",
      content: `**What is an Endpoint?**

An **endpoint** is any device that connects to a network and can be a target for attack. In a corporate environment, this includes:
- **Laptops and desktops** — The most common endpoints. Used by employees daily.
- **Servers** — High-value targets. They host applications, databases, and sensitive data.
- **Mobile devices** — Smartphones and tablets that connect to company email and apps.
- **IoT devices** — Security cameras, badge readers, smart thermostats, industrial sensors. These are increasingly connected to corporate networks and often have weak security.

**Why Endpoints?**

Attackers target endpoints because they are where humans interact with technology. A human can be tricked into clicking a phishing link, downloading a malicious file, or entering credentials on a fake website. Once an attacker has code running on an endpoint, they can steal data, move to other systems, or deploy ransomware.

---

**Generation 1: Traditional Antivirus (AV) — The Signature Era (1987–2010s)**

Traditional antivirus works like a criminal wanted-poster database. Every known piece of malware is given a unique "fingerprint" called a **signature** — a pattern of bytes found in that specific malware file. When the AV scans a file, it compares it against this database of signatures. If there is a match → malware detected.

**Limitation**: Traditional AV is completely blind to **new malware it has never seen before** (zero-day malware). Attackers figured out that if they change the malware slightly (polymorphic malware) or pack it differently, the signature no longer matches and AV misses it entirely. By the early 2010s, attackers were generating thousands of new malware variants per day, and signature databases simply couldn't keep up.

---

**Generation 2: NGAV — Next-Generation Antivirus (2012–present)**

**NGAV** abandoned pure signature matching in favour of:
- **Behavioural detection**: Instead of asking "does this file match a known bad signature?", NGAV asks "is this process *behaving* like malware?" — for example, does it enumerate all files and start encrypting them? That behaviour pattern is ransomware, even if the file has never been seen before.
- **Machine learning**: Models trained on millions of malware samples can detect new malware based on subtle characteristics, even without an exact signature match.
- **Memory scanning**: Detecting malicious code that runs only in memory without ever writing to disk (fileless malware).
- **Exploit prevention**: Blocking exploitation techniques like buffer overflows and code injection, regardless of the specific vulnerability being exploited.

Products like **CrowdStrike Falcon Prevent**, **SentinelOne Singularity**, and **Microsoft Defender Antivirus** are NGAV solutions.

---

**Generation 3: EDR — Endpoint Detection & Response (2013–present)**

**EDR** is a quantum leap beyond NGAV. Think of NGAV as an alarm system that beeps when someone breaks in. EDR is an alarm system *plus* a full security camera system *plus* a recording of everything that happened before and after the break-in.

EDR's defining characteristic is **continuous monitoring and telemetry recording**. An EDR agent on every endpoint silently records everything:
- Every process that starts (name, command line, parent process, user)
- Every file created, modified, or deleted
- Every network connection made (destination IP, port, process that made it)
- Every registry key changed
- Every PowerShell or script executed

This **telemetry stream** flows to a central cloud platform where it is analysed in real time. This enables:

1. **Threat detection**: Alert when a behaviour pattern matches a known attack technique.
2. **Investigation**: When an alert fires, analysts can look back through the recorded telemetry to understand exactly what happened — a full **process tree** showing parent → child process chains.
3. **Remote response**: Isolate a compromised laptop from the network with one click, kill a malicious process, delete a malicious file — all without touching the physical device.

**Key EDR vendors today (2026)**:
- **CrowdStrike Falcon Insight XDR** — Industry-leading threat intelligence and process telemetry depth.
- **SentinelOne Singularity** — Best autonomous response (can auto-remediate without analyst intervention, including ransomware rollback).
- **Microsoft Defender for Endpoint Plan 2 (MDE)** — Excellent value for Microsoft 365 E5 customers; deep Windows integration; native integration with Entra ID and Purview.
- **Palo Alto Cortex XDR** — Strong in mixed-OS environments (Windows, macOS, Linux).
- **VMware Carbon Black** — Popular in regulated industries.

---

**Generation 4: XDR — Extended Detection & Response (2019–present)**

**XDR** takes the EDR concept and extends it beyond the endpoint:
- **EDR**: Endpoint telemetry only
- **XDR**: Endpoint + Network + Identity + Email + Cloud in one unified platform

Instead of having separate tools for each domain that analysts must correlate manually, XDR correlates telemetry across all these sources automatically. An attack that starts with a phishing email → compromised credentials → lateral movement via PowerShell → data exfiltration to cloud storage can be visualised as a single correlated incident timeline in XDR, rather than scattered alerts across five different tools.

**Microsoft Defender XDR** is Microsoft's XDR platform, combining: Defender for Endpoint, Defender for Office 365, Defender for Identity, and Defender for Cloud Apps.`,
      checkpoint: {
        question: "According to the reading, what is the key limitation of traditional signature-based antivirus?",
        options: [
          "It can only inspect files on removable media such as USB drives, so malware written straight to the system drive is never scanned",
          "It is blind to new malware it has never seen before, and easily evaded by slightly modified (polymorphic) malware",
          "It runs only on Windows, because signature matching depends on NTFS alternate data streams that Linux and macOS filesystems do not provide",
          "It cannot function without a live internet connection, because every file hash must be checked against the vendor's cloud before the file is allowed to open",
        ],
        answer: 1,
        explanation:
          "Signature-based AV compares files against a database of known malware fingerprints, so it misses zero-day malware and can be evaded simply by changing the malware slightly so the signature no longer matches.",
      },
    } satisfies ReadingTask,

    // ── Reading 2: EDR Deep Dive ───────────────────────────────────────────────
    {
      type: "reading",
      id: "ep-sec-r2",
      heading: "EDR Deep Dive — What It Collects and What Analysts Do With It",
      content: `Now that you understand *what* EDR is, let's go deeper into *how* it works and what a SOC analyst actually does with EDR data.

**The EDR Agent**

Every endpoint protected by EDR has a small software program installed on it called an **agent** (also called a sensor or client). This agent runs silently in the background, consuming minimal CPU and memory, and does two things:
1. **Collects telemetry** — Records every process, file, network, and registry event.
2. **Enforces prevention** — Can block malicious behaviour in real-time (NGAV function).

The agent sends telemetry to a central **cloud platform** (e.g. CrowdStrike's Threat Graph, SentinelOne's SentinelCloud, or Microsoft's Defender for Endpoint in Azure). This is where detection rules run and analysts investigate.

**The Process Tree — The Most Powerful Investigation Tool**

Imagine you get an alert: "Suspicious PowerShell command detected on LAPTOP-JSMITH." You open the EDR console and see the **process tree**:

\`\`\`
explorer.exe (PID 1824)  ← User's desktop shell (normal)
  └─ outlook.exe (PID 3312)  ← Email client (normal)
       └─ winword.exe (PID 4456)  ← Word opened an attachment (suspicious!)
            └─ cmd.exe (PID 4892)  ← Word spawned a command prompt (very suspicious!)
                 └─ powershell.exe (PID 5102)  ← PowerShell with encoded command (malicious!)
\`\`\`

This chain tells an incredibly clear story: **a Word document was opened from Outlook, the document ran a macro that spawned cmd.exe, which then ran a malicious PowerShell command**. This is the classic "malicious Office macro" attack chain. Without a process tree, you'd just see a PowerShell alert with no context.

**EDR Telemetry Data Types**

| Data Type | Fields Recorded | Why It Matters |
|---|---|---|
| **Process events** | Process name, PID, parent process, command line, file hash, user, integrity level | Core of investigation — who ran what? |
| **File events** | File path, operation (create/modify/delete), hash, process that caused it | Detect malware being written to disk |
| **Network connections** | Process that made the connection, destination IP and port, bytes transferred | Detect C2 (command-and-control) communications |
| **Registry events** | Key path, operation, new value, process that changed it | Detect persistence mechanisms (malware setting itself to run at boot) |
| **User activity** | Login/logout events, authentication method | Detect lateral movement via stolen credentials |
| **DNS queries** | Domain queried, response IP, process that made the query | Detect malicious domain lookups |

**EDR Response Capabilities**

EDR platforms give analysts powerful remote response capabilities — all from a browser, without touching the physical machine:

- **Network Isolation (Host Isolation)**: Cuts the endpoint off from the network (except for the EDR management channel). The machine cannot talk to anything — not even internal servers. Used when a host is confirmed compromised, to prevent lateral movement. Technically it is one click in the console.
- **Kill Process**: Immediately terminate a malicious process running on the endpoint.
- **Delete File**: Remove a malicious file from the endpoint.
- **Live Response / Remote Shell**: Open a remote command-line shell on the endpoint for in-depth forensic investigation. SOC analysts can run commands, collect files, and examine artefacts without physically touching the device.
- **Run Containment Script**: Push a custom script to the endpoint (e.g. to disable a compromised service or quarantine a file).
- **Collect Forensic Package**: Collect a bundle of artefacts (event logs, memory dump, prefetch files, registry hives) from the endpoint for offline analysis.

**"One click" is the technical cost, not the real one.** This is the part that separates a console operator from an analyst, so be clear-eyed about it: isolation is an *outage you are choosing to cause*. Isolating a developer's laptop costs that person an afternoon. Isolating a domain controller, a database server, a payment gateway, or the PC running a hospital ward's medication system can be more damaging than the malware you are containing — and on a busy shift, under pressure, that is a genuinely easy mistake to make.

So before you isolate, answer three questions:
- **What does this asset do?** A hostname alone tells you nothing. Check the asset inventory or CMDB for its role, its business owner, and its criticality tier.
- **Who has to know?** Most organisations require the system owner to be notified, and many require a change/emergency-change approval for production systems. Some run a standing pre-authorisation for endpoints but not for servers — learn where that line sits in *your* environment, before you need it.
- **Is there a lighter option that still stops the bleeding?** Killing the malicious process, blocking one destination at the firewall, or disabling the compromised account will sometimes contain the incident without taking the whole host offline.

None of this means "hesitate while an attacker encrypts your file server." When the evidence is strong and the spread is active, isolate and explain afterwards — a short outage beats a domain-wide compromise. The point is that isolation is a *decision with a cost on both sides*, and a good analyst can say out loud why they judged the cost of acting to be lower than the cost of waiting.

**Endpoint Hardening — Reducing the Attack Surface**

EDR detects threats *after* they start. **Endpoint hardening** reduces the attack surface so fewer threats can start:
- **Attack Surface Reduction (ASR) rules** in Microsoft Defender: Block Office macros from spawning processes, block credential theft from LSASS, block executable content in email.
- **Application allowlisting**: Only run approved software. If it's not on the approved list, it can't run.
- **Least privilege**: Users run as standard users, not local administrators. Malware running as the user has limited rights.
- **BitLocker**: Full-disk encryption so stolen laptops don't expose data.
- **Patch management**: Keep the OS and applications updated to close known vulnerabilities.`,
      checkpoint: {
        question: "According to the reading, what does 'Network Isolation (Host Isolation)' do when an analyst triggers it from the EDR console?",
        options: [
          "It permanently deletes the endpoint's data",
          "It cuts the endpoint off from the network except for the EDR management channel",
          "It only blocks outbound email from the endpoint",
          "It uninstalls the EDR agent from the endpoint",
        ],
        answer: 1,
        explanation:
          "Host Isolation cuts the machine off from talking to anything else on the network — even internal servers — while keeping the EDR management channel alive, so analysts can still investigate and remediate remotely.",
      },
    } satisfies ReadingTask,

    // ── Reading 3: Reading EDR Alerts ─────────────────────────────────────────
    {
      type: "reading",
      id: "ep-sec-r3",
      heading: "How to Read an EDR Alert — A Step-by-Step Approach",
      content: `When an alert appears in your EDR console, it can feel overwhelming at first. There's a lot of information. This reading walks you through a structured approach to reading any EDR alert.

**The Anatomy of a CrowdStrike Alert**

CrowdStrike Falcon is one of the most widely deployed EDR platforms. When it fires an alert, the key fields are:

| Field | What It Is | Example |
|---|---|---|
| \`AlertType\` | Category of the alert | "Process", "Network", "File" |
| \`Severity\` | How bad CrowdStrike thinks it is | Critical, High, Medium, Low |
| \`Technique\` | MITRE ATT&CK technique ID | T1059.001 |
| \`TechniqueName\` | Human name of the technique | "Command and Scripting Interpreter: PowerShell" |
| \`ContextProcessName\` | The process that triggered the alert | powershell.exe |
| \`ContextProcessParentName\` | What launched the alerting process | cmd.exe |
| \`CommandLine\` | The exact command that was run | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JAB... |
| \`UserName\` | Who was logged in | CORP\\j.smith |
| \`HostName\` | Which machine | LAPTOP-JSMITH |
| \`LocalIP\` | IP address of the machine | 10.0.1.55 |
| \`SHA256\` | Cryptographic hash of the process executable | a1b2c3... |
| \`Confidence\` | How confident CrowdStrike is (0–100) | 95 |

**Step-by-Step Alert Analysis**

**Step 1: Read the alert title and technique**
What is the alert about, broadly? If it says "T1059.001 — PowerShell" you know you're looking at PowerShell abuse, which is extremely common in attacks. If it says "T1003 — OS Credential Dumping" (a technique under the Credential Access tactic, TA0006) you know someone tried to dump credentials.

**Step 2: Identify the affected host and user**
Who and what machine are affected? Is this a finance server (critical) or a developer laptop (important but lower blast radius)? Is the user an administrator or a regular employee?

**Step 3: Examine the command line**
The command line is often the most revealing field. For PowerShell alerts, look for:
- \`-Enc\` or \`-EncodedCommand\`: The command is Base64-encoded to hide what it's doing. Frequently abused and always worth decoding — but management tools (SCCM/ConfigMgr, Intune, many RMM agents) use it too, so judge by the parent process and the decoded content.
- \`-ExecutionPolicy Bypass\` or \`-Exec Bypass\`: Bypassing PowerShell's script execution policy. Attackers use it constantly, but so do legitimate management tools — again, the parent process and what the script does decide it.
- \`-NoP\` or \`-NoProfile\`: Skips loading the user's profile scripts, giving a clean, predictable session. It does NOT switch off PowerShell logging — Script Block Logging, Module Logging and Transcription are set by Group Policy and still record the session. Common in both admin tooling and malware.
- \`-NonI\` or \`-NonInteractive\`: Running without user interaction — indicates automated/scripted execution.
- \`-W Hidden\` or \`-WindowStyle Hidden\`: Hiding the PowerShell window from the user. Malware doesn't want to be seen.
- \`IEX\` or \`Invoke-Expression\`: Executing a string as a command — often used to execute code downloaded from the internet.
- \`DownloadString\` or \`WebClient\`: Downloading code from the internet.

**Step 4: Check the process tree**
Who launched this process? Normal PowerShell usage might be launched by an admin tool or the Windows Task Scheduler. **PowerShell launched by Word, Excel, or Outlook is a major red flag** — it means a document executed malicious code.

**Step 5: Check the hash against threat intelligence**
Copy the SHA256 hash and paste it into **VirusTotal** (virustotal.com) or your threat intelligence platform. If 40 out of 72 antivirus engines flag it as malicious, that confirms the alert.

**Step 6: Look for follow-on activity**
EDR alert timelines let you look at what happened before and after the alert. Did the PowerShell process make any network connections? Did it create any files? Did it spawn any child processes? This tells you whether the attacker succeeded or was caught early.

**Step 7: Determine the response action**
Based on your analysis:
- **Clearly malicious with active threat**: Isolate the host immediately, kill the process, escalate.
- **Suspicious but uncertain**: Escalate to senior analyst, collect forensic package, investigate further.
- **False positive**: Document why and tune the detection rule if needed.

**Common PowerShell Flags and Their Meaning**

| Flag | Short Form | Meaning | Malware Use |
|---|---|---|---|
| \`-NoProfile\` | \`-NoP\` | Skip loading the user's PowerShell profile scripts | A clean, predictable session free of user customisations (does not disable Script Block Logging) |
| \`-NonInteractive\` | \`-NonI\` | Run without prompting the user for input | Automated/scripted execution |
| \`-WindowStyle Hidden\` | \`-W Hidden\` | Hide the PowerShell console window | Don't show the user a black window |
| \`-ExecutionPolicy Bypass\` | \`-Exec Bypass\` | Skip PowerShell script execution policy | Run scripts blocked by policy |
| \`-EncodedCommand\` | \`-Enc\` | Accept a Base64-encoded command | Obfuscate the command from simple string-matching |`,
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q1",
      question: "What is the fundamental difference between traditional signature-based antivirus and EDR (Endpoint Detection & Response)?",
      options: [
        "Traditional AV is a cloud-only service with no device software, while EDR runs wholly locally with no cloud console",
        "Traditional AV matches files against known-bad signatures; EDR records endpoint activity and detects behaviour for hunting",
        "EDR works only on Windows because it relies on ETW, so AV remains the only option for Linux and macOS",
        "Traditional AV can isolate a host on demand, whereas EDR is passive alerting with no containment"
      ],
      answer: 1,
      explanation: "The key difference is **scope and approach**. Traditional AV relies on known-bad **signatures** — it cannot detect new malware it has never seen before. EDR continuously records all endpoint telemetry (processes, files, network connections, registry changes) and applies **behavioural analysis** to detect threats regardless of whether they have known signatures. EDR also provides **visibility** for investigation (process trees, command lines, timelines) and **response** capabilities (host isolation, remote shell) that traditional AV completely lacks.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q2",
      question: "An EDR alert shows the following process tree: `winword.exe → cmd.exe → powershell.exe -Enc JAB...`. What does this process chain most likely indicate?",
      options: [
        "A legitimate Office macro running a system administration script",
        "A malicious Word macro launching PowerShell with an obfuscated encoded command",
        "An Office update component calling PowerShell through cmd.exe to install patches",
        "A Word add-in installer running an encoded PowerShell setup routine"
      ],
      answer: 1,
      explanation: "**winword.exe spawning cmd.exe which spawns powershell.exe** is one of the most classic malicious process chains in endpoint security. Word does not normally spawn command prompts or PowerShell shells during legitimate use. This chain indicates a **malicious Office macro** (embedded in a document) that executed system commands. The `-Enc` flag on PowerShell means the actual command is Base64-encoded — a strong obfuscation indicator. This should be treated as a high-priority true positive.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q3",
      question: "A user's laptop is confirmed to be infected with malware that is actively spreading to other machines on the network. What is the most important immediate EDR response action?",
      options: [
        "Delete the malware file from disk, which also terminates the running instance",
        "Run a full antivirus scan of the laptop before touching the network",
        "Network-isolate the host with EDR to stop further lateral movement",
        "Reboot the laptop so the malware is cleared from memory"
      ],
      answer: 2,
      explanation: "**Host isolation** (also called network isolation or containment) is the single most important immediate action when a host is actively spreading malware. Isolation cuts the device off from all network communication (except the EDR management channel), preventing the malware from reaching additional hosts, communicating with a command-and-control server, or exfiltrating data. Deleting the malware file and rebooting are secondary steps that come after containment. A full AV scan is also secondary and may miss fileless malware.\n\nNote what makes this an easy call: it is a **user's laptop**, and the spread is **confirmed and active**. Both halves matter. Change either one — a production database server instead of a laptop, or a single suspicious process instead of confirmed spreading — and the calculation shifts, because isolation is an outage you are deliberately causing. Reading 2 covers the questions to ask first when the asset is business-critical.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q4",
      question: "What does XDR (Extended Detection & Response) add compared to EDR (Endpoint Detection & Response)?",
      options: [
        "XDR is the same endpoint-only telemetry as EDR behind a nicer incident dashboard",
        "XDR extends beyond the endpoint to network, identity, email and cloud data, correlated in one platform",
        "XDR replaces EDR's behavioural detection with a much larger signature database",
        "XDR is the mobile-device tier of EDR, covering iOS and Android handsets"
      ],
      answer: 1,
      explanation: "The 'X' in **XDR** stands for 'Extended' — it extends detection and response **across multiple security domains** beyond just the endpoint. While EDR sees only what happens on a single device, XDR correlates telemetry from endpoints, network traffic, identity systems (Active Directory, Entra ID), email (Exchange, phishing), and cloud workloads (AWS, Azure). This cross-domain correlation allows XDR to detect multi-stage attacks that would appear as disconnected, low-confidence signals in isolated tools. Microsoft Defender XDR, CrowdStrike Falcon XDR, and SentinelOne Singularity XDR are current examples.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Log Analysis: CrowdStrike Alert — Malicious PowerShell ────────────────
    {
      type: "log_analysis",
      id: "ep-sec-la1",
      heading: "CrowdStrike Alert — Suspicious PowerShell Execution",
      context: "You are a Tier 1 SOC analyst. A CrowdStrike Falcon alert has just appeared in your queue. The alert was generated on an employee's laptop. Your task is to analyse the alert details and answer the investigation questions below.",
      event: {
        id: "ep-la1-001",
        ts: "2025-11-19T14:32:07.000Z",
        source: "edr",
        vendor: "CrowdStrike Falcon",
        event_type: "edr_alert",
        severity: "high",
        description: "CrowdStrike: Suspicious encoded PowerShell execution — possible post-exploitation",
        hostname: "LAPTOP-JSMITH",
        user_email: "j.smith@corp.com",
        src_ip: "10.0.1.55",
        mitre_technique: "T1059.001",
        mitre_tactic: "Execution",
        process: {
          name: "powershell.exe",
          pid: 4892,
          parent_name: "cmd.exe",
          cmdline: "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMAUAB...",
          hash: { sha256: "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab" }
        },
        // Field names follow the same Falcon schema as malware-analysis (batch-07)
        // and edr-detection-investigation (batch-28): event_simpleName,
        // SeverityName, ParentProcessName, SHA256HashData, DetectionId. An
        // earlier version used AlertType / Severity / SHA256 / ContextProcessParentName,
        // which meant a student meeting CrowdStrike in two different rooms saw two
        // conflicting sets of "real" field names for the same product.
        raw: {
          "crowdstrike.event_simpleName": "DetectionSummaryEvent",
          "crowdstrike.DetectionId": "ldt:8f3c1a92b7e44d05:44117",
          "crowdstrike.SeverityName": "High",
          "crowdstrike.Confidence": "95",
          "crowdstrike.Tactic": "Execution",
          "crowdstrike.Technique": "T1059.001",
          "crowdstrike.TechniqueName": "PowerShell",
          "crowdstrike.PatternDispositionDescription": "Detection, Process Killed",
          "crowdstrike.ContextProcessName": "powershell.exe",
          "crowdstrike.ContextProcessId": "4892",
          "crowdstrike.ParentProcessName": "cmd.exe",
          "crowdstrike.CommandLine": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0A...",
          "crowdstrike.UserName": "CORP\\j.smith",
          "crowdstrike.HostName": "LAPTOP-JSMITH",
          "crowdstrike.LocalIP": "10.0.1.55",
          "crowdstrike.SHA256HashData": "505e6a45917684bf24f4603e189a29713c196e734821c6df2b104e7147d53ff0",
          "crowdstrike.FalconHostLink": "https://falcon.crowdstrike.com/activity/detections/detail/8f3c1a92",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "CrowdStrike's confidence score for this alert is 95. What does this score indicate?",
          options: [
            "95 % of the malware's capabilities have already executed on the host",
            "CrowdStrike is 95 % confident the activity is malicious, based on ML models and threat intelligence",
            "95 % of the detection engines the sensor consulted agreed it is malicious",
            "The alert's business-impact severity is 95 on a 0–100 scale"
          ],
          answer: 1,
          explanation: "In CrowdStrike, the **Confidence score (0–100)** represents how certain CrowdStrike's detection models are that the observed activity is malicious, based on machine-learning analysis, Threat Graph intelligence, and pattern matching against known attack techniques. A score of 95 is very high — this is almost certainly malicious activity and should be treated as a true positive pending analyst confirmation. Low confidence scores (below 50) warrant more careful evaluation for false positives.",
          xp: 35,
        },
        {
          question: "The command line includes `-W Hidden`. What is the purpose of this flag in the context of this attack?",
          options: [
            "It runs PowerShell with elevated rights that are hidden from access controls",
            "It hides the PowerShell console window so the logged-in user cannot see it running",
            "It hides the script's network connections from the host firewall logs",
            "It writes the command's output to a hidden file instead of the console"
          ],
          answer: 1,
          explanation: "`-WindowStyle Hidden` (shortened to `-W Hidden`) instructs PowerShell to launch with a hidden window style — meaning no black PowerShell console window appears on screen. Legitimate PowerShell scripts sometimes use this for cleaner UX, but in the context of malware, it is used to hide the malicious activity from the victim user sitting at the keyboard. Combined with `-NoP` (no profile), `-NonI` (non-interactive), and `-Exec Bypass` (bypass execution policy), this is a textbook malicious PowerShell execution pattern.",
          xp: 35,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "ep-sec-f1",
      prompt: "Look at the CrowdStrike alert log above. Falcon killed the process, but your ticket still has to say what the script actually did — and from this alert alone, you can't. One of the flags in the PowerShell command line is the reason. Enter that flag exactly as it appears in the command line (the flag only, without the value that follows it).",
      answer: "-Enc",
      hint: "Read the crowdstrike.CommandLine field flag by flag. Most of the flags change HOW PowerShell runs (profile, prompts, window, policy); only one changes whether a human can READ what it ran. The 'Common PowerShell Flags' table in the reading maps each short form to its meaning.",
      xp: 50,
    } satisfies FlagTask,

  ],
};

// ---------------------------------------------------------------------------
// Room 4 — Microsoft Defender XDR
// ---------------------------------------------------------------------------

const defenderXdr: Room = {
  id: "defender-xdr",
  title: "Microsoft Defender XDR",
  description:
    "Master Microsoft's unified security platform. Learn to investigate incidents across Defender for Endpoint, Office 365, and Identity. Write KQL Advanced Hunting queries and detect lateral movement, credential theft, and cloud-based attacks.",
  difficulty: "intermediate",
  category: "Endpoint Security",
  estimatedMinutes: 55,
  xp: 320,
  icon: "🛡️",
  prerequisites: ["endpoint-security-fundamentals", "microsoft-365-security", "security-products-behaviour"],
  tasks: [

    // ── Reading 1: MDE Overview & Onboarding ──────────────────────────────────
    {
      type: "reading",
      id: "def-xdr-r1",
      heading: "Microsoft Defender XDR — The Unified Security Platform",
      content: `**Microsoft Defender XDR** (formerly Microsoft 365 Defender) is Microsoft's integrated extended detection and response platform. It is accessed at **security.microsoft.com** and unifies multiple security products into a single portal with correlated incidents, a shared alert queue, and cross-domain threat hunting.

**The Components of Microsoft Defender XDR**

Think of Defender XDR as the "mother platform" that aggregates signals from four specialised products:

| Component | What It Protects | Key Capability |
|---|---|---|
| **Defender for Endpoint (MDE)** | Windows, macOS, Linux, mobile devices | EDR telemetry, device risk score, live response, vulnerability management |
| **Defender for Office 365 (MDO)** | Exchange email, Teams, SharePoint, OneDrive | Anti-phishing, Safe Attachments, Safe Links, Threat Explorer |
| **Defender for Identity (MDI)** | Active Directory Domain Controllers, Entra ID | Detect Kerberoasting, DCSync, lateral movement, Pass-the-Hash |
| **Defender for Cloud Apps (MDCA)** | SaaS apps (Salesforce, Box, Dropbox, ServiceNow, etc.) | Shadow IT discovery, anomaly detection, Cloud App policies |

When an attack spans multiple domains (e.g. phishing email → compromised account → lateral movement via PSEXEC), Defender XDR automatically **correlates** all the related alerts from all components into a single **incident**. This is what sets XDR apart from standalone tools.

---

**Microsoft Defender for Endpoint (MDE) — Deep Dive**

**MDE Onboarding** — Getting devices under MDE management:

- **GPO (Group Policy)**: Deploy the MDE onboarding package to domain-joined Windows machines via Active Directory Group Policy. Most common in enterprise environments.
- **Microsoft Intune / Endpoint Manager**: Mobile Device Management (MDM) deployment, ideal for modern cloud-managed devices (Azure AD-joined laptops, BYOD).
- **Microsoft Configuration Manager (SCCM/MECM)**: For organisations with existing SCCM infrastructure.
- **Local script**: Download and run the onboarding script manually. Used for testing or very small deployments.
- **Linux / macOS**: Manual package deployment or management tool-based deployment.

Once onboarded, each device appears in the **Device Inventory** (security.microsoft.com → Assets → Devices).

**Device Inventory — What You See**

Each device in the inventory shows:
- **Device name and OS**: LAPTOP-JSMITH, Windows 11 22H2
- **Risk Level**: Critical / High / Medium / Low — calculated from active alerts and unpatched vulnerabilities
- **Exposure Score**: How vulnerable is this device to known attack techniques? (0–100)
- **Onboarding status**: Whether the MDE agent is active and reporting
- **Last seen**: When the device last checked in
- **Installed software**: Complete software inventory for vulnerability management

**Alert Queue and Incident Page**

MDE generates alerts when it detects suspicious behaviour. Each alert shows:
- **Severity**: Critical, High, Medium, Low, Informational
- **Detection source**: EDR (behavioural detection), Antivirus, Network protection, Threat Intelligence
- **MITRE ATT&CK mapping**: The technique (e.g. T1055 — Process Injection) and tactic (e.g. Defense Evasion)
- **Affected entity**: Device name and user

Multiple related alerts are automatically grouped into **Incidents**. The incident page shows:
- **Incident graph**: A visual map of affected devices, users, email addresses, and processes, with connecting lines showing relationships
- **Evidence**: All files, IPs, domains, and users involved across all correlated alerts
- **Timeline**: Chronological sequence of events across all affected devices
- **Recommendations**: Automated response suggestions (isolate device, run antivirus scan)

**MDE Timeline — The Investigator's Best Friend**

Every onboarded device has a **Timeline** view (Device page → Timeline tab). This shows every recorded event on that device in chronological order, going back up to 180 days. SOC analysts use the timeline to:
- Find the initial access event (when did the attacker first appear on this device?)
- Trace the attack chain (what happened step by step?)
- Identify the patient-zero device (was this machine the first compromised or was the malware spread from elsewhere?)

**Live Response — Remote Forensics**

MDE Live Response provides a remote interactive shell to any onboarded endpoint, including one that MDE has network-isolated (isolation keeps the device's connection to the Defender service open). From security.microsoft.com, analysts can:
- Browse the file system
- Collect specific files for analysis
- Run investigative commands (\`tasklist\`, \`netstat\`, \`dir\`)
- Upload and execute response scripts
- Collect memory dumps

This eliminates the need for physical access to investigate a compromised device.`,
      checkpoint: {
        question: "A laptop was network-isolated through MDE an hour ago. You now need a copy of a suspicious file from its disk, and nobody can reach the laptop physically. What is the best way to get it?",
        options: [
          "Use Live Response; it still connects to an isolated device",
          "Export the file from the device Timeline entry that shows it",
          "Query DeviceFileEvents in Advanced Hunting to retrieve the file",
          "Release isolation briefly and copy the file over an SMB share",
        ],
        answer: 0,
        explanation:
          "Live Response works on any onboarded device, including an isolated one, because isolation keeps the connection to the Defender service open; collecting files is one of its core functions. The Timeline shows that the file event happened, but it does not hold the file's contents. Advanced Hunting tables hold metadata (name, path, hashes), not the file. Releasing isolation reconnects a possibly compromised host to the network just to copy a file that Live Response can collect safely.",
      },
    } satisfies ReadingTask,

    // ── Reading 2: Alert Investigation ────────────────────────────────────────
    {
      type: "reading",
      id: "def-xdr-r2",
      heading: "Investigating Incidents in Microsoft Defender XDR",
      content: `A new incident in Defender XDR can look overwhelming at first. This reading gives you a structured investigation methodology and explains each component of the incident page.

**The Defender XDR Incident Workflow**

When an incident is assigned to you:

**1. Read the Incident Summary**

The incident title usually tells you the primary alert that triggered grouping. Example: "Multi-stage attack using PowerShell and network reconnaissance". Look at:
- **Severity**: How urgent is this?
- **Number of alerts**: How many individual detections were grouped?
- **Number of affected devices and users**: What is the blast radius?
- **Attack categories**: What did the attacker do? (Initial Access, Execution, Persistence, Lateral Movement)

**2. Examine the Incident Graph**

The incident graph visually connects the dots. You might see:
- An email (Defender for Office 365 flagged a phishing email)
- A user account (the same user authenticated from an unusual location)
- A device (the user's laptop where malware ran)
- An external IP (the command-and-control server the malware contacted)
- Another device (where the attacker moved laterally)

This graph answers: **how are all the pieces connected?**

**3. Investigate Each Alert**

Click into each alert within the incident. For an MDE alert:
- **Process details**: What was the exact command line?
- **Process tree**: What spawned what?
- **File details**: What files were created or modified?
- **Network activity**: What external connections were made?

**4. Check the Device Timeline**

From the affected device page, open the Timeline. Filter the timeline around the time of the first alert and look 30–60 minutes earlier — attackers often perform reconnaissance before their loudest action. Look for:
- Unusual process executions before the alert time
- Network connections to external IPs
- Credential access attempts

**5. Check for Lateral Movement**

In the incident graph, look for additional devices. If the attacker moved from Device A to Device B, you'll see alerts on both. Common lateral movement tools:
- **PsExec**: Sysinternals tool that allows remote command execution. Abused constantly. It copies a service binary, \`PSEXESVC.exe\`, to the target and starts it as a service, so the account used must already be a local administrator there. On the target, the remote command appears as a child process of \`PSEXESVC.exe\`. By default it runs as the connecting account; with PsExec's \`-s\` option it runs as \`NT AUTHORITY\\SYSTEM\` instead.
- **WMI (Windows Management Instrumentation)**: Built-in Windows remote management.
- **RDP (Remote Desktop Protocol)**: If the attacker has credentials, they can RDP to other machines.
- **SMB (Server Message Block)**: File sharing protocol often used to deploy malware to network shares.

**6. Identify the Attack Timeline (ATT&CK Tactics)**

Map the events to MITRE ATT&CK tactics (the attack stages; not to be confused with Lockheed Martin's separate Cyber Kill Chain model):
- **Initial Access**: How did they get in? (Phishing? VPN with stolen credentials? Exploited vulnerability?)
- **Execution**: What code did they run? (Malicious macro, PowerShell, scheduled task?)
- **Persistence**: How did they ensure they survive a reboot? (Registry run key, scheduled task, new service?)
- **Privilege Escalation**: Did they move from a normal user to admin?
- **Defense Evasion**: Did they try to avoid detection? (Disable AV, delete logs, use LOLBins — Living Off the Land Binaries?)
- **Credential Access**: Did they steal credentials? (LSASS dump, Kerberoasting?)
- **Discovery**: Did they map the network? (Port scans, AD enumeration?)
- **Lateral Movement**: Did they move to other machines? (PsExec, WMI, RDP?)
- **Collection & Exfiltration**: Did they steal data?

**7. Containment and Response**

Based on your investigation:
- **Isolate compromised devices** (MDE network isolation with one click)
- **Reset compromised accounts** (via Entra ID or Active Directory)
- **Block IOCs** (Add malicious IPs, domains, and file hashes to the MDE indicators list for automatic blocking)
- **Run AV scan** on affected devices
- **Revoke active sessions** for compromised accounts (Entra ID → Users → select the user → Revoke sessions)
- **Revoke OAuth consent** granted to a malicious app, because the app's tokens are separate from the user's password

**Two cloud identity attacks to recognise**

- **Illicit consent grant (consent phishing)**: the user is tricked into approving a malicious OAuth app that asks for permissions such as Mail.Read or Mail.ReadWrite. The app then reads the mailbox with its own tokens, which keep working after a password reset until the consent is revoked. In telemetry: a consent event for a new, unverified app shortly after a risky sign-in.
- **Adversary-in-the-middle (AiTM) phishing**: a phishing page relays the real Microsoft sign-in, so the user enters their password and approves their own MFA prompt while the attacker captures the session. In telemetry: a successful sign-in with MFA from an unfamiliar IP or unmanaged device. A quick MFA approval therefore does not prove the sign-in was legitimate; it fits AiTM as well as a fatigued user tapping Approve.

**Defender for Identity (MDI) Alerts**

MDI monitors your on-premises Active Directory domain controllers and Azure Entra ID for identity-based attacks. Key alerts SOC analysts see from MDI:

| MDI Alert | Attack Technique |
|---|---|
| Suspected Kerberoasting activity | T1558.003 — Kerberoasting: request TGS tickets for service accounts to crack offline |
| Suspected DCSync attack | T1003.006 — DCSync: simulate a DC to replicate all password hashes from AD |
| Lateral movement path to sensitive entity | Graph-based lateral movement risk |
| Pass-the-Hash / Pass-the-Ticket | T1550 — Credential reuse without the plaintext password |
| Reconnaissance using LDAP queries | T1087 — Account enumeration via LDAP |
| Suspicious additions to sensitive groups | T1098 — Adding a backdoor account to Domain Admins |`,
      checkpoint: {
        question: "An MDE alert fires at 14:05 for a PsExec launch on a workstation. Why should you open the device Timeline well before 14:05 instead of starting at the alert time?",
        options: [
          "Quieter reconnaissance usually comes before the loud action that fired the alert",
          "The Timeline keeps only the events from the hour before an alert is raised",
          "Alert times are shown in UTC, so the real activity happened hours earlier",
          "Events after the alert are already summarised in the incident graph instead",
        ],
        answer: 0,
        explanation:
          "Alerts usually fire on the loudest step. Reconnaissance, credential access and the first execution often happen quietly beforehand, so starting earlier (the reading suggests 30–60 minutes) shows how the attacker got there. The Timeline goes back up to 180 days, not one hour. UTC is a display-format question: converting time zones does not uncover earlier activity. The incident graph shows how entities are connected; it does not replace reading the events that came before the alert.",
      },
    } satisfies ReadingTask,

    // ── Reading 3: Advanced Hunting KQL ───────────────────────────────────────
    {
      type: "reading",
      id: "def-xdr-r3",
      heading: "Advanced Hunting with KQL — Proactive Threat Hunting",
      content: `**Advanced Hunting** is one of the most powerful features in Microsoft Defender XDR. It allows analysts to write queries against raw telemetry data to proactively search for threats — even before an alert fires. Advanced Hunting is accessed at: **security.microsoft.com → Hunting → Advanced Hunting**.

**KQL — Kusto Query Language**

Advanced Hunting queries are written in **KQL (Kusto Query Language)**, which is also used by Microsoft Sentinel (Microsoft's SIEM). KQL is designed to be readable, intuitive, and powerful for security analysis.

**KQL Basics**

A KQL query follows this general structure:
\`\`\`kql
TableName
| where Timestamp > ago(7d)               // Filter: last 7 days
| where ColumnName == "value"              // Filter by a specific column
| project ColumnA, ColumnB, ColumnC       // Select which columns to show
| summarize Count = count() by ColumnA    // Aggregate (count per group)
| order by Count desc                     // Sort results
| limit 100                               // Return top 100 results
\`\`\`

KQL uses the **pipe operator** (\`|\`) — each step transforms the result of the previous step. Advanced Hunting tables use the \`Timestamp\` column for event time; the same data in Microsoft Sentinel uses \`TimeGenerated\`.

**The Advanced Hunting Tables**

Defender XDR exposes raw telemetry in structured tables. Key tables:

| Table | Contains |
|---|---|
| \`DeviceProcessEvents\` | Process creation events: name, command line, parent, user, SHA256 |
| \`DeviceNetworkEvents\` | Network connections: process, remote IP, remote port, URL |
| \`DeviceFileEvents\` | File creation, modification, deletion events |
| \`DeviceRegistryEvents\` | Registry key reads and writes |
| \`DeviceLogonEvents\` | Sign-ins on the device: account, logon type (interactive, network, RDP), remote IP and device |
| \`DeviceEvents\` | Miscellaneous security events: ASR and exploit-protection events, antivirus detections, PowerShell commands and more |
| \`AlertInfo\` / \`AlertEvidence\` | Alerts from all Defender products, and the devices, files, users and IPs attached to each alert |
| \`EmailEvents\` | Email delivery events (from Defender for Office 365) |
| \`EmailAttachmentInfo\` | Attachment metadata for emails |
| \`IdentityLogonEvents\` | Identity authentication events (AD, Entra ID) |
| \`CloudAppEvents\` | Activity from cloud apps monitored by MDCA |

**Practical Example Queries**

**Query 1: Find all PowerShell with encoded commands in the last 7 days**
\`\`\`kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\\s-(e|ec|en|enc\\w*)\\s"   // -e, -ec, -enc, -EncodedCommand…
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
\`\`\`
Encoded PowerShell is worth reviewing, because attackers use it to hide script content. It is not malicious by itself: management tools such as Configuration Manager (CcmExec.exe) and Intune also launch encoded commands. Decode the content and check the parent process and account; an Office application, a browser or an unusual account as the parent deserves priority. The regex catches the short forms (-e, -ec, -enc) that a plain match on "-Enc" would miss.

**Query 2: Find processes making network connections to rare external IPs**
\`\`\`kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe")
| summarize DeviceCount = dcount(DeviceName), Devices = make_set(DeviceName) by RemoteIP, InitiatingProcessFileName
| where DeviceCount < 3   // rare: fewer than 3 devices contacted this IP
| order by DeviceCount asc
\`\`\`

**Query 3: Detect PsExec lateral movement**
\`\`\`kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "PSEXESVC.exe" or ProcessCommandLine has "psexec"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
\`\`\`

**Query 4: Join tables — find processes that made network connections (hunting for C2)**
\`\`\`kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "powershell.exe"
| join kind=inner DeviceNetworkEvents on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
\`\`\`
This joins process events with network events to find PowerShell processes that made outbound connections — a strong C2 indicator.

**Custom Detection Rules**

Advanced Hunting queries can be saved as **Custom Detection Rules** that run on a schedule (every hour, every day) and automatically create alerts when the query returns results. This is how threat hunters turn hunting queries into continuous monitoring. Go to: Advanced Hunting → Create detection rule.

**Microsoft Secure Score — Endpoint Contribution**

**Microsoft Secure Score** (security.microsoft.com → Secure Score) measures your organisation's security posture as a score from 0 to the maximum possible points. The endpoint section includes points for:
- Percentage of devices onboarded to MDE
- Percentage of devices with antivirus enabled
- Percentage of devices with Attack Surface Reduction rules enabled
- Percentage of devices with BitLocker encryption
- Vulnerability management: percentage of critical vulnerabilities remediated

SOC analysts often track Secure Score as a KPI for endpoint security health.`,
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q1",
      question: "From a contractor laptop that has no MDE agent, someone requests Kerberos service tickets for 40 different service accounts within one minute. No malware runs. Which Defender XDR component can still raise an alert on this?",
      options: [
        "Defender for Endpoint, from the ticket requests recorded on the laptop",
        "Defender for Office 365, by tracing the phishing email that began it",
        "Defender for Identity, whose domain-controller sensors see the requests",
        "Defender for Cloud Apps, which inspects Entra ID token issuance"
      ],
      answer: 2,
      explanation: "This is the Kerberoasting pattern (T1558.003), and the ticket requests are answered by the domain controllers. **Defender for Identity** runs its sensors on the DCs, so it sees them whatever the client is. That is why it still alerts when the source laptop is unmanaged. Defender for Endpoint needs its agent on the device, and this laptop has none. Defender for Office 365 covers email and collaboration; even if a phishing email started the attack, it does not see Kerberos traffic. Defender for Cloud Apps watches SaaS and cloud activity, while these tickets are issued by on-premises Active Directory, not by Entra ID.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q2",
      question: "In a KQL Advanced Hunting query, you want to find all PowerShell processes that made outbound network connections to public IPs in the last 24 hours. Which two tables would you join to answer this question?",
      options: [
        "AlertEvidence and DeviceNetworkEvents",
        "DeviceProcessEvents and DeviceNetworkEvents",
        "DeviceProcessEvents and DeviceLogonEvents",
        "IdentityLogonEvents and DeviceNetworkEvents"
      ],
      answer: 1,
      explanation: "To tie **which process** to **which connection**, join:\n- **DeviceProcessEvents**: process creation, with the process name (powershell.exe), command line and ProcessId.\n- **DeviceNetworkEvents**: connections, with RemoteIP, RemotePort, RemoteIPType and the InitiatingProcessId of the process that opened them.\nJoin on DeviceId and ProcessId = InitiatingProcessId, as in Query 4. AlertEvidence only holds entities attached to alerts that already fired, so it misses unalerted activity, which is what hunting is for. DeviceLogonEvents records sign-ins, not connections to public IPs. IdentityLogonEvents records authentication against AD/Entra ID, not which process on a device opened a connection.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q3",
      question: "You receive a Defender XDR incident containing 12 alerts across 4 devices and 3 user accounts. What is the main advantage of Defender XDR automatically grouping these into one incident rather than 12 separate alerts?",
      options: [
        "The incident can be closed as soon as its highest-severity alert is resolved",
        "Alerts from different products are linked into one attack story with its full scope",
        "Duplicate detections of one event are merged, so 11 of the alerts can be ignored",
        "The alerts are ranked, so only the most severe one needs to be investigated"
      ],
      answer: 1,
      explanation: "The value of **XDR correlation** is reconstructing the attack story. A phishing alert (Defender for Office 365), a suspicious logon (Defender for Identity) and PowerShell and PsExec alerts on two devices (MDE) each look moderate alone. Together, in one incident with its graph, they show phishing → credential compromise → lateral movement across 4 devices and 3 accounts. Resolving the most severe alert does not resolve the others: each can be a separate step that needs its own containment. The 12 alerts are related detections, not duplicates of one event, so none can be ignored. Severity ordering helps you choose where to start, but scoping still needs every alert.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Log Analysis: MDE — PsExec Lateral Movement ───────────────────────────
    {
      type: "log_analysis",
      id: "def-xdr-la1",
      heading: "MDE Alert — Lateral Movement via PsExec",
      context: "You are investigating a Defender XDR incident. Its lateral-movement alert says that at 03:17 the service account CORP\\svc-backup authenticated from a developer workstation (WS-DEV-09, 10.0.5.21) to the file server SRV-FILE01 and started a remote process there. Below is the DeviceProcessEvents record from SRV-FILE01 that the alert points to. Analyse it and answer the questions.",
      event: {
        id: "def-xdr-la1-001",
        ts: "2025-11-22T03:17:44.000Z",
        source: "edr",
        vendor: "Microsoft Defender for Endpoint",
        event_type: "process_create",
        severity: "high",
        description: "MDE DeviceProcessEvents on SRV-FILE01: cmd.exe created at 03:17, linked to a lateral-movement alert from WS-DEV-09",
        hostname: "SRV-FILE01",
        user_email: "svc-backup@corp.com",
        src_ip: "10.0.5.21",
        dst_ip: "10.0.10.5",
        mitre_technique: "T1021.002",
        mitre_tactic: "Lateral Movement",
        process: {
          name: "cmd.exe",
          pid: 7712,
          parent_name: "PSEXESVC.exe",
          parent_pid: 5340,
          cmdline: "\"cmd.exe\"",
          user: "NT AUTHORITY\\SYSTEM",
          integrity: "system",
        },
        raw: {
          "Timestamp": "2025-11-22T03:17:44.000Z",
          "DeviceId": "4c1e7a92-5b3d-4f08-9e6a-2d7f1b0c8e35",
          "DeviceName": "srv-file01.corp.local",
          "ActionType": "ProcessCreated",
          "FileName": "cmd.exe",
          "FolderPath": "C:\\Windows\\System32\\cmd.exe",
          "ProcessId": 7712,
          "ProcessCommandLine": "\"cmd.exe\"",
          "ProcessIntegrityLevel": "System",
          "AccountDomain": "nt authority",
          "AccountName": "system",
          "AccountSid": "S-1-5-18",
          "InitiatingProcessFileName": "PSEXESVC.exe",
          "InitiatingProcessFolderPath": "C:\\Windows\\PSEXESVC.exe",
          "InitiatingProcessId": 5340,
          "InitiatingProcessCommandLine": "C:\\Windows\\PSEXESVC.exe",
          "InitiatingProcessParentFileName": "services.exe",
          "InitiatingProcessAccountDomain": "nt authority",
          "InitiatingProcessAccountName": "system",
          "ReportId": 30417
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "The alert says the remote connection authenticated as svc-backup, yet the shell on SRV-FILE01 runs as nt authority\\system. What best explains this, and what does it tell you about svc-backup?",
          options: [
            "PsExec always maps service accounts to SYSTEM; svc-backup may be unprivileged",
            "PsExec was run with -s; svc-backup must already be a local admin on SRV-FILE01",
            "A local scheduled task started the shell; svc-backup was not involved in it",
            "The record is mis-attributed; MDE logs PsExec children under the service name"
          ],
          answer: 1,
          explanation: "On the target, PsExec's remote command runs as a child of `PSEXESVC.exe` (shown here), and it runs as the connecting account unless the `-s` option is used, which makes it run as SYSTEM. Installing PSEXESVC requires local administrator rights, so svc-backup already had admin on SRV-FILE01: that is a finding in itself, and it widens the blast radius of the stolen credential. PsExec does not map service accounts to SYSTEM; without -s, the shell would run as svc-backup. A scheduled task would be started by the task scheduler service, not by PSEXESVC.exe, so the parent rules it out. MDE records the real account of each process (AccountName/AccountSid S-1-5-18); nothing in the record suggests mis-attribution.",
          xp: 45,
        },
        {
          question: "svc-backup is a legitimate service account, normally used only by the overnight backup job that runs from the backup server. How should you read this 03:17 activity?",
          options: [
            "Expected: the backup window is overnight, so svc-backup activity at 03:17 is normal",
            "A misconfigured backup task that launched PsExec with the wrong command by mistake",
            "Likely stolen credentials: a backup job has no need for a SYSTEM shell from a dev PC",
            "Lower priority: svc-backup is already privileged, so a SYSTEM shell adds little"
          ],
          answer: 2,
          explanation: "The time fits the account, but nothing else does. The connection comes from a developer workstation (WS-DEV-09), not the backup server, and the result is an interactive SYSTEM `cmd.exe` through PsExec, not backup traffic. Attackers pick service accounts precisely because activity in their usual window looks normal. Treating it as expected judges the time and ignores the source host and the action. A misconfigured backup task would run from the backup server, not from a dev PC. A SYSTEM shell on a file server gives full control of the host and its data, so the account's existing privilege raises the priority rather than lowering it.",
          xp: 45,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "def-xdr-f1",
      prompt: "Next you want the SRV-FILE01 timeline to show everything else the PsExec service process did there (other child processes, files written, network connections). Using the record above, what is the process ID of the process that launched the SYSTEM shell?",
      answer: "5340",
      hint: "The record describes two processes: the one that was created and the one that created it.",
      xp: 60,
    } satisfies FlagTask,

    // ── Question 4 (bonus) ────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q4",
      question: "A hunter runs Query 1 from the reading (encoded PowerShell, last 7 days). It returns 40 rows: 36 have InitiatingProcessFileName = CcmExec.exe (the Configuration Manager client) spread across hundreds of devices, and 4 have InitiatingProcessFileName = WINWORD.EXE on two Finance laptops. How should the hunter handle the results?",
      options: [
        "Escalate all 40 at once — encoded PowerShell is rarely legitimate, whatever the parent",
        "Prioritise the 4 WINWORD.EXE rows; decode and baseline the CcmExec.exe rows",
        "Close all 40 — Defender would already have alerted on any malicious encoded script",
        "Treat the WINWORD.EXE rows as benign — Office add-ins routinely run encoded scripts"
      ],
      answer: 1,
      explanation: "Encoded PowerShell is a lead, not a verdict. Configuration Manager's CcmExec.exe legitimately launches encoded commands across the fleet, so those rows are decoded and baselined rather than escalated. Word spawning encoded PowerShell on two Finance laptops is the classic macro-delivery pattern, so it comes first. Escalating everything treats management tooling as an attack and buries the 4 real leads. Closing everything assumes an alert would already exist, but hunting exists to find what did not alert. Office applications launching encoded PowerShell are a top-priority signal, not routine add-in behaviour.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Analyst Choice: risky sign-in + new OAuth app consent ────────────────
    {
      type: "analyst_choice",
      id: "def-xdr-ac1",
      heading: "Verdict: High-Risk Sign-In Followed by a New OAuth App Consent",
      scenario:
        "Defender XDR groups three signals into one incident at 04:47 AM: (1) Entra ID Identity Protection flags a High-risk sign-in for the CFO's account (m.reyes@corp.com) that nonetheless succeeded, including MFA, from an IP address never associated with this account before; (2) two minutes later the same account grants OAuth consent to a newly-registered third-party application requesting Mail.Read and Mail.ReadWrite permissions; (3) Defender for Cloud Apps flags the application as an unverified publisher, first seen today across the whole tenant. Review the Unified Audit Log sign-in record below and render your verdict.",
      event: {
        id: "def-xdr-ac1-evt-001",
        ts: "2026-02-11T04:47:03Z",
        source: "o365",
        vendor: "Microsoft 365 Unified Audit Log",
        event_type: "auth_success",
        severity: "high",
        user_email: "m.reyes@corp.com",
        description:
          "High-risk sign-in succeeded for m.reyes@corp.com from a previously unseen IP address; the MFA push notification was approved 4 seconds after being sent",
        mitre_technique: "T1078.004",
        mitre_tactic: "Initial Access",
        authentication: {
          method: "OAuth2",
          mfa_type: "push",
          result: "Success",
        },
        raw: {
          "data.office365.Operation": "UserLoggedIn",
          "data.office365.UserId": "m.reyes@corp.com",
          "data.office365.ActorIpAddress": "91.214.124.60",
          "data.office365.ResultStatus": "Succeeded",
          "data.office365.Workload": "AzureActiveDirectory",
          "data.office365.AzureActiveDirectoryEventType": 1,
          "GeoLocation.country_name": "Romania",
          "GeoLocation.city_name": "Cluj-Napoca",
          "data.office365.ExtendedProperties": [
            { Name: "ResultStatusDetail", Value: "Success" },
            { Name: "UserAgent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" },
            { Name: "UserAuthenticationMethod", Value: "16457" },
            { Name: "RequestType", Value: "OAuth2:Authorize" },
            { Name: "KeepMeSignedIn", Value: "True" },
          ],
          "data.office365.DeviceProperties": [
            { Name: "OS", Value: "Windows 10" },
            { Name: "IsCompliant", Value: "false" },
            { Name: "TrustType", Value: "Unknown" },
          ],
          "rule.description": "Azure AD Identity Protection: High risk sign-in succeeded",
          "rule.level": "12",
          "rule.groups": ["identity", "azuread", "identity-protection"],
        },
      } satisfies TelemetryEvent,
      correct_verdict: "true_positive",
      explanation:
        "On its own, a High-risk sign-in from Identity Protection is a probabilistic signal, not proof of compromise: travel or a new device can also trigger it. The combination removes the ambiguity. The sign-in comes from an IP and country this account has never used. The device is unmanaged and non-compliant (IsCompliant: false, TrustType: Unknown). MFA was satisfied, but a fast approval on an unfamiliar sign-in is not reassurance: it fits a fatigued user tapping Approve, and it fits adversary-in-the-middle phishing, where the user approves their own prompt while a proxy captures the session. Most decisive of all, two minutes later the same account granted OAuth consent to a brand-new, unverified app requesting Mail.Read and Mail.ReadWrite. That is the illicit consent grant pattern from the reading: the app's tokens keep reading the mailbox even after a password reset. Correct response: revoke the app's consent and the user's sessions and refresh tokens, reset the password and re-register MFA for m.reyes, and review the mailbox for forwarding rules or further OAuth grants.",
      fp_trap:
        "Treating any High-risk sign-in as automatically meaning “attack” would generate constant false alarms, because risk detections also fire on routine events such as a new laptop or a business trip. The trap here runs the other way: it is easy to see “MFA satisfied” and assume the sign-in must be legitimate. But MFA only proves that a prompt was approved, not who was behind the session. With AiTM phishing the real user approves their own prompt, and a rushed or fatigued tap looks the same in the log. It is the full chain (unfamiliar IP and country, non-compliant device, and an unverified app granted mailbox read/write two minutes later) that turns an ambiguous risk score into a confirmed compromise.",
      xp: 30,
    } satisfies AnalystChoiceTask,

  ],
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

const rooms = [
  exchangeOnlineSecurity,
  sharepointTeamsMonitoring,
  endpointSecurityFundamentals,
  defenderXdr,
];

export default rooms;
